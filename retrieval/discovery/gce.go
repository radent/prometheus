package discovery

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/config"
)

const (
	gceLabel              = model.MetaLabelPrefix + "gce_"
	gceLabelZone          = gceLabel + "zone"
	gceLabelInstanceGroup = gceLabel + "group"
	gceLabelInstanceName  = gceLabel + "instance_name"
)

var (
	gceDiscoveryFailuresCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "gce_discovery_failures_total",
			Help:      "The number of GCE backend service discovery failures.",
		})
	gceDiscoveryClientBackends = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "gce_targets",
			Help:      "Number of instances discovered for each instance group.",
		}, []string{"zone", "instance_group"})
)

func init() {
	prometheus.MustRegister(gceDiscoveryFailuresCount)
	prometheus.MustRegister(gceDiscoveryClientBackends)
}

type GCEInstanceGroupDiscovery struct {
	Conf         *config.GCEInstanceGroupSDConfig
	apiClient    *http.Client
	authHeader   string
	tokenExpires time.Time
}

func NewGCEInstanceGroupDiscovery(conf *config.GCEInstanceGroupSDConfig) (*GCEInstanceGroupDiscovery, error) {
	retDiscovery := &GCEInstanceGroupDiscovery{
		Conf: conf,
	}

	if len(conf.ApiProxyUrl) != 0 {
		proxyUrl, err := url.Parse(conf.ApiProxyUrl)
		if err != nil {
			return nil, err
		}
		retDiscovery.apiClient = &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyUrl),
			},
		}
	} else {
		retDiscovery.apiClient = &http.Client{}
	}
	return retDiscovery, nil
}

func (gce *GCEInstanceGroupDiscovery) groupToSource(group *config.GCEInstanceGroup) string {
	return fmt.Sprintf("%s:%s", group.Zone, group.GroupName)
}

// Sources implements the TargetProvider interface.
func (gce *GCEInstanceGroupDiscovery) Sources() []string {
	var sources []string
	for _, group := range gce.Conf.Groups {
		sources = append(sources, gce.groupToSource(group))
	}
	return sources
}

// Run implements the TargetProvider interface.
func (gce *GCEInstanceGroupDiscovery) Run(ch chan<- config.TargetGroup, done <-chan struct{}) {
	defer close(ch)

	ticker := time.NewTicker(time.Duration(gce.Conf.RefreshInterval))
	defer ticker.Stop()

	// Get an initial set right away.
	tg, err := gce.refresh()
	if err != nil {
		log.Error(err)
	} else {
		for _, group := range tg {
			ch <- *group
		}
	}

	for {
		select {
		case <-ticker.C:
			tg, err := gce.refresh()
			if err != nil {
				log.Error(err)
			} else {
				for _, group := range tg {
					ch <- *group
				}
			}
		case <-done:
			return
		}
	}
}

func (gce *GCEInstanceGroupDiscovery) refreshAccessToken() error {
	if len(gce.authHeader) > 0 && gce.tokenExpires.After(time.Now()) {
		// Still valid.
		return nil
	}

	gce.authHeader = ""
	accessTokenUrl :=
		fmt.Sprintf("http://metadata/computeMetadata/v1/instance/service-accounts/%s/token",
			gce.Conf.ServiceAccount)
	req, _ := http.NewRequest("GET", accessTokenUrl, nil)
	req.Header.Add("Metadata-Flavor", "Google")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Read token response: %s", err)
		return err
	}

	var tokenResponse struct {
		AccessToken  string `json:"access_token"`
		ExpiresInSec int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		log.Errorf("Parse token response: %s", err)
		return err
	}

	if len(tokenResponse.AccessToken) == 0 {
		return fmt.Errorf("Empty access token.")
	}

	gce.authHeader = fmt.Sprintf("%s %s", tokenResponse.TokenType, tokenResponse.AccessToken)
	gce.tokenExpires = time.Now().Add(time.Duration(tokenResponse.ExpiresInSec) * time.Second)

	log.Infof("**** Refreshed %s access token, expires in %d sec",
		tokenResponse.TokenType, tokenResponse.ExpiresInSec)
	return nil
}

type _gceApiErrorJson struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type _gceApiResponseJson struct {
	Error *_gceApiErrorJson `json:"error"`
}

type _gceLabelJson struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type _gceEndpointJson struct {
	Name string `json:"name"`
	Port int    `json:"port"`
}

type _gceInstanceGroupJson struct {
	_gceApiResponseJson

	Kind              string             `json:"kind"`
	Name              string             `json:"name"`
	Description       string             `json:"description"`
	Size              int                `json:"size"`
	CreationTimestamp string             `json:"creationTimestamp"`
	Resources         []string           `json:"resources"`
	Id                string             `json:"id"`
	SelfLink          string             `json:"selfLink"`
	Labels            []_gceLabelJson    `json:"labels"`
	Endpoints         []_gceEndpointJson `json:"endpoints"`
	Network           string             `json:"network"`
	Fingerprint       string             `json:"fingerprint"`
}

func (gce *GCEInstanceGroupDiscovery) getInstanceGroupResources(group *config.GCEInstanceGroup) ([]string, error) {
	getInstanceGroupUrl :=
		fmt.Sprintf("https://www.googleapis.com/resourceviews/v1beta2/projects/%s/zones/%s/resourceViews/%s",
			gce.Conf.Project, group.Zone, group.GroupName)
	req, _ := http.NewRequest("GET", getInstanceGroupUrl, nil)
	req.Header.Add("Authorization", gce.authHeader)
	resp, err := gce.apiClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Read instance group %s/%s: %s", group.Zone, group.GroupName, err)
		return nil, err
	}

	var groupInfo _gceInstanceGroupJson
	err = json.Unmarshal(body, &groupInfo)
	if err != nil {
		log.Errorf("Parse instance group: %s/%s: %s", group.Zone, group.GroupName, err)
		return nil, err
	}

	if groupInfo.Error != nil && len(groupInfo.Error.Message) > 0 {
		return nil, errors.New(groupInfo.Error.Message)
	}
	return groupInfo.Resources, nil
}

func (gce *GCEInstanceGroupDiscovery) getInstanceList(group *config.GCEInstanceGroup) ([]string, error) {
	err := gce.refreshAccessToken()
	if err != nil {
		return nil, err
	}

	resources, err := gce.getInstanceGroupResources(group)
	if err != nil {
		return nil, err
	}

	var instances []string
	for _, resource := range resources {
		shortName := resource[strings.LastIndex(resource, "/")+1:]
		instances = append(instances, shortName)
	}
	return instances, nil
}

func (gce *GCEInstanceGroupDiscovery) refresh() ([]*config.TargetGroup, error) {
	var retGroups []*config.TargetGroup
	for _, group := range gce.Conf.Groups {
		retGroup := &config.TargetGroup{
			Source: gce.groupToSource(group),
			Labels: model.LabelSet{
				gceLabelZone:          model.LabelValue(group.Zone),
				gceLabelInstanceGroup: model.LabelValue(group.GroupName),
			},
		}
		newInstanceList, err := gce.getInstanceList(group)
		if err != nil {
			gceDiscoveryFailuresCount.Inc()
			log.Warnf("Failed to fetch instance list: %s", err)
			return nil, err
		}

		exportLabels := prometheus.Labels{
			"zone":           group.Zone,
			"instance_group": group.GroupName,
		}
		gceDiscoveryClientBackends.With(exportLabels).Set(float64(len(newInstanceList)))
		var domainSuffix string
		if len(gce.Conf.AppendDomain) > 0 {
			domainSuffix = fmt.Sprintf(".%s", gce.Conf.AppendDomain)
		}
		for _, instanceName := range newInstanceList {
			targetLabels := model.LabelSet{
				gceLabelInstanceName: model.LabelValue(instanceName),
			}
			endpoint := &url.URL{
				Host: fmt.Sprintf("%s%s:%d",
					instanceName,
					domainSuffix,
					gce.Conf.Port),
			}
			targetLabels[model.AddressLabel] = model.LabelValue(endpoint.String())
			retGroup.Targets = append(retGroup.Targets, targetLabels)
		}
	}

	return retGroups, nil
}
