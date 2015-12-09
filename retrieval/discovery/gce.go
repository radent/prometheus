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

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/config"
)

const (
	gceZone          = "zone"
	gceInstanceGroup = "instance_group"
	gceInstanceName  = "instance_name"
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
	Conf      *config.GCEInstanceGroupSDConfig
	apiClient *http.Client
}

func newGoogleClient(conf *config.GCEInstanceGroupSDConfig) (*http.Client, error) {
	transport := &oauth2.Transport{}
	if conf.UseSdk {
		sdkConf, err := google.NewSDKConfig(conf.ServiceAccount)
		if err != nil {
			return nil, err
		}
		transport.Source = sdkConf.TokenSource(oauth2.NoContext)
	} else {
		transport.Source = google.ComputeTokenSource(conf.ServiceAccount)
	}
	if len(conf.ApiProxyUrl) > 0 {
		u, err := url.Parse(conf.ApiProxyUrl)
		if err != nil {
			return nil, err
		}
		transport.Base = &http.Transport{Proxy: http.ProxyURL(u)}
	}
	return &http.Client{Transport: transport}, nil
}

func NewGCEInstanceGroupDiscovery(conf *config.GCEInstanceGroupSDConfig) (*GCEInstanceGroupDiscovery, error) {
	client, err := newGoogleClient(conf)
	if err != nil {
		return nil, err
	}

	return &GCEInstanceGroupDiscovery{
		Conf:      conf,
		apiClient: client,
	}, nil
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
				gceZone:          model.LabelValue(group.Zone),
				gceInstanceGroup: model.LabelValue(group.GroupName),
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
				gceInstanceName: model.LabelValue(instanceName),
			}
			host := fmt.Sprintf("%s%s:%d", instanceName, domainSuffix, gce.Conf.Port)
			targetLabels[model.AddressLabel] = model.LabelValue(host)
			retGroup.Targets = append(retGroup.Targets, targetLabels)
		}
		retGroups = append(retGroups, retGroup)
	}

	return retGroups, nil
}
