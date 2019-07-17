package driver

import (
	"github.com/atagirov/goonvif"
	"github.com/atagirov/goonvif/Device"
	"github.com/atagirov/goonvif/Media"
	"github.com/atagirov/goonvif/xsd/onvif"
	"github.com/beevik/etree"
	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"
	"io/ioutil"
	"net/http"
	"strings"
)

type OnvifClient struct {
	ipAddress string
	user      string
	password  string
	lc        logger.LoggingClient
}

func NewOnvifClient(ipAddress string, user string, password string, lc logger.LoggingClient) *OnvifClient {
	return &OnvifClient{
		ipAddress: ipAddress,
		user:      user,
		password:  password,
		lc:        lc,
	}
}

func (c *OnvifClient) GetDeviceInformation() (map[string]string, error) {
	// The goonvif library not exposing the onvif device as a public interface means
	// we need to create a new device and authenticate in each function we make an onvif
	// call.  Would probably be smart to change this behavior.
	dev, err := goonvif.NewDevice(c.ipAddress)
	if err != nil {
		return nil, err
	}
	dev.Authenticate(c.user, c.password)

	deviceInfoResp, err := dev.CallMethod(Device.GetDeviceInformation{})
	if err != nil {
		return nil, err
	}

	doc := etree.NewDocument()
	b, err := ioutil.ReadAll(deviceInfoResp.Body)
	if err != nil {
		return nil, err
	}

	if err := doc.ReadFromBytes(b); err != nil {
		return nil, err
	}

	deviceInfo := make(map[string]string)

	getResponseElements := doc.FindElements("./Envelope/Body/GetDeviceInformationResponse/*")
	for _, j := range getResponseElements {
		deviceInfo[j.Tag] = j.Text()
	}

	return deviceInfo, nil
}

func (c *OnvifClient) GetProfileInformation() ([]map[string]string, error) {
	dev, err := goonvif.NewDevice(c.ipAddress)
	if err != nil {
		return nil, err
	}
	dev.Authenticate(c.user, c.password)

	profilesResp, err := dev.CallMethod(Media.GetProfiles{})
	if err != nil {
		return nil, err
	}

	doc := etree.NewDocument()
	b, err := ioutil.ReadAll(profilesResp.Body)
	if err != nil {
		return nil, err
	}

	if err := doc.ReadFromBytes(b); err != nil {
		return nil, err
	}

	getResponseElements := doc.FindElements("./Envelope/Body/GetProfilesResponse/*")
	profileMaps := make([]map[string]string, 0)
	for _, elem := range getResponseElements {
		pMap := make(map[string]string)
		pMap["name"] = elem.FindElement("./Name").Text()
		pMap["encoding"] = elem.FindElement("./VideoEncoderConfiguration/Encoding").Text()
		pMap["resolution"] = strings.Join(mapElementsToStrings(elem.FindElements("./VideoEncoderConfiguration/Resolution/*")), ", ")
		token := elem.SelectAttr("token").Value

		getStream := Media.GetStreamUri{
			StreamSetup: onvif.StreamSetup{
				Stream:    onvif.StreamType("RTP-Unicast"),
				Transport: onvif.Transport{Protocol: "RTSP"},
			},
			ProfileToken: onvif.ReferenceToken(token),
		}

		getStreamResponse, err := dev.CallMethod(getStream)
		if err != nil {
			c.lc.Error("Error getting stream URI: %s", err.Error())
			return nil, err
		}

		getImage := Media.GetSnapshotUri{
			ProfileToken: onvif.ReferenceToken(token),
		}

		getImageResponse, err := dev.CallMethod(getImage)
		if err != nil {
			c.lc.Error(err.Error())
		}

		pMap["RTSPPath"] = c.getRTSP(getStreamResponse)
		pMap["ImagePath"] = c.getImagePath(getImageResponse)

		profileMaps = append(profileMaps, pMap)
	}

	return profileMaps, nil
}

func (c *OnvifClient) getRTSP(resp *http.Response) string {
	doc := etree.NewDocument()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		c.lc.Error(err.Error())
		return ""
	}

	err = doc.ReadFromBytes(b)
	if err != nil {
		c.lc.Error(err.Error())
		return ""
	}

	elem := doc.FindElement("./Envelope/Body/GetStreamUriResponse/MediaUri/Uri")
	if elem == nil {
		return ""
	}
	return elem.Text()
}

func (c *OnvifClient) getImagePath(resp *http.Response) string {
	doc := etree.NewDocument()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		c.lc.Error(err.Error())
		return ""
	}

	err = doc.ReadFromBytes(b)
	if err != nil {
		c.lc.Error(err.Error())
		return ""
	}

	elem := doc.FindElement("./Envelope/Body/GetSnapshotUriResponse/MediaUri/Uri")
	if elem == nil {
		return ""
	}
	return elem.Text()
}

func mapElementsToStrings(elems []*etree.Element) []string {
	result := make([]string, 0)
	for _, elem := range elems {
		result = append(result, elem.Text())
	}
	return result
}
