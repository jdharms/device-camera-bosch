package axis

import (
	"device-camera-bosch/internal/pkg/client"
	"device-camera-bosch/internal/pkg/digest"
	"encoding/binary"
	"fmt"
	ds_models "github.com/edgexfoundry/device-sdk-go/pkg/models"
	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"
	e_models "github.com/edgexfoundry/go-mod-core-contracts/models"
	"io"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

const VAPIX_FMT_URL = "http://%s/axis-cgi/mjpg/video.cgi?fps=1" // hard coded to mjpg video for now

type trigger struct {
	alarmCode string
	state bool
}

type VapixClient struct {
	lc        logger.LoggingClient
	asyncChan chan<- *ds_models.AsyncValues

	alarms      map[string]e_models.DeviceResource
	alarmStates map[string]bool

	stop    chan bool
	stopped chan bool
}

func (c *VapixClient) triggersFromString(triggerString string) (t trigger) {
	split := strings.Split(triggerString, ";")
	for _, s := range split {
		if len(s) < 4 {
			return
		}
		alarmCode := s[0:2]

		_, ok := c.alarms[alarmCode]
		if ok {
			t.alarmCode = alarmCode
			t.state = s[3] == '1'
		}
	}
	return
}

func (c *VapixClient) parseTriggers(bytes []byte) trigger {
	for i := 0; i < len(bytes)-4; i++ {
		if bytes[i] == 0xff && bytes[i+1] == 0xfe {
			length := int(binary.BigEndian.Uint16(bytes[i+2 : i+4]))
			comment := bytes[i+4 : (i + length - 1)]
			axis_id := binary.BigEndian.Uint16(comment[0:2])
			if axis_id == 0x0a03 {
				triggerString := string(comment[2 : length-2])
				return c.triggersFromString(triggerString)
			}
		}
	}
	return trigger{}
}

func (c *VapixClient) listenForTriggers(edgexDevice e_models.Device, address string, username string, password string) error {
	dclient := digest.NewDClient(&http.Client{}, username, password)
	url := fmt.Sprintf(VAPIX_FMT_URL, address)

	reader, err := getMultipartReader(dclient, url)
	if err != nil {
		return fmt.Errorf("listenForTriggers: %v", err.Error())
	}

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			return fmt.Errorf("listenForTriggers: found EOF", err.Error())
		}
		if err != nil {
			return fmt.Errorf("listenForTriggers: %v", err.Error())
		}

		slurp, err := ioutil.ReadAll(part)
		if err != nil {
			return fmt.Errorf("listenForTriggers: ioutil.ReadAll: %v", err.Error())
		}

		t := c.parseTriggers(slurp)

		if t.state != c.alarmStates[t.alarmCode] {
			c.alarmStates[t.alarmCode] = t.state
			cvs, err := c.getCommandValue(edgexDevice, c.alarms[t.alarmCode].Name, t.state)
			if err != nil {
				continue
			}
			c.sendEvent(edgexDevice, cvs)
		}
	}
}

func NewClient(asyncCh chan<- *ds_models.AsyncValues, lc logger.LoggingClient) client.Client {
	return &VapixClient{asyncChan: asyncCh, lc: lc}
}

func (c *VapixClient) CameraInit(edgexDevice e_models.Device, ipAddress string, username string, password string) {
	if c.alarms == nil {
		c.alarms = make(map[string]e_models.DeviceResource)
	}

	if c.alarmStates == nil {
		c.alarmStates = make(map[string]bool)
	}

	// interrogate device profile for alarms to listen for
	deviceResources := edgexDevice.Profile.DeviceResources

	for _, e := range deviceResources {
		alarmCode, ok := e.Attributes["alarm_code"]
		if ok {
			c.alarms[alarmCode] = e
			c.alarmStates[alarmCode] = false
		}
	}

	go retryLoop(func() error {
		err := c.listenForTriggers(edgexDevice, ipAddress, username, password)
		return err
	}, c.lc)
}

func (c *VapixClient) HandleReadCommand(req ds_models.CommandRequest) (*ds_models.CommandValue, error) {
	// todo
	return nil, nil
}

func (c *VapixClient) CameraRelease(force bool) {
	// todo
}

func retryLoop(fn func() error, client logger.LoggingClient) {
	for {
		err := fn()
		if err != nil {
			client.Error(err.Error())
		}
		time.Sleep(5 * time.Second)
	}
}

func (c *VapixClient) getCommandValue(edgexDevice e_models.Device, trigger string, val bool) ([]*ds_models.CommandValue, error) {
	cv, err := ds_models.NewBoolValue(trigger, time.Now().UnixNano()/int64(time.Millisecond), val)
	if err != nil {
		c.lc.Error("failed getting new bool CommandValue")
		return []*ds_models.CommandValue{}, fmt.Errorf("failed getting new bool CommandValue")
	}
	cvs := []*ds_models.CommandValue{cv}
	return cvs, nil
}

func (c *VapixClient) sendEvent(edgexDevice e_models.Device, cvs []*ds_models.CommandValue) {
	var av ds_models.AsyncValues
	av.DeviceName = edgexDevice.Name

	for _, cv := range cvs {
		av.CommandValues = append(av.CommandValues, cv)
	}

	c.asyncChan <- &av
}

func getMultipartReader(client digest.Client, url string) (*multipart.Reader, error) {
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET Error: %v", err.Error())
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status Error: %v", resp.StatusCode)
	}

	mediaType, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, fmt.Errorf("ParseMediaType error: %v", err.Error())
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		mr := multipart.NewReader(resp.Body, params["boundary"])
		return mr, nil
	}

	// Not a multipart message?

	return nil, fmt.Errorf("not a valid multipart message")
}
