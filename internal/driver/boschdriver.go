package driver

import (
	"device-camera-bosch/internal/pkg/axis"
	"device-camera-bosch/internal/pkg/bosch"
	"device-camera-bosch/internal/pkg/client"
	"fmt"
	"github.com/edgexfoundry/device-sdk-go"
	sdkModel "github.com/edgexfoundry/device-sdk-go/pkg/models"
	"github.com/edgexfoundry/go-mod-core-contracts/clients/logger"
	contract "github.com/edgexfoundry/go-mod-core-contracts/models"
	"github.com/pkg/errors"
	"strings"
	"sync"
)

var once sync.Once
var lock sync.Mutex

var onvifClients map[string]*OnvifClient
var clients map[string]client.Client

var driver *Driver

type Driver struct {
	lc       logger.LoggingClient
	asynchCh chan<- *sdkModel.AsyncValues
	config   *configuration
}

func NewProtocolDriver() sdkModel.ProtocolDriver {
	once.Do(func() {
		driver = new(Driver)
		onvifClients = make(map[string]*OnvifClient)
		clients = make(map[string]client.Client)
	})

	return driver
}

// HandleReadCommands triggers a protocol Read operation for the specified device.
func (d *Driver) HandleReadCommands(deviceName string, protocols map[string]contract.ProtocolProperties, reqs []sdkModel.CommandRequest) ([]*sdkModel.CommandValue, error) {
	var responses = make([]*sdkModel.CommandValue, len(reqs))
	if _, ok := protocols["HTTP"]; !ok {
		d.lc.Error("No HTTP address found for device. Check configuration file.")
		return responses, fmt.Errorf("No HTTP address in protocols map")
	}

	if _, ok := protocols["HTTP"]["Address"]; !ok {
		d.lc.Error("No HTTP address found for device. Check configuration file.")
		return responses, fmt.Errorf("No HTTP address in protocols map")
	}

	addr := protocols["HTTP"]["Address"]

	// check for existence of both clients

	onvifClient, ok := getOnvifClient(addr)

	if !ok {
		dev, err := device.RunningService().GetDeviceByName(deviceName)
		if err != nil {
			err = fmt.Errorf("Device not found: %s", deviceName)
			d.lc.Error(err.Error())

			return responses, err
		}

		onvifClient = initializeOnvifClient(dev, d.config.Camera.User, d.config.Camera.Password)
	}

	client, ok := getClient(addr)

	if !ok {
		dev, err := device.RunningService().GetDeviceByName(deviceName)
		if err != nil {
			err = fmt.Errorf("Device not found: %s", deviceName)
			d.lc.Error(err.Error())

			return responses, err
		}
		client = newClient(dev, d.config.Camera.User, d.config.Camera.Password)
	}

	for i, req := range reqs {
		var result string
		switch req.DeviceResourceName {
		// ONVIF cases
		case "onvif_device_information":
			data, err := onvifClient.GetDeviceInformation()

			if err != nil {
				d.lc.Error(err.Error())
				return responses, err
			}

			result = mapToString(data)

			cv := sdkModel.NewStringValue(reqs[i].DeviceResourceName, 0, string(result))
			responses[i] = cv
		case "onvif_profile_information":
			data, err := onvifClient.GetProfileInformation()

			if err != nil {
				d.lc.Error(err.Error())
				return responses, err
			}

			profiles := make([]string, 0)
			for _, e := range data {
				profiles = append(profiles, mapToString(e))
			}

			result = strings.Join(profiles, ",,")

			cv := sdkModel.NewStringValue(reqs[i].DeviceResourceName, 0, string(result))
			responses[i] = cv
		// camera specific cases
		default:
			if client == nil {
				err := errors.New("Non-ONVIF command for camera without secondary client")
				d.lc.Error(err.Error())
				return responses, err
			}

			cv, err := client.HandleReadCommand(req)
			if err != nil {
				d.lc.Error(err.Error())
				return responses, err
			}
			responses[i] = cv
		}
	}

	return responses, nil
}

// HandleWriteCommands passes a slice of CommandRequest struct each representing
// a ResourceOperation for a specific device resource (aka DeviceObject).
// Since the commands are actuation commands, params provide parameters for the individual
// command.
func (d *Driver) HandleWriteCommands(deviceName string, protocols map[string]contract.ProtocolProperties, reqs []sdkModel.CommandRequest, params []*sdkModel.CommandValue) error {
	return nil
}

// DisconnectDevice handles protocol-specific cleanup when a device
// is removed.
func (d *Driver) DisconnectDevice(deviceName string, protocols map[string]contract.ProtocolProperties) error {
	errString := "No HTTP address found for device. Check configuration file."
	if _, ok := protocols["HTTP"]; !ok {
		d.lc.Error(errString)
		return fmt.Errorf(errString)
	}

	if _, ok := protocols["HTTP"]["Address"]; !ok {
		d.lc.Error(errString)
		return fmt.Errorf(errString)
	}

	addr := protocols["HTTP"]["Address"]

	shutdownClient(addr)
	shutdownOnvifClient(addr)
	return nil
}

// Initialize performs protocol-specific initialization for the device
// service.
func (d *Driver) Initialize(lc logger.LoggingClient, asyncCh chan<- *sdkModel.AsyncValues) error {
	d.lc = lc
	d.asynchCh = asyncCh

	config, err := LoadConfigFromFile()
	if err != nil {
		panic(fmt.Errorf("read bosch driver configuration from file failed: %d", err))
	}
	d.config = config

	for _, dev := range device.RunningService().Devices() {
		initializeOnvifClient(dev, config.Camera.User, config.Camera.Password)
		newClient(dev, config.Camera.User, config.Camera.Password)
	}

	return nil
}

// Stop the protocol-specific DS code to shutdown gracefully, or
// if the force parameter is 'true', immediately. The driver is responsible
// for closing any in-use channels, including the channel used to send async
// readings (if supported).
func (d *Driver) Stop(force bool) error {
	for _, client := range clients {
		client.CameraRelease(force)
	}

	close(d.asynchCh)

	return nil
}

func newClient(device contract.Device, user string, password string) client.Client {
	labels := device.Profile.Labels
	var c client.Client

	if in("bosch", labels) {
		c = initializeClient(device, user, password)
	} else if in("hanwha", labels) {
		// c = initializeHanwhaClient(device, user, password)
	} else if in("axis", labels) {
		c = initializeAxisClient(device, user, password)
	}

	return c
}

func getOnvifClient(addr string) (*OnvifClient, bool) {
	lock.Lock()
	client, ok := onvifClients[addr]
	lock.Unlock()
	return client, ok
}

func getClient(addr string) (client.Client, bool) {
	lock.Lock()
	client, ok := clients[addr]
	lock.Unlock()
	return client, ok
}

func initializeOnvifClient(device contract.Device, user string, password string) *OnvifClient {
	addr := device.Protocols["HTTP"]["Address"]
	client := NewOnvifClient(addr, user, password, driver.lc)
	lock.Lock()
	onvifClients[addr] = client
	lock.Unlock()
	return client
}

func initializeClient(device contract.Device, user string, password string) client.Client {
	addr := device.Protocols["HTTP"]["Address"]

	client := bosch.NewClient(driver.asynchCh, driver.lc)
	client.CameraInit(device, addr, user, password)

	lock.Lock()
	clients[addr] = client
	lock.Unlock()

	return client
}

func initializeAxisClient(device contract.Device, user string, password string) client.Client {
	addr := device.Protocols["HTTP"]["Address"]

	client := axis.NewClient(driver.asynchCh, driver.lc)
	client.CameraInit(device, addr, user, password)

	lock.Lock()
	clients[addr] = client
	lock.Unlock()

	return client
}

func shutdownOnvifClient(addr string) {
	// nothing much to do here at the moment
	lock.Lock()
	delete(onvifClients, addr)
	lock.Unlock()
}

func shutdownClient(addr string) {
	lock.Lock()

	clients[addr].CameraRelease(true)
	delete(clients, addr)

	lock.Unlock()
}

func mapToString(m map[string]string) string {
	var pairs []string
	for k, v := range m {
		pairs = append(pairs, fmt.Sprintf("%s:%s", k, v))
	}

	result := strings.Join(pairs, ",")
	return result
}


func in(needle string, haystack []string) bool {
	for _, e := range haystack {
		if needle == e {
			return true
		}
	}
	return false
}