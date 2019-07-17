// -*- Mode: Go; indent-tabs-mode: t -*-
//
// Copyright (C) 2019 Dell Technologies
//
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"device-camera-bosch/internal/driver"
	"github.com/edgexfoundry/device-sdk-go/pkg/startup"
)

const (
	version     string = "0.1.0"
	serviceName string = "device-camera-bosch"
)

func main() {
	sd := driver.NewProtocolDriver()
	startup.Bootstrap(serviceName, version, sd)
}
