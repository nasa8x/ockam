package main

import "github.com/go-ble/ble/darwin"

func newBleDevice() (*darwin.Device, error) {
	return darwin.NewDevice()
}
