package main

import "github.com/go-ble/ble/linux"

func newBleDevice() (*linux.Device, error) {
	return linux.NewDevice()
}
