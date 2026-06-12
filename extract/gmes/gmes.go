// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

// Package gmes has configs for extracting information from Google measurements.
package gmes

const (
	// BMCData is the expected content of the BMC Firmware event.
	BMCData = "HCRTM"

	// BIOSData is the expected content of the BIOS event.
	BIOSData = "DRTM"
)

type registerConfig struct {
	BMCFirmwareIdx uint32
	BIOSIdx        uint32
	HostKernelIdx  uint32
}

// PCRConfig configures the expected PCR indexes for GMES event logs.
var PCRConfig = registerConfig{
	BMCFirmwareIdx: 0,
	BIOSIdx:        17,
	HostKernelIdx:  21,
}
