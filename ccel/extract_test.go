// Copyright 2024 Google LLC
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

package ccel

import (
	"os"
	"strings"
	"testing"

	"github.com/google/go-eventlog/common"
	"github.com/google/go-eventlog/register"
)

func TestExtractFirmwareLogState(t *testing.T) {
	elBytes, err := os.ReadFile("../testdata/eventlogs/ccel/cos-113-intel-tdx.bin")
	if err != nil {
		t.Fatal(err)
	}
	tableBytes, err := os.ReadFile("../testdata/eventlogs/ccel/cos-113-intel-tdx.table.bin")
	if err != nil {
		t.Fatal(err)
	}

	rtmr0 := []byte("?\xa2\xf6\x1f9[\x7f_\xee\xfbN\xc2\xdfa)\x7f\x10\x9aث\xcdd\x10\xc1\xb7\xdf`\xf2\x1f7\xb1\x92\x97\xfc5\xe5D\x03\x9c~\x1e\xde\xceu*\xfd\x17\xf6")
	rtmr1 := []byte("\xf6-\xbc\a+\xd5\xd3\xf3C\x8b{5Úr\x7fZ\xea/\xfc$s\xf47#\x95?S\r\xafbPO\nyD\xaab\xc4\x1a\x86\xe8\xa8x±\"\xc1")
	rtmr2 := []byte("IihM\xc8s\x81\xfc;14\x17l\x8d\x88\x06\xea\xf0\xa9\x01\x85\x9f_pϮ\x8d\x17qKF\xc1\n\x8d\xe2\x19\x04\x8c\x9f\xc0\x9f\x11\xf3\x81\xa6\xfb\xe7\xc1")
	bank := register.RTMRBank{RTMRs: []register.RTMR{
		{Index: 0, Digest: rtmr0},
		{Index: 1, Digest: rtmr1},
		{Index: 2, Digest: rtmr2},
	}}
	_, err = ExtractFirmwareLogState(tableBytes, elBytes, bank, ExtractOpts{Loader: common.GRUB})
	if err != nil {
		t.Errorf("failed to extract FirmwareLogState from CCEL: %v", err)
	}
}

func TestExtractFirmwareLogStateFailDuplicateSeparator(t *testing.T) {
	badELWithUEFIBug, err := os.ReadFile("../testdata/eventlogs/ccel/cos-113-intel-tdx-dupe-separator.bin")
	if err != nil {
		t.Fatal(err)
	}
	tableBytes, err := os.ReadFile("../testdata/eventlogs/ccel/CCEL.bin")
	if err != nil {
		t.Fatal(err)
	}

	rtmr0 := []byte("\xa4\xde-\xf2>\x96\x11)\x91#\xbaCY\xc4*^W\x8b\x0f\x84\x88\xbf\x1b\xba\x8e\xf5`m\x9e\xa5\xd8\x1c\x97\xc0d\xb4\x82\xa5\xea\xc57\xd1f\xbd\x0f\x0fu-")
	rtmr1 := []byte("\x0e\xe96l\x92\x8aw\t/U\xe9\xe1\x14\xc79A\x81\xfd&F\x99\x15_\r\xf7}#Wv\x18\xd5\xf6PV\x8a\x17\xd3y5Z\a\xbd\x84nU/N ")
	rtmr2 := []byte("IihM\xc8s\x81\xfc;14\x17l\x8d\x88\x06\xea\xf0\xa9\x01\x85\x9f_pϮ\x8d\x17qKF\xc1\n\x8d\xe2\x19\x04\x8c\x9f\xc0\x9f\x11\xf3\x81\xa6\xfb\xe7\xc1")
	bank := register.RTMRBank{RTMRs: []register.RTMR{
		// {Index: 0, Digest: zeroes},
		{Index: 0, Digest: rtmr0},
		{Index: 1, Digest: rtmr1},
		{Index: 2, Digest: rtmr2},
	}}
	_, err = ExtractFirmwareLogState(tableBytes, badELWithUEFIBug, bank, ExtractOpts{Loader: common.GRUB})
	if err == nil || !strings.Contains(err.Error(), "duplicate separator at event") {
		t.Errorf("ExtractFirmwareLogState(badELWithUEFIBug): got %v, expected error with duplicate separator message", err)
	}
}
