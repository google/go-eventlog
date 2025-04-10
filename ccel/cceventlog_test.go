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
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-eventlog/register"
	"github.com/google/go-eventlog/tcg"
)

type eventLog struct {
	fname string
	mrs   []register.MR
	// TODO: migrate off of the slice based bank type and move to a map-based representation.
	rtmrs []register.RTMR
}

var COS113TDX = eventLog{
	fname: "../testdata/eventlogs/ccel/cos-113-intel-tdx.bin",
	mrs: []register.MR{
		register.RTMR{
			Index:  0,
			Digest: []byte("?\xa2\xf6\x1f9[\x7f_\xee\xfbN\xc2\xdfa)\x7f\x10\x9aث\xcdd\x10\xc1\xb7\xdf`\xf2\x1f7\xb1\x92\x97\xfc5\xe5D\x03\x9c~\x1e\xde\xceu*\xfd\x17\xf6"),
		},
		register.RTMR{
			Index:  1,
			Digest: []byte("\xf6-\xbc\a+\xd5\xd3\xf3C\x8b{5Úr\x7fZ\xea/\xfc$s\xf47#\x95?S\r\xafbPO\nyD\xaab\xc4\x1a\x86\xe8\xa8x±\"\xc1"),
		},
		register.RTMR{
			Index:  2,
			Digest: []byte("IihM\xc8s\x81\xfc;14\x17l\x8d\x88\x06\xea\xf0\xa9\x01\x85\x9f_pϮ\x8d\x17qKF\xc1\n\x8d\xe2\x19\x04\x8c\x9f\xc0\x9f\x11\xf3\x81\xa6\xfb\xe7\xc1"),
		},
	},
	rtmrs: []register.RTMR{
		{
			Index:  0,
			Digest: []byte("?\xa2\xf6\x1f9[\x7f_\xee\xfbN\xc2\xdfa)\x7f\x10\x9aث\xcdd\x10\xc1\xb7\xdf`\xf2\x1f7\xb1\x92\x97\xfc5\xe5D\x03\x9c~\x1e\xde\xceu*\xfd\x17\xf6"),
		},
		{
			Index:  1,
			Digest: []byte("\xf6-\xbc\a+\xd5\xd3\xf3C\x8b{5Úr\x7fZ\xea/\xfc$s\xf47#\x95?S\r\xafbPO\nyD\xaab\xc4\x1a\x86\xe8\xa8x±\"\xc1"),
		},
		{
			Index:  2,
			Digest: []byte("IihM\xc8s\x81\xfc;14\x17l\x8d\x88\x06\xea\xf0\xa9\x01\x85\x9f_pϮ\x8d\x17qKF\xc1\n\x8d\xe2\x19\x04\x8c\x9f\xc0\x9f\x11\xf3\x81\xa6\xfb\xe7\xc1"),
		},
	},
}

var COS113TDXUnpadded = eventLog{
	fname: "../testdata/eventlogs/ccel/cos-113-intel-tdx-dupe-separator-unpadded.bin",
	mrs: []register.MR{
		register.RTMR{
			Index:  0,
			Digest: []byte("\xa4\xde-\xf2>\x96\x11)\x91#\xbaCY\xc4*^W\x8b\x0f\x84\x88\xbf\x1b\xba\x8e\xf5`m\x9e\xa5\xd8\x1c\x97\xc0d\xb4\x82\xa5\xea\xc57\xd1f\xbd\x0f\x0fu-"),
		},
		register.RTMR{
			Index:  1,
			Digest: []byte("\x0e\xe96l\x92\x8aw\t/U\xe9\xe1\x14\xc79A\x81\xfd&F\x99\x15_\r\xf7}#Wv\x18\xd5\xf6PV\x8a\x17\xd3y5Z\a\xbd\x84nU/N "),
		},
		register.RTMR{
			Index:  2,
			Digest: []byte("IihM\xc8s\x81\xfc;14\x17l\x8d\x88\x06\xea\xf0\xa9\x01\x85\x9f_pϮ\x8d\x17qKF\xc1\n\x8d\xe2\x19\x04\x8c\x9f\xc0\x9f\x11\xf3\x81\xa6\xfb\xe7\xc1"),
		},
	},
	rtmrs: []register.RTMR{
		{
			Index:  0,
			Digest: []byte("\xa4\xde-\xf2>\x96\x11)\x91#\xbaCY\xc4*^W\x8b\x0f\x84\x88\xbf\x1b\xba\x8e\xf5`m\x9e\xa5\xd8\x1c\x97\xc0d\xb4\x82\xa5\xea\xc57\xd1f\xbd\x0f\x0fu-"),
		},
		{
			Index:  1,
			Digest: []byte("\x0e\xe96l\x92\x8aw\t/U\xe9\xe1\x14\xc79A\x81\xfd&F\x99\x15_\r\xf7}#Wv\x18\xd5\xf6PV\x8a\x17\xd3y5Z\a\xbd\x84nU/N "),
		},
		{
			Index:  2,
			Digest: []byte("IihM\xc8s\x81\xfc;14\x17l\x8d\x88\x06\xea\xf0\xa9\x01\x85\x9f_pϮ\x8d\x17qKF\xc1\n\x8d\xe2\x19\x04\x8c\x9f\xc0\x9f\x11\xf3\x81\xa6\xfb\xe7\xc1"),
		},
	},
}

var COS113TDXPadded = eventLog{
	fname: "../testdata/eventlogs/ccel/cos-113-intel-tdx-dupe-separator.bin",
	mrs: []register.MR{
		register.RTMR{
			Index:  0,
			Digest: []byte("\xa4\xde-\xf2>\x96\x11)\x91#\xbaCY\xc4*^W\x8b\x0f\x84\x88\xbf\x1b\xba\x8e\xf5`m\x9e\xa5\xd8\x1c\x97\xc0d\xb4\x82\xa5\xea\xc57\xd1f\xbd\x0f\x0fu-"),
		},
		register.RTMR{
			Index:  1,
			Digest: []byte("\x0e\xe96l\x92\x8aw\t/U\xe9\xe1\x14\xc79A\x81\xfd&F\x99\x15_\r\xf7}#Wv\x18\xd5\xf6PV\x8a\x17\xd3y5Z\a\xbd\x84nU/N "),
		},
		register.RTMR{
			Index:  2,
			Digest: []byte("IihM\xc8s\x81\xfc;14\x17l\x8d\x88\x06\xea\xf0\xa9\x01\x85\x9f_pϮ\x8d\x17qKF\xc1\n\x8d\xe2\x19\x04\x8c\x9f\xc0\x9f\x11\xf3\x81\xa6\xfb\xe7\xc1"),
		},
	},
	rtmrs: []register.RTMR{
		{
			Index:  0,
			Digest: []byte("\xa4\xde-\xf2>\x96\x11)\x91#\xbaCY\xc4*^W\x8b\x0f\x84\x88\xbf\x1b\xba\x8e\xf5`m\x9e\xa5\xd8\x1c\x97\xc0d\xb4\x82\xa5\xea\xc57\xd1f\xbd\x0f\x0fu-"),
		},
		{
			Index:  1,
			Digest: []byte("\x0e\xe96l\x92\x8aw\t/U\xe9\xe1\x14\xc79A\x81\xfd&F\x99\x15_\r\xf7}#Wv\x18\xd5\xf6PV\x8a\x17\xd3y5Z\a\xbd\x84nU/N "),
		},
		{
			Index:  2,
			Digest: []byte("IihM\xc8s\x81\xfc;14\x17l\x8d\x88\x06\xea\xf0\xa9\x01\x85\x9f_pϮ\x8d\x17qKF\xc1\n\x8d\xe2\x19\x04\x8c\x9f\xc0\x9f\x11\xf3\x81\xa6\xfb\xe7\xc1"),
		},
	},
}

var IntelTestCCEL = eventLog{
	fname: "../testdata/eventlogs/ccel/CCEL.data.bin",
	mrs: []register.MR{
		register.RTMR{
			Index:  0,
			Digest: []byte("\x80\x83\xcdh\x98\xccR\xa9\x021\xcd\xf9\xc0S+\xf9Q<@F\\oq\xe5l\xbe2\xee,\x11\xa9\xdf\xc00)|\xa3\xca\x0fbG}m\x1fa\r?\xdb"),
		},
		register.RTMR{
			Index:  1,
			Digest: []byte("\x80\x83\xcdh\x98\xccR\xa9\x021\xcd\xf9\xc0S+\xf9Q<@F\\oq\xe5l\xbe2\xee,\x11\xa9\xdf\xc00)|\xa3\xca\x0fbG}m\x1fa\r?\xdb"),
		},
		register.RTMR{
			Index:  2,
			Digest: []byte("\x80\x83\xcdh\x98\xccR\xa9\x021\xcd\xf9\xc0S+\xf9Q<@F\\oq\xe5l\xbe2\xee,\x11\xa9\xdf\xc00)|\xa3\xca\x0fbG}m\x1fa\r?\xdb"),
		},
	},
	rtmrs: []register.RTMR{
		{
			Index:  0,
			Digest: []byte("\x80\x83\xcdh\x98\xccR\xa9\x021\xcd\xf9\xc0S+\xf9Q<@F\\oq\xe5l\xbe2\xee,\x11\xa9\xdf\xc00)|\xa3\xca\x0fbG}m\x1fa\r?\xdb"),
		},
		{
			Index:  1,
			Digest: []byte("\x80\x83\xcdh\x98\xccR\xa9\x021\xcd\xf9\xc0S+\xf9Q<@F\\oq\xe5l\xbe2\xee,\x11\xa9\xdf\xc00)|\xa3\xca\x0fbG}m\x1fa\r?\xdb"),
		},
		{
			Index:  2,
			Digest: []byte("\x80\x83\xcdh\x98\xccR\xa9\x021\xcd\xf9\xc0S+\xf9Q<@F\\oq\xe5l\xbe2\xee,\x11\xa9\xdf\xc00)|\xa3\xca\x0fbG}m\x1fa\r?\xdb"),
		},
	},
}

var GDCCCEL = eventLog{
	fname: "../testdata/eventlogs/ccel/gdc-tdx.bin",
	mrs: []register.MR{
		register.RTMR{
			Index:  0,
			Digest: []byte("FU\xef\x03\xc8w\xb3\xd7Jf >F\x85\x8f\xb9\x90۩t\xa4\\\xa6P\x85\xbcFE\x943n\x04\xebI\xca\x10\x0ej\x1c\xeb\xe7\xae2/2\x88\xb0\x8f")},
		register.RTMR{
			Index:  1,
			Digest: []byte("\xbf\x86\xaa\xc1@\xc1\x05\a\xb7<#\xd2\xf3\xa6v\xb6\xa3iZ\x9a\xad\xe3c5s1\x80\xb0K\x0e\xec\xd2\r\x05\xab\xe2\xe3\xaa^\x8b\v\xads\xfa\xe3\x0f4\xf4")},
		register.RTMR{
			Index:  2,
			Digest: []byte("\xb6_\x82\x02\xd0\xd3\xc9g\x9f\xe0\xb1\xf3\xf3A\xa5\xc8\ue91e\xa4\x93\x14d\x16\xde\xed\x8a\xe3c\xd7c%D\xd4)BN* \x824\xc7n\xd5\xc1\xba\t\xce")},
	},
	rtmrs: []register.RTMR{
		{
			Index:  0,
			Digest: []byte("FU\xef\x03\xc8w\xb3\xd7Jf >F\x85\x8f\xb9\x90۩t\xa4\\\xa6P\x85\xbcFE\x943n\x04\xebI\xca\x10\x0ej\x1c\xeb\xe7\xae2/2\x88\xb0\x8f")},
		{
			Index:  1,
			Digest: []byte("\xbf\x86\xaa\xc1@\xc1\x05\a\xb7<#\xd2\xf3\xa6v\xb6\xa3iZ\x9a\xad\xe3c5s1\x80\xb0K\x0e\xec\xd2\r\x05\xab\xe2\xe3\xaa^\x8b\v\xads\xfa\xe3\x0f4\xf4")},
		{
			Index:  2,
			Digest: []byte("\xb6_\x82\x02\xd0\xd3\xc9g\x9f\xe0\xb1\xf3\xf3A\xa5\xc8\ue91e\xa4\x93\x14d\x16\xde\xed\x8a\xe3c\xd7c%D\xd4)BN* \x824\xc7n\xd5\xc1\xba\t\xce")},
	},
}

func TestParseAndReplay(t *testing.T) {
	tests := []struct {
		el           eventLog
		allowPadding bool
		wantErr      bool
	}{
		{
			el:           COS113TDXUnpadded,
			allowPadding: true,
			wantErr:      false,
		},
		{
			el:           COS113TDXUnpadded,
			allowPadding: false,
			wantErr:      false,
		},
		{
			el:           COS113TDXPadded,
			allowPadding: true,
			wantErr:      false,
		},
		{
			el:           COS113TDXPadded,
			allowPadding: false,
			wantErr:      true,
		},
		{
			el:           GDCCCEL,
			allowPadding: true,
			wantErr:      false,
		},
		{
			el:           GDCCCEL,
			allowPadding: false,
			wantErr:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.el.fname+"_allowPadding_"+strconv.FormatBool(tt.allowPadding), func(t *testing.T) {
			elBytes, err := os.ReadFile(tt.el.fname)
			if err != nil {
				t.Fatal(err)
			}
			_, err = tcg.ParseAndReplay(elBytes,
				tt.el.mrs,
				tcg.ParseOpts{AllowPadding: tt.allowPadding},
			)
			if (err != nil) != tt.wantErr {
				t.Errorf("tcg.ParseAndReplay() = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseCCACPITable(t *testing.T) {
	tableBytes, err := os.ReadFile("../testdata/eventlogs/ccel/CCEL.bin")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		table     []byte
		wantErr   bool
		wantTable CCACPITable
	}{
		{
			name:      "Happy Path",
			table:     tableBytes,
			wantErr:   false,
			wantTable: CCACPITable{65536, TDX},
		},
		{
			name:      "Bad signature",
			table:     []byte{'A', 'B', 'C', 'D', 56, 1, 2, 3, 4},
			wantErr:   true,
			wantTable: CCACPITable{},
		},
		{
			name:      "Bad length",
			table:     []byte{'C', 'C', 'E', 'L', 48, 0, 0, 0},
			wantErr:   true,
			wantTable: CCACPITable{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acpiTable, err := parseCCELACPITable(tt.table)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseCCELACPITable() = %v, wantErr %v", err, tt.wantErr)
			} else {
				if diff := cmp.Diff(acpiTable, tt.wantTable); diff != "" {
					t.Errorf("parseCCELACPITable() = %v, want = %v", acpiTable, tt.wantTable)
				}
			}
		})
	}
}
