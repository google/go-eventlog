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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-eventlog/register"
	"github.com/google/go-eventlog/tcg"
)

func TestParseAndReplay(t *testing.T) {
	elBytes, err := os.ReadFile("../testdata/eventlogs/ccel/CCEL.data.bin")
	if err != nil {
		t.Fatal(err)
	}
	zeroes := make([]byte, 48)
	rtmr0 := []byte("\x80\x83\xcdh\x98\xccR\xa9\x021\xcd\xf9\xc0S+\xf9Q<@F\\oq\xe5l\xbe2\xee,\x11\xa9\xdf\xc00)|\xa3\xca\x0fbG}m\x1fa\r?\xdb")
	rtmr1 := []byte("d\x84\xf0\xd7,\x03R\x1c\x044U;\xe3N\x8d\xb8\"\x8br\x9ey\x96fҷu@\x85\xc7z\xa9\x98\x1fZD\r\xf3\x04q\x94\xb2O!/\xf1\x16\f\x1e")
	rtmr2 := []byte("\xc3\xe7\xed\x9d~\x90\x9b)s/gm\x01\xdccކ\x9b\x04\x93b\xb5\"\xa3\x15\xcb\x04&\x89g\v\xe0sD\xc3Gυمǹ(ԓNA\xe1")
	_, err = tcg.ParseAndReplay(elBytes, []register.MR{
		register.RTMR{Index: 0, Digest: rtmr0},
		register.RTMR{Index: 1, Digest: rtmr1},
		register.RTMR{Index: 2, Digest: rtmr2},
		register.RTMR{Index: 3, Digest: zeroes},
	})
	if err != nil {
		t.Errorf("failed to parse and replay CCEL: %v", err)
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
