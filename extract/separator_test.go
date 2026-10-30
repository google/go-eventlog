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

package extract

import (
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-eventlog/tcg"
)

// The PC Client spec allows two separator values: 00000000h and FFFFFFFFh.
var separatorCases = []struct {
	name string
	data []byte
}{
	{name: "zero separator", data: []byte{0, 0, 0, 0}},
	{name: "all ones separator", data: []byte{0xff, 0xff, 0xff, 0xff}},
}

func TestGetSeparatorInfoDigests(t *testing.T) {
	// Digests of 00000000h and FFFFFFFFh, in that order.
	want := map[crypto.Hash][][]byte{
		crypto.SHA1: {
			decodeHex("9069ca78e7450a285173431b3e52c5c25299e473"),
			decodeHex("d9be6524a5f5047db5866813acf3277892a7a30a"),
		},
		crypto.SHA256: {
			decodeHex("df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"),
			decodeHex("ad95131bc0b799c0b1af477fb14fcf26a6a9f76079e48bf090acb7e8367bfd0e"),
		},
		crypto.SHA384: {
			decodeHex("394341b7182cd227c5c6b07ef8000cdfd86136c4292b8e576573ad7ed9ae41019f5818b4b971c9effc60e1ad9f1289f0"),
			decodeHex("4a06b879c7eedbe01c945d46b5bd785b59203dce81ea6a1206c28091ca285365f760d9167778f0dc1763d4854aafd40a"),
		},
	}
	for hash, wantDigests := range want {
		t.Run(hash.String(), func(t *testing.T) {
			got := getSeparatorInfo(hash).separatorDigests
			if diff := cmp.Diff(wantDigests, got); diff != "" {
				t.Errorf("getSeparatorInfo(%v) digests mismatch (-want +got):\n%s", hash, diff)
			}
		})
	}
}

// A separator event with a changed type must be rejected for both separator
// values. Otherwise the parser would continue to trust events after the
// separator.
func TestPlatformStateRejectsRetypedSeparator(t *testing.T) {
	for _, tc := range separatorCases {
		t.Run(tc.name, func(t *testing.T) {
			events := getEventsFromLog(t, []tcg.Event{
				newEvent(t, 0, tcg.SCRTMVersion, []byte("pre-separator")),
				newEvent(t, 0, tcg.SCRTMVersion, tc.data),
				newEvent(t, 0, tcg.SCRTMVersion, []byte("post-separator")),
			})
			_, err := PlatformState(crypto.SHA256, events)
			if !errors.Is(err, errRetypedSeparator) {
				t.Errorf("PlatformState() error = %v, want %v", err, errRetypedSeparator)
			}
		})
	}
}

func TestEfiStateRejectsRetypedSeparator(t *testing.T) {
	cfg := TPMRegisterConfig
	for _, tc := range separatorCases {
		t.Run(tc.name, func(t *testing.T) {
			events := getEventsFromLog(t, []tcg.Event{
				newEvent(t, cfg.EFIAppIdx, tcg.EFIAction, []byte(tcg.CallingEFIApplication)),
				newSeparatorEvent(t, cfg.EFIAppIdx),
				newEvent(t, cfg.EFIAppIdx, tcg.EFIBootServicesApplication, tc.data),
				newEvent(t, cfg.ExitBootServicesIdx, tcg.EFIAction, []byte(tcg.ExitBootServicesInvocation)),
			})
			_, err := EfiState(crypto.SHA256, events, cfg, Opts{})
			if !errors.Is(err, errRetypedSeparator) {
				t.Errorf("EfiState() error = %v, want %v", err, errRetypedSeparator)
			}
		})
	}
}

// Separator events with the correct type must still pass for both values.
func TestPlatformStateAcceptsSeparator(t *testing.T) {
	for _, tc := range separatorCases {
		t.Run(tc.name, func(t *testing.T) {
			events := getEventsFromLog(t, []tcg.Event{
				newEvent(t, 0, tcg.SCRTMVersion, []byte("version")),
				newEvent(t, 0, tcg.Separator, tc.data),
			})
			if _, err := PlatformState(crypto.SHA256, events); err != nil {
				t.Errorf("PlatformState() error = %v, want nil", err)
			}
		})
	}
}

// PCR0 events after a valid separator must not change the platform state.
func TestPlatformStateIgnoresEventsAfterSeparator(t *testing.T) {
	for _, tc := range separatorCases {
		t.Run(tc.name, func(t *testing.T) {
			events := getEventsFromLog(t, []tcg.Event{
				newEvent(t, 0, tcg.SCRTMVersion, []byte("version")),
				newEvent(t, 0, tcg.Separator, tc.data),
				newEvent(t, 0, tcg.SCRTMVersion, []byte("post-separator")),
			})
			state, err := PlatformState(crypto.SHA256, events)
			if err != nil {
				t.Fatalf("PlatformState() error = %v", err)
			}
			if got := string(state.GetScrtmVersionId()); got != "version" {
				t.Errorf("PlatformState() SCRTM version = %q, want %q", got, "version")
			}
		})
	}
}
