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

package extract

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/google/go-eventlog/internal/testutil"
	pb "github.com/google/go-eventlog/proto/state"
	"github.com/google/go-eventlog/register"
	"github.com/google/go-eventlog/tcg"
	"github.com/google/go-eventlog/testdata"
)

func TestExtractFirmwareLogStateRTMR(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func([]tcg.Event)
		expectErr bool
	}{
		{
			name:   "Happy Path",
			mutate: func(_ []tcg.Event) {},
		},
		{
			name: "Nil Digests",
			mutate: func(evts []tcg.Event) {
				for i := range evts {
					evts[i].Digest = nil
				}
			},
			expectErr: true,
		},
		{
			name: "Bad Digests",
			mutate: func(evts []tcg.Event) {
				for i := range evts {
					b := make([]byte, len(evts[i].Digest))
					if _, err := rand.Read(b); err != nil {
						t.Fatal(err)
					}
					evts[i].Digest = b
				}
			},
			expectErr: true,
		},
		{
			name: "Nil Data",
			mutate: func(evts []tcg.Event) {
				for i := range evts {
					evts[i].Data = nil
				}
			},
			expectErr: true,
		},
		{
			name: "Bad Data",
			mutate: func(evts []tcg.Event) {
				for i := range evts {
					b := make([]byte, len(evts[i].Data))
					if _, err := rand.Read(b); err != nil {
						t.Fatal(err)
					}
					evts[i].Data = b
				}
			},
			expectErr: true,
		},
		{
			name: "Zero Index",
			mutate: func(evts []tcg.Event) {
				for i := range evts {
					evts[i].Index = 0
				}
			},
			expectErr: true,
		},
		{
			name: "Rand Index",
			mutate: func(evts []tcg.Event) {
				for i := range evts {
					bigInt, err := rand.Int(rand.Reader, big.NewInt(25))
					if err != nil {
						t.Fatal(err)
					}
					evts[i].Index = int(bigInt.Int64())
				}
			},
			expectErr: true,
		},
		{
			name: "Zero Type",
			mutate: func(evts []tcg.Event) {
				for i := range evts {
					evts[i].Type = 0
				}
			},
			expectErr: true,
		},
		{
			name: "More Separators",
			mutate: func(evts []tcg.Event) {
				for i := range evts {
					evts[i].Type = tcg.Separator
				}
			},
			expectErr: true,
		},
		{
			name: "More EFIAction",
			mutate: func(evts []tcg.Event) {
				for i := range evts {
					evts[i].Type = tcg.EFIAction
				}
			},
			expectErr: true,
		},
		{
			name: "More IPL",
			mutate: func(evts []tcg.Event) {
				for i := range evts {
					evts[i].Type = tcg.Ipl
				}
			},
			expectErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			evts := getCCELEvents(t)
			tc.mutate(evts)
			_, err := FirmwareLogState(evts, crypto.SHA384, RTMRRegisterConfig, Opts{Loader: GRUB})
			if (err != nil) != tc.expectErr {
				t.Errorf("ExtractFirmwareLogState(%v) = got %v, wantErr: %v", tc.name, err, tc.expectErr)
			}
		})
	}
}

func TestExtractFirmwareLogStateRTMRNilEvents(t *testing.T) {
	_, err := FirmwareLogState(nil, crypto.SHA384, RTMRRegisterConfig, Opts{Loader: GRUB})
	if err == nil || !strings.Contains(err.Error(), "no GRUB measurements found") {
		t.Errorf("ExtractFirmwareLogState(nil): got %v, expected error no GRUB measurements found", err)
	}
}

func getCCELEvents(t *testing.T) []tcg.Event {
	elBytes, err := os.ReadFile("../testdata/eventlogs/ccel/cos-113-intel-tdx.bin")
	if err != nil {
		t.Fatal(err)
	}
	rtmr0 := []byte("?\xa2\xf6\x1f9[\x7f_\xee\xfbN\xc2\xdfa)\x7f\x10\x9aث\xcdd\x10\xc1\xb7\xdf`\xf2\x1f7\xb1\x92\x97\xfc5\xe5D\x03\x9c~\x1e\xde\xceu*\xfd\x17\xf6")
	rtmr1 := []byte("\xf6-\xbc\a+\xd5\xd3\xf3C\x8b{5Úr\x7fZ\xea/\xfc$s\xf47#\x95?S\r\xafbPO\nyD\xaab\xc4\x1a\x86\xe8\xa8x±\"\xc1")
	rtmr2 := []byte("IihM\xc8s\x81\xfc;14\x17l\x8d\x88\x06\xea\xf0\xa9\x01\x85\x9f_pϮ\x8d\x17qKF\xc1\n\x8d\xe2\x19\x04\x8c\x9f\xc0\x9f\x11\xf3\x81\xa6\xfb\xe7\xc1")
	mrs := []register.MR{
		register.RTMR{Index: 0, Digest: rtmr0},
		register.RTMR{Index: 1, Digest: rtmr1},
		register.RTMR{Index: 2, Digest: rtmr2},
	}
	events, err := tcg.ParseAndReplay(elBytes, mrs, tcg.ParseOpts{AllowPadding: true})
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func TestExtractFirmwareLogStateTPM(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func([]tcg.Event)
		expectErr bool
	}{
		{
			name:   "Happy Path",
			mutate: func(_ []tcg.Event) {},
		},
		{
			name: "Nil Digests",
			mutate: func(evts []tcg.Event) {
				for i := range evts {
					evts[i].Digest = nil
				}
			},
			expectErr: true,
		},
		{
			name: "Bad Digests",
			mutate: func(evts []tcg.Event) {
				for i := range evts {
					b := make([]byte, len(evts[i].Digest))
					if _, err := rand.Read(b); err != nil {
						t.Fatal(err)
					}
					evts[i].Digest = b
				}
			},
			expectErr: true,
		},
		{
			name: "Nil Data",
			mutate: func(evts []tcg.Event) {
				for i := range evts {
					evts[i].Data = nil
				}
			},
			expectErr: true,
		},
		{
			name: "Bad Data",
			mutate: func(evts []tcg.Event) {
				for i := range evts {
					b := make([]byte, len(evts[i].Data))
					if _, err := rand.Read(b); err != nil {
						t.Fatal(err)
					}
					evts[i].Data = b
				}
			},
			expectErr: true,
		},
		{
			name: "Zero Index",
			mutate: func(evts []tcg.Event) {
				for i := range evts {
					evts[i].Index = 0
				}
			},
			expectErr: true,
		},
		{
			name: "Rand Index",
			mutate: func(evts []tcg.Event) {
				for i := range evts {
					bigInt, err := rand.Int(rand.Reader, big.NewInt(25))
					if err != nil {
						t.Fatal(err)
					}
					evts[i].Index = int(bigInt.Int64())
				}
			},
			expectErr: true,
		},
		{
			name: "Zero Type",
			mutate: func(evts []tcg.Event) {
				for i := range evts {
					evts[i].Type = 0
				}
			},
			expectErr: true,
		},
		{
			name: "More Separators",
			mutate: func(evts []tcg.Event) {
				for i := range evts {
					evts[i].Type = tcg.Separator
				}
			},
			expectErr: true,
		},
		{
			name: "More EFIAction",
			mutate: func(evts []tcg.Event) {
				for i := range evts {
					evts[i].Type = tcg.EFIAction
				}
			},
			expectErr: true,
		},
		{
			name: "More IPL",
			mutate: func(evts []tcg.Event) {
				for i := range evts {
					evts[i].Type = tcg.Ipl
				}
			},
			expectErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hash, evts := getTPMELEvents(t)
			tc.mutate(evts)
			_, err := FirmwareLogState(evts, hash, TPMRegisterConfig, Opts{Loader: GRUB})
			if (err != nil) != tc.expectErr {
				t.Errorf("ExtractFirmwareLogState(%v) = got %v, wantErr: %v", tc.name, err, tc.expectErr)
			}
		})
	}
}

func TestExtractFirmwareLogStateTPMNilEvents(t *testing.T) {
	_, err := FirmwareLogState(nil, crypto.SHA384, TPMRegisterConfig, Opts{Loader: GRUB})
	if err == nil || !strings.Contains(err.Error(), "no GRUB measurements found") {
		t.Errorf("ExtractFirmwareLogState(nil): got %v, expected error no GRUB measurements found", err)
	}
}

func getTPMELEvents(t *testing.T) (crypto.Hash, []tcg.Event) {
	log := testdata.Ubuntu2404AmdSevSnpEventLog
	bank := testutil.MakePCRBank(pb.HashAlgo_SHA256, map[uint32][]byte{
		0:  decodeHex("50597a27846e91d025eef597abbc89f72bff9af849094db97b0684d8bc4c515e"),
		1:  decodeHex("57344e1cc8c6619413df33013a7cd67915459f967395af41db21c1fa7ca9c307"),
		2:  decodeHex("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
		3:  decodeHex("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
		4:  decodeHex("abe8b3fa6aecb36c2fd93c6f6edde661c21b353d007410a2739d69bfa7e1b9be"),
		5:  decodeHex("0b0e1903aeb1bff649b82dba2cdcf5c4ffb75027e54f151ab00b3b989f16a300"),
		6:  decodeHex("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
		7:  decodeHex("33ad69850fb2c7f30b4f8b4bc10ed93fc954dc07fa726e84f50f3d192dc1c140"),
		8:  decodeHex("6932a3f71dc55ad3c1a6ac2196eeac26a1b7164b6bbfa106625d94088ec3ecc3"),
		9:  decodeHex("ce08798b283c7a0ddc5e9ad1d602304b945b741fc60c20e254eafa0f4782512b"),
		14: decodeHex("306f9d8b94f17d93dc6e7cf8f5c79d652eb4c6c4d13de2dddc24af416e13ecaf"),
	})
	cryptoHash, err := bank.CryptoHash()
	if err != nil {
		t.Fatal(err)
	}
	events, err := tcg.ParseAndReplay(log, bank.MRs(), tcg.ParseOpts{})
	if err != nil {
		t.Fatal(err)

	}
	return cryptoHash, events
}

func decodeHex(hexStr string) []byte {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(err)
	}
	return bytes
}
