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
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/google/go-eventlog/internal/testutil"
	"github.com/google/go-eventlog/register"
	"github.com/google/go-eventlog/tcg"
	"github.com/google/go-eventlog/testdata"
	"google.golang.org/protobuf/proto"

	pb "github.com/google/go-eventlog/proto/state"
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
					bigInt, err := rand.Int(rand.Reader, big.NewInt(4))
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
			fs, err := FirmwareLogState(evts, crypto.SHA384, RTMRRegisterConfig, Opts{Loader: GRUB})
			if (err != nil) != tc.expectErr {
				t.Errorf("FirmwareLogState(%v) = got %v, wantErr: %v", tc.name, err, tc.expectErr)
			}
			if fs.LogType != pb.LogType_LOG_TYPE_CC {
				t.Errorf("FirmwareLogState(%v) = got LogType %v, want LogType: %v", tc.name, fs.LogType, pb.LogType_LOG_TYPE_CC)
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
			fs, err := FirmwareLogState(evts, hash, TPMRegisterConfig, Opts{Loader: GRUB})
			if (err != nil) != tc.expectErr {
				t.Errorf("ExtractFirmwareLogState(%v) = got %v, wantErr: %v", tc.name, err, tc.expectErr)
			}
			if fs.LogType != pb.LogType_LOG_TYPE_TCG2 {
				t.Errorf("FirmwareLogState(%v) = got LogType %v, want LogType: %v", tc.name, fs.LogType, pb.LogType_LOG_TYPE_TCG2)
			}
		})
	}
}

func TestExtractFirmwareLogStateNoLogType(t *testing.T) {
	hash, evts := getTPMELEvents(t)
	missingType := TPMRegisterConfig
	missingType.LogType = pb.LogType_LOG_TYPE_UNDEFINED
	fs, err := FirmwareLogState(evts, hash, missingType, Opts{Loader: GRUB})
	if err != nil {
		t.Fatal("failed to extract FirmwareLogState")
	}
	if fs.LogType != pb.LogType_LOG_TYPE_UNDEFINED {
		t.Errorf("FirmwareLogState() = got LogType %v, want LogType: %v", fs.LogType, pb.LogType_LOG_TYPE_UNDEFINED)
	}
}

func TestExtractFirmwareLogStateTPMNilEvents(t *testing.T) {
	_, err := FirmwareLogState(nil, crypto.SHA384, TPMRegisterConfig, Opts{Loader: GRUB})
	if err == nil || !strings.Contains(err.Error(), "no GRUB measurements found") {
		t.Errorf("ExtractFirmwareLogState(nil): got %v, expected error no GRUB measurements found", err)
	}
}

func TestGrubStateFromTPMLogWithModifiedNullTerminator(t *testing.T) {
	hash, tpmEvents := getTPMELEvents(t)

	// Make sure the original events can parse successfully.
	if _, err := GrubStateFromTPMLog(hash, tpmEvents); err != nil {
		t.Fatal(err)
	}

	// Change the null terminator
	for _, e := range tpmEvents {
		if e.Index == 8 {
			if e.Data[len(e.Data)-1] == '\x00' {
				e.Data[len(e.Data)-1] = '\xff'
			}
		}
	}

	if _, err := GrubStateFromTPMLog(hash, tpmEvents); err == nil {
		t.Error("GrubStateFromTPMLog should fail after modifying the null terminator")
	}
}

func TestGrubStateFromRTMRLogWithModifiedNullTerminator(t *testing.T) {
	ccelEvents := getCCELEvents(t)

	// Make sure the original events can parse successfully.
	if _, err := GrubStateFromRTMRLog(crypto.SHA384, ccelEvents); err != nil {
		t.Fatal(err)
	}

	for _, e := range ccelEvents {
		if e.Data[len(e.Data)-1] == '\x00' {
			e.Data[len(e.Data)-1] = '\xff'
		}
	}
	if _, err := GrubStateFromRTMRLog(crypto.SHA384, ccelEvents); err == nil {
		t.Error("GrubStateFromRTMRLog should fail after modifying the null terminator")
	}
}

func TestEfiState(t *testing.T) {
	tests := []struct {
		name            string
		events          func() (crypto.Hash, []tcg.Event)
		registserConfig registerConfig
		wantPass        bool
		wantEfiState    *pb.EfiState
		opts            Opts
	}{
		{
			name: "success with TPM logs",
			events: func() (crypto.Hash, []tcg.Event) {
				return getTPMELEvents(t)
			},
			registserConfig: TPMRegisterConfig,
			wantPass:        true,
			wantEfiState: &pb.EfiState{
				Apps: []*pb.EfiApp{
					{
						Digest: []byte("rM\xe6\x84M\xd0\xfea\x8b\xa5wl{\xca\x07(\xbe8\xa6TN$\xe4N\xf2Y\xb9\x87\xb7\xab΀"),
					},
					{
						Digest: []byte("^\x8c\xb7Z\xcd\xf8\xe0\x9e_\xc1L\xc2\xd6\xce\x0c\"\x88\xaf \x89v\xd9s\t\x85\x1cf\x1e\x91\xec\x1e\x03"),
					},
				},
			},
			opts: Opts{
				AllowEFIAppBeforeCallingEvent: false,
			},
		},
		{
			name: "success with CCEL logs",
			events: func() (crypto.Hash, []tcg.Event) {
				return crypto.SHA384, getCCELEvents(t)
			},
			registserConfig: RTMRRegisterConfig,
			wantPass:        true,
			wantEfiState: &pb.EfiState{
				Apps: []*pb.EfiApp{
					{
						Digest: []byte("Z\x10\x02l\x9a\xd4\x1d\x1f\x90ܜ\xfe\x88\xbc\xab\xe1\x84,\xcf\xd8T\x95\xc8\x1b\x1a\x1a\xb9&\xa9\xef#\xb5\xd2\xe6\x0e\xef\xeb\xa0A[\xbe\\\x8c2\x8a\x89\x9a\n"),
					},
					{
						Digest: []byte("\xb1\xfb\x7fL\x06\x89\xf5\xa9 \xb8\x00\xb2`pu\xf4\x90o\x8c\x82\x82\xd4NV\xfc\x99\x1e\xc0\x1f\x1a\xda\xc1v\xd2\x04\n&\xf1E=\xf1\x12\xd7\xc4\xf4)?\xc9"),
					},
				},
			},
			opts: Opts{
				AllowEFIAppBeforeCallingEvent: false,
			},
		},
		{
			name: "nil EFI state with missing ExitBootServicesInvocation event in TPM logs",
			events: func() (crypto.Hash, []tcg.Event) {
				hash, evts := getTPMELEvents(t)
				var failedEvts []tcg.Event
				for _, e := range evts {
					if bytes.Equal(e.RawData(), []byte(tcg.ExitBootServicesInvocation)) {
						continue
					}
					failedEvts = append(failedEvts, e)
				}
				return hash, failedEvts
			},
			registserConfig: TPMRegisterConfig,
			wantPass:        true,
			wantEfiState:    nil,
			opts: Opts{
				AllowEFIAppBeforeCallingEvent: false,
			},
		},
		{
			name: "failed with missing CallingEFIApp event in TPM logs",
			events: func() (crypto.Hash, []tcg.Event) {
				hash, evts := getTPMELEvents(t)
				var failedEvts []tcg.Event
				for _, e := range evts {
					if bytes.Equal(e.RawData(), []byte(tcg.CallingEFIApplication)) {
						continue
					}
					failedEvts = append(failedEvts, e)
				}
				return hash, failedEvts
			},
			registserConfig: TPMRegisterConfig,
			wantPass:        false,
			wantEfiState:    nil,
			opts: Opts{
				AllowEFIAppBeforeCallingEvent: false,
			},
		},
		{
			name: "failed with multiple separators in TPM logs",
			events: func() (crypto.Hash, []tcg.Event) {
				hash, evts := getTPMELEvents(t)
				for i := range evts {
					evts[i].Type = tcg.Separator
				}
				return hash, evts
			},
			registserConfig: TPMRegisterConfig,
			wantPass:        false,
			wantEfiState:    nil,
			opts: Opts{
				AllowEFIAppBeforeCallingEvent: false,
			},
		},
		{
			name: "failed with bad data in TPM logs",
			events: func() (crypto.Hash, []tcg.Event) {
				hash, evts := getTPMELEvents(t)
				for i := range evts {
					b := make([]byte, len(evts[i].Data))
					if _, err := rand.Read(b); err != nil {
						t.Fatal(err)
					}
					evts[i].Data = b
				}
				return hash, evts
			},
			registserConfig: TPMRegisterConfig,
			wantPass:        false,
			wantEfiState:    nil,
			opts: Opts{
				AllowEFIAppBeforeCallingEvent: false,
			},
		},
		{
			name: "failed with valid boot attempt before Separator event in CCEL logs",
			events: func() (crypto.Hash, []tcg.Event) {
				hash, evts := crypto.SHA384, getCCELEvents(t)
				var failedEvts []tcg.Event
				for _, e := range evts {
					if bytes.Equal(e.RawData(), []byte(tcg.CallingEFIApplication)) {
						continue
					}
					failedEvts = append(failedEvts, e)
				}
				return hash, failedEvts
			},
			registserConfig: RTMRRegisterConfig,
			wantPass:        false,
			wantEfiState:    nil,
			opts: Opts{
				AllowEFIAppBeforeCallingEvent: true,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hash, events := tc.events()
			efiState, err := EfiState(hash, events, tc.registserConfig, tc.opts)
			if gotPass := (err == nil); gotPass != tc.wantPass {
				t.Errorf("EfiState returned unexpected result, gotPass %v, but want %v", gotPass, tc.wantPass)
			}
			if !proto.Equal(efiState, tc.wantEfiState) {
				t.Errorf("EfiState returned unexpected state, got %+v, but want %+v", efiState, tc.wantEfiState)
			}
		})
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
