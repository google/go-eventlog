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
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	gmes "github.com/google/go-eventlog/extract/gmes"
	"github.com/google/go-eventlog/internal/testutil"
	"github.com/google/go-eventlog/register"
	"github.com/google/go-eventlog/tcg"
	"github.com/google/go-eventlog/testdata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

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
			eventGetters := map[string]func(*testing.T) []tcg.Event{
				"singleBoot":   getCCELEvents,
				"multipleBoot": getCCELEventsWithMultipleBootAttempts,
			}
			for name, getEvents := range eventGetters {
				t.Run(name, func(t *testing.T) {
					evts := getEvents(t)
					tc.mutate(evts)
					fs, err := FirmwareLogState(evts, crypto.SHA384, RTMRRegisterConfig, Opts{Loader: GRUB})
					if (err != nil) != tc.expectErr {
						t.Errorf("FirmwareLogState() = got %v, wantErr: %v", err, tc.expectErr)
					}
					if err == nil && fs.LogType != pb.LogType_LOG_TYPE_CC {
						t.Errorf("FirmwareLogState() = got LogType %v, want LogType: %v", fs.LogType, pb.LogType_LOG_TYPE_CC)
					}
				})
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

func getCCELEventsWithMultipleBootAttempts(t *testing.T) []tcg.Event {
	elBytes, err := os.ReadFile("../testdata/eventlogs/ccel/ubuntu-2404-intel-tdx.bin")
	if err != nil {
		t.Fatal(err)
	}
	rtmr0 := []byte(">/\xb8\xad]\xe9\xb9\xe6m\x0f\xe7:T\xc0)\x13\x0e\xb9\xc0\xae\xf0\x97\x10\xe3\x18\xc9w\xcc\x13\xc7\x186\x8cJ\xdc\x02\xb7K\xc9\xcfL\xf8\x11\x8e\xfe\x1ao\x93")
	rtmr1 := []byte("\x952\x8d\xff\x96\xc9\xd6\xc5T\xa4\x01\x98eX|\xf1~\xccw\xffH\xa9}\xec^R\xe0a\xe58\xbd\x13\xc0\xb7\xf2 ~\xc4\x06|\xb6m\xbe:\x9c\x99\xda'")
	rtmr2 := []byte("\x81\x93\xfdM\xa6-`\xabe\x97\xfc*S˨z\x85\xa9\xa5\xf0\x97\x9f\xd5\xcag\r\x15\xa0x \xe3/\xf6M\xa4i\x9a\xe8+O*`\x05\xaau\xc4x\xd5")
	rtmr3 := []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	mrs := []register.MR{
		register.RTMR{Index: 0, Digest: rtmr0},
		register.RTMR{Index: 1, Digest: rtmr1},
		register.RTMR{Index: 2, Digest: rtmr2},
		register.RTMR{Index: 3, Digest: rtmr3},
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
			eventGetters := map[string]func(*testing.T) (crypto.Hash, []tcg.Event){
				"singleBoot":            getTPMELEvents,
				"ubuntuMultipleBoot":    getTPMELEventsUbuntuWithMultipleBootAttempts,
				"cosSecureMultipleBoot": getTPMELEventsCosWithSecureBootAndMultipleBootAttempts,
			}
			for name, getEvents := range eventGetters {
				t.Run(name, func(t *testing.T) {
					hash, evts := getEvents(t)
					tc.mutate(evts)
					fs, err := FirmwareLogState(evts, hash, TPMRegisterConfig, Opts{Loader: GRUB})
					if (err != nil) != tc.expectErr {
						t.Errorf("FirmwareLogState() = got %v, wantErr: %v", err, tc.expectErr)
					}
					if err == nil && fs.LogType != pb.LogType_LOG_TYPE_TCG2 {
						t.Errorf("FirmwareLogState() = got LogType %v, want LogType: %v", fs.LogType, pb.LogType_LOG_TYPE_TCG2)
					}
				})
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

func getTPMELEventsUbuntuWithMultipleBootAttempts(t *testing.T) (crypto.Hash, []tcg.Event) {
	log := testdata.Ubuntu2404IntelTdxA4HighGpu8GEventLog
	bank := testutil.MakePCRBank(pb.HashAlgo_SHA384, map[uint32][]byte{
		0:  decodeHex("592b3f42ec556a9c093f201124cc7313fdaa4ce40ae1602e14d51f18fbfc480d6a1e196d1c52ad919328410272dc7222"),
		1:  decodeHex("ba1ac69c213175dc72db1493bd5bdfa4799028fe5d5c2bb41ddccc6affa50ba01f189d4639a77afbedd6dd6aff1af3b4"),
		2:  decodeHex("3d29b768ef16e5d7b775ff0397d9d1d22ec83078d1a26ae103de671b6906f0688d713844db3b84783235246e1b564257"),
		3:  decodeHex("518923b0f955d08da077c96aaba522b9decede61c599cea6c41889cfbea4ae4d50529d96fe4d1afdafb65e7f95bf23c4"),
		4:  decodeHex("1213ef15e54d13181724275c16f22f89f866ba2c5b3d24a99a79e4962af4126a8b220c22429fde6e747a4bc4378b556d"),
		5:  decodeHex("c50b529497c7f441ea47305587d6ce83e2e31f7b4fab6c13dc0b0c3c900e1d0caf0768321100927862df142bf0465ee4"),
		6:  decodeHex("518923b0f955d08da077c96aaba522b9decede61c599cea6c41889cfbea4ae4d50529d96fe4d1afdafb65e7f95bf23c4"),
		7:  decodeHex("3ee5663e4119df40192276ff9749a3cd339c489ebc2ab6fd65b11b12a4845d82f4a93bca684126f382feed3324fca561"),
		8:  decodeHex("58b0d4e1a9d3cb21342f0574312c49748f30d30ede290465e79d5238cf76f60d0c89054c5524e7cb1504555913f31efb"),
		9:  decodeHex("8d799e8eb5bdf56009f435adb4238158951e9cf95fd05a9c1bfd3c60eecab5ea0c9d63a2c90ec20b30435f894e8d33db"),
		10: decodeHex("fce98e2810c72187e60a9f83f4e05309a6395a72fb50a366602551227973df5df0c6ef42d9158d94719f4d3f6fdc5be3"),
		11: decodeHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		12: decodeHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		13: decodeHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		14: decodeHex("937437d07298010015f4598395c9f8dc202ef36e0be3897bba89874bf612b5da092beadfe37f79714a60193819e384ad"),
		15: decodeHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		16: decodeHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		17: decodeHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		18: decodeHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		19: decodeHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		20: decodeHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		21: decodeHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		22: decodeHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		23: decodeHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
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

func getTPMELEventsCosWithSecureBootAndMultipleBootAttempts(t *testing.T) (crypto.Hash, []tcg.Event) {
	log := testdata.Cos125IntelTdxSecureBootA4HighGpu8GEventLog
	bank := testutil.MakePCRBank(pb.HashAlgo_SHA384, map[uint32][]byte{
		0:  decodeHex("592b3f42ec556a9c093f201124cc7313fdaa4ce40ae1602e14d51f18fbfc480d6a1e196d1c52ad919328410272dc7222"),
		1:  decodeHex("d67b943903a0ac6244e491604f4d4c2090031142847e914add418b058b032aa636a7eb559669b1879b8459963ab63c24"),
		2:  decodeHex("c286e5791d56d735f1e159bc77c5c0fb04e27a4cb697e74974b98c9db246ac7effc466ab20f42bcd974d2c5e3f1ce7c3"),
		3:  decodeHex("518923b0f955d08da077c96aaba522b9decede61c599cea6c41889cfbea4ae4d50529d96fe4d1afdafb65e7f95bf23c4"),
		4:  decodeHex("404e1dfa6118533162df83b88e9e183272d139e8cb306f103251030aa444ba005e2b9c8cdb90c275f707dd29e21d0085"),
		5:  decodeHex("c50b529497c7f441ea47305587d6ce83e2e31f7b4fab6c13dc0b0c3c900e1d0caf0768321100927862df142bf0465ee4"),
		6:  decodeHex("518923b0f955d08da077c96aaba522b9decede61c599cea6c41889cfbea4ae4d50529d96fe4d1afdafb65e7f95bf23c4"),
		7:  decodeHex("6e64b25bab4f2382466f419dae07a4dbdbaaa3ce56c16bb740516c8bc05cb6c3dbc161016739be4e542a7265c4bd1d70"),
		8:  decodeHex("08052cde78f6561f52a4c37286edac23fa6915e211881770a5ebbbc5fc22411a4805829b9ca4741e0715edbb58aec4e5"),
		9:  decodeHex("596ecbc8e6077dd980848c6f2ebcc7876321c9228eef86939fc61733d02d988e25a3a06d280f36c8d9c026ba2d6175d7"),
		10: decodeHex("8dfb3a115f861a7ef67e9670d47fe970f1029be7ca67b90cb851bc3358311ea3fd376b763b40b3a53df7785f75f1a8cb"),
		11: decodeHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		12: decodeHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		13: decodeHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		14: decodeHex("7dd22d0be1dc4debfbfc5900589ea0940c6276d92edb6fed8625b6ec1f9be341c253d877229c00925c826761760cb355"),
		15: decodeHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		16: decodeHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		17: decodeHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		18: decodeHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		19: decodeHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		20: decodeHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		21: decodeHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		22: decodeHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		23: decodeHex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
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

func TestGMESState(t *testing.T) {
	separatorEvents := []tcg.Event{
		newSeparatorEvent(t, gmes.PCRConfig.BMCFirmwareIdx),
		newSeparatorEvent(t, gmes.PCRConfig.BIOSIdx),
		newSeparatorEvent(t, gmes.PCRConfig.HostKernelIdx),
	}

	bmcEvent := newEvent(t, gmes.PCRConfig.BMCFirmwareIdx, tcg.EFIHCRTMEvent, []byte(gmes.BMCData))
	biosEvent := newEvent(t, gmes.PCRConfig.BIOSIdx, tcg.GoogleDRTMEvent, []byte(gmes.BIOSData))
	kernelEvent := newEFIImageLoadEvent(t, gmes.PCRConfig.HostKernelIdx, 0x1000, 0x2000, 0x3000, []byte("test-dev-path"))

	validEvents := append([]tcg.Event{
		bmcEvent,
		biosEvent,
		kernelEvent,
	}, separatorEvents...)

	// We need to ensure events are replayed correctly.
	events := getEventsFromLog(t, validEvents)

	gotState, err := GMESState(crypto.SHA256, events)
	if err != nil {
		t.Fatalf("GMESState() error = %v", err)
	}

	expectedState := &pb.GMESState{
		BmcFirmwareDigest: bmcEvent.Digest,
		BiosDigest:        biosEvent.Digest,
		HostKernelDigest:  kernelEvent.Digest,
	}

	if diff := cmp.Diff(gotState, expectedState, protocmp.Transform()); diff != "" {
		t.Errorf("GMESState() mismatch (-want +got):\n%s", diff)
	}
}

func TestGMESStateErrors(t *testing.T) {
	separatorEvent := newSeparatorEvent(t, gmes.PCRConfig.HostKernelIdx)
	validEvents := []tcg.Event{
		newEvent(t, gmes.PCRConfig.BMCFirmwareIdx, tcg.EFIHCRTMEvent, []byte(gmes.BMCData)),
		newEvent(t, gmes.PCRConfig.BIOSIdx, tcg.GoogleDRTMEvent, []byte(gmes.BIOSData)),
		newEFIImageLoadEvent(t, gmes.PCRConfig.HostKernelIdx, 0x1000, 0x2000, 0x3000, []byte("test-dev-path")),
		separatorEvent,
	}

	testcases := []struct {
		name           string
		events         []tcg.Event
		expectedErrStr string
	}{
		{
			name:           "duplicate separator",
			events:         append(validEvents, newSeparatorEvent(t, gmes.PCRConfig.HostKernelIdx)),
			expectedErrStr: "duplicate separator event",
		},
		{
			name: "event after separator",
			events: append(validEvents,
				newEvent(t, gmes.PCRConfig.HostKernelIdx, tcg.EFIBootServicesApplication, []byte("ModifiedKernel")),
			),
			expectedErrStr: "found event after separator",
		},
		{
			name: "invalid BMC event type",
			events: []tcg.Event{
				newEvent(t, gmes.PCRConfig.BMCFirmwareIdx, tcg.GoogleDRTMEvent, []byte(gmes.BMCData)),
				separatorEvent,
			},
			expectedErrStr: "unexpected event type for BMC firmware",
		},
		{
			name: "invalid BIOS event type",
			events: []tcg.Event{
				newEvent(t, gmes.PCRConfig.BIOSIdx, tcg.EFIHCRTMEvent, []byte(gmes.BIOSData)),
				separatorEvent,
			},
			expectedErrStr: "unexpected event type for BIOS",
		},
		{
			name: "invalid Host Kernel event type",
			events: []tcg.Event{
				newEvent(t, gmes.PCRConfig.HostKernelIdx, tcg.GoogleDRTMEvent, []byte("testhostkernel")),
				separatorEvent,
			},
			expectedErrStr: "unexpected event type for host kernel",
		},
		{
			name: "unknown MR index",
			events: []tcg.Event{
				newEvent(t, 999, tcg.EFIHCRTMEvent, []byte("unknown data")),
				separatorEvent,
			},
			expectedErrStr: "unknown MR index",
		},
		{
			name: "missing separator",
			events: []tcg.Event{
				newEvent(t, gmes.PCRConfig.BMCFirmwareIdx, tcg.EFIHCRTMEvent, []byte(gmes.BMCData)),
				newEvent(t, gmes.PCRConfig.BIOSIdx, tcg.GoogleDRTMEvent, []byte(gmes.BIOSData)),
			},
			expectedErrStr: "missing separator event",
		},
		{
			name: "extra BMC event",
			events: append(
				validEvents,
				newEvent(t, gmes.PCRConfig.BMCFirmwareIdx, tcg.GoogleDRTMEvent, []byte(gmes.BMCData)),
			),
			expectedErrStr: "found duplicate event for MR",
		},
		{
			name: "extra BIOS event",
			events: append(
				validEvents,
				newEvent(t, gmes.PCRConfig.BIOSIdx, tcg.GoogleDRTMEvent, []byte(gmes.BIOSData)),
			),
			expectedErrStr: "found duplicate event for MR",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := GMESState(crypto.SHA256, getEventsFromLog(t, tc.events))
			if err == nil {
				t.Fatalf("GMESState() expected error containing %q, but got nil", tc.expectedErrStr)
			}

			if !strings.Contains(err.Error(), tc.expectedErrStr) {
				t.Errorf("GMESState() expected error containing %q, but got %v", tc.expectedErrStr, err)
			}
		})
	}
}

// newEvent creates a tcg.Event containing a GMES measurement.
func newEvent(t *testing.T, mrIndex uint32, eventType tcg.EventType, data []byte) tcg.Event {
	t.Helper()
	digest := sha256.Sum256(data)
	return tcg.Event{
		Index:  int(mrIndex),
		Type:   eventType,
		Data:   data,
		Digest: digest[:],
	}
}

// newSeparatorEvent creates a tcg.Separator event for the given MR index.
func newSeparatorEvent(t *testing.T, mrIndex uint32) tcg.Event {
	t.Helper()
	data := []byte{0, 0, 0, 0}
	digest := sha256.Sum256(data)
	return tcg.Event{
		Index:  int(mrIndex),
		Type:   tcg.Separator,
		Data:   data,
		Digest: digest[:],
	}
}

// newEFIImageLoadEvent creates a tcg.Event containing an EFI image load event.
func newEFIImageLoadEvent(t *testing.T, mrIndex uint32, loadAddr, length, linkAddr uint64, devPathData []byte) tcg.Event {
	t.Helper()
	header := tcg.EFIImageLoadHeader{
		LoadAddr:      loadAddr,
		Length:        length,
		LinkAddr:      linkAddr,
		DevicePathLen: uint64(len(devPathData)),
	}
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, header); err != nil {
		t.Fatal(err)
	}
	if _, err := buf.Write(devPathData); err != nil {
		t.Fatal(err)
	}
	return newEvent(t, mrIndex, tcg.EFIBootServicesApplication, buf.Bytes())
}

// getEventsFromLog takes a slice of events and returns a slice of verified events
// by building a synthetic raw event log and replaying it.
func getEventsFromLog(t *testing.T, events []tcg.Event) []tcg.Event {
	t.Helper()

	buf := new(bytes.Buffer)
	// Spec ID event (SHA1 format)
	binary.Write(buf, binary.LittleEndian, uint32(0))    // PCRIndex
	binary.Write(buf, binary.LittleEndian, uint32(0x03)) // Type: NoAction
	binary.Write(buf, binary.LittleEndian, [20]byte{})   // Digest

	specIDBuf := new(bytes.Buffer)
	// "Spec ID Event03\0"
	binary.Write(specIDBuf, binary.LittleEndian, [16]byte{0x53, 0x70, 0x65, 0x63, 0x20, 0x49, 0x44, 0x20, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x30, 0x33, 0x00})
	binary.Write(specIDBuf, binary.LittleEndian, uint32(0))      // PlatformClass
	binary.Write(specIDBuf, binary.LittleEndian, uint8(0))       // VersionMinor
	binary.Write(specIDBuf, binary.LittleEndian, uint8(2))       // VersionMajor
	binary.Write(specIDBuf, binary.LittleEndian, uint8(0))       // Errata
	binary.Write(specIDBuf, binary.LittleEndian, uint8(8))       // UintnSize
	binary.Write(specIDBuf, binary.LittleEndian, uint32(1))      // NumAlgs
	binary.Write(specIDBuf, binary.LittleEndian, uint16(0x000B)) // SHA256 ID
	binary.Write(specIDBuf, binary.LittleEndian, uint16(32))     // SHA256 Size
	binary.Write(specIDBuf, binary.LittleEndian, uint8(0))       // VendorInfoSize

	specIDData := specIDBuf.Bytes()
	binary.Write(buf, binary.LittleEndian, uint32(len(specIDData)))
	buf.Write(specIDData)

	// Subsequent events (TPM 2.0 format)
	for _, e := range events {
		binary.Write(buf, binary.LittleEndian, uint32(e.Index))
		binary.Write(buf, binary.LittleEndian, uint32(e.Type))
		binary.Write(buf, binary.LittleEndian, uint32(1))      // NumDigests
		binary.Write(buf, binary.LittleEndian, uint16(0x000B)) // SHA256
		buf.Write(e.Digest)
		binary.Write(buf, binary.LittleEndian, uint32(len(e.Data)))
		buf.Write(e.Data)
	}

	rawLog := buf.Bytes()

	// Calculate PCRs for replay.
	pcrValues := make(map[int][]byte)
	for _, e := range events {
		h := sha256.New()
		if current, ok := pcrValues[e.Index]; ok {
			h.Write(current)
		} else {
			// First event for this PCR - initialize with zeros.
			// Note this is a simplification for some PCRs. PCRs 17-23 are initialized with 0xFF but
			// the DRTM event clears the index to 0x00 before extending. Starting with 0x00 is functionally
			// the same because DRTM is always the first event, but this is subtly different from the spec.
			initial := make([]byte, h.Size())
			if e.Type == tcg.EFIHCRTMEvent {
				initial[len(initial)-1] = 0x04
			}
			h.Write(initial)
		}
		h.Write(e.Digest)
		pcrValues[e.Index] = h.Sum(nil)
	}

	pcrMap := make(map[uint32][]byte)
	for idx, val := range pcrValues {
		pcrMap[uint32(idx)] = val[:]
	}
	bank := testutil.MakePCRBank(pb.HashAlgo_SHA256, pcrMap)

	// Parse and Replay to get events.
	replayedEvents, err := tcg.ParseAndReplay(rawLog, bank.MRs(), tcg.ParseOpts{})
	if err != nil {
		t.Fatalf("failed to parse synthetic log: %v", err)
	}
	return replayedEvents
}
