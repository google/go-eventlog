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

package extract_test

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-eventlog/extract"
	"github.com/google/go-eventlog/internal/testutil"
	"github.com/google/go-eventlog/proto/state"
	"github.com/google/go-eventlog/register"
	"github.com/google/go-eventlog/tcg"
)

func TestSecureBoot(t *testing.T) {
	data, err := os.ReadFile("../testdata/legacydata/windows_gcp_shielded_vm.json")
	if err != nil {
		t.Fatalf("reading test data: %v", err)
	}
	var dump testutil.Dump
	if err := json.Unmarshal(data, &dump); err != nil {
		t.Fatalf("parsing test data: %v", err)
	}

	el, err := tcg.ParseEventLog(dump.Log.Raw, tcg.ParseOpts{})
	if err != nil {
		t.Fatalf("parsing event log: %v", err)
	}
	logBank := register.PCRBank{
		TCGHashAlgo: state.HashAlgo(dump.Log.PCRAlg),
		PCRs:        dump.Log.PCRs}
	events, err := el.Verify(logBank.MRs())
	if err != nil {
		t.Fatalf("validating event log: %v", err)
	}

	sbState, err := extract.ParseSecurebootState(events, extract.TPMRegisterConfig, extract.Opts{})
	if err != nil {
		t.Fatalf("ExtractSecurebootState() failed: %v", err)
	}

	if got, want := sbState.Enabled, true; got != want {
		t.Errorf("secureboot.Enabled = %v, want %v", got, want)
	}
}

// See: https://github.com/google/go-attestation/issues/157
func TestSecureBootBug157(t *testing.T) {
	raw, err := os.ReadFile("../testdata/legacydata/sb_cert_eventlog")
	if err != nil {
		t.Fatalf("reading test data: %v", err)
	}
	elr, err := tcg.ParseEventLog(raw, tcg.ParseOpts{})
	if err != nil {
		t.Fatalf("parsing event log: %v", err)
	}

	pcrs := []register.PCR{
		{Index: '\x00', Digest: []byte("Q\xc3#\xde\f\fiOF\x01\xcd\xd0+\xebX\xff\x13b\x9ft"), DigestAlg: crypto.SHA1},
		{Index: '\x01', Digest: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DigestAlg: crypto.SHA1},
		{Index: '\x02', Digest: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DigestAlg: crypto.SHA1},
		{Index: '\x03', Digest: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DigestAlg: crypto.SHA1},
		{Index: '\x04', Digest: []byte("\xb7q\x00\x8d\x17<\x02+\xc1oKM\x1a\u007f\x8b\x99\xed\x88\xee\xb1"), DigestAlg: crypto.SHA1},
		{Index: '\x05', Digest: []byte("\xd79j\xc6\xe8\x87\xda\"ޠ;@\x95/p\xb8\xdbҩ\x96"), DigestAlg: crypto.SHA1},
		{Index: '\x06', Digest: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DigestAlg: crypto.SHA1},
		{Index: '\a', Digest: []byte("E\xa8b\x1d4\xa5}\xf2\xb2\xe7\xf1L\x92\xb9\x9a\xc8\xde}X\x05"), DigestAlg: crypto.SHA1},
		{Index: '\b', Digest: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DigestAlg: crypto.SHA1},
		{Index: '\t', Digest: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DigestAlg: crypto.SHA1},
		{Index: '\n', Digest: []byte("\x82\x84\x10>\x06\xd4\x01\"\xbcd\xa0䡉\x1a\xf9\xec\xd4\\\xf6"), DigestAlg: crypto.SHA1},
		{Index: '\v', Digest: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DigestAlg: crypto.SHA1},
		{Index: '\f', Digest: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DigestAlg: crypto.SHA1},
		{Index: '\r', Digest: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DigestAlg: crypto.SHA1},
		{Index: '\x0e', Digest: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DigestAlg: crypto.SHA1},
		{Index: '\x0f', Digest: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DigestAlg: crypto.SHA1},
		{Index: '\x10', Digest: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DigestAlg: crypto.SHA1},
		{Index: '\x11', Digest: []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), DigestAlg: crypto.SHA1},
		{Index: '\x12', Digest: []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), DigestAlg: crypto.SHA1},
		{Index: '\x13', Digest: []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), DigestAlg: crypto.SHA1},
		{Index: '\x14', Digest: []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), DigestAlg: crypto.SHA1},
		{Index: '\x15', Digest: []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), DigestAlg: crypto.SHA1},
		{Index: '\x16', Digest: []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), DigestAlg: crypto.SHA1},
		{Index: '\x17', Digest: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DigestAlg: crypto.SHA1},
		{Index: '\x00', Digest: []byte("\xfc\xec\xb5j\xcc08b\xb3\x0e\xb3Bę\v\xebP\xb5ૉr$I\xc2٧?7\xb0\x19\xfe"), DigestAlg: crypto.SHA256},
		{Index: '\x01', Digest: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DigestAlg: crypto.SHA256},
		{Index: '\x02', Digest: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DigestAlg: crypto.SHA256},
		{Index: '\x03', Digest: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DigestAlg: crypto.SHA256},
		{Index: '\x04', Digest: []byte("\xa9)h\x80oy_\xa3D5\xd9\xf1\x18\x13hL\xa1\xe7\x05`w\xf7\x00\xbaI\xf2o\x99b\xf8m\x89"), DigestAlg: crypto.SHA256},
		{Index: '\x05', Digest: []byte("̆\x18\xb7y2\xb4\xef\xda\x12\xccX\xba\xd9>\xcdѕ\x9d\xea)\xe5\xabyE%\xa6\x19\xf5\xba\xab\xee"), DigestAlg: crypto.SHA256},
		{Index: '\x06', Digest: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DigestAlg: crypto.SHA256},
		{Index: '\a', Digest: []byte("Q\xb3\x04\x88\xc9\xe6%]\x82+\xdc\x1b ٩,2\xbd\xe6\xc3\xe7\xbc\x02\xbc\xdd2\x82^\xb5\xef\x06\x9a"), DigestAlg: crypto.SHA256},
		{Index: '\b', Digest: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DigestAlg: crypto.SHA256},
		{Index: '\t', Digest: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DigestAlg: crypto.SHA256},
		{Index: '\n', Digest: []byte("\xc3l\x9a\xb1\x10\x9b\xa0\x8a?dX!\x18\xf8G\x1a]i[\xc9#\xa0\xa2\xbd\x04]\xb1K\x97OB9"), DigestAlg: crypto.SHA256},
		{Index: '\v', Digest: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DigestAlg: crypto.SHA256},
		{Index: '\f', Digest: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DigestAlg: crypto.SHA256},
		{Index: '\r', Digest: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DigestAlg: crypto.SHA256},
		{Index: '\x0e', Digest: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DigestAlg: crypto.SHA256},
		{Index: '\x0f', Digest: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DigestAlg: crypto.SHA256},
		{Index: '\x10', Digest: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DigestAlg: crypto.SHA256},
		{Index: '\x11', Digest: []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), DigestAlg: crypto.SHA256},
		{Index: '\x12', Digest: []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), DigestAlg: crypto.SHA256},
		{Index: '\x13', Digest: []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), DigestAlg: crypto.SHA256},
		{Index: '\x14', Digest: []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), DigestAlg: crypto.SHA256},
		{Index: '\x15', Digest: []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), DigestAlg: crypto.SHA256},
		{Index: '\x16', Digest: []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"), DigestAlg: crypto.SHA256},
		{Index: '\x17', Digest: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), DigestAlg: crypto.SHA256},
	}

	events, err := elr.Verify(register.PCRBank{TCGHashAlgo: state.HashAlgo_SHA1, PCRs: pcrs}.MRs())
	if err != nil {
		t.Fatalf("failed to verify log: %v", err)
	}

	sbs, err := extract.ParseSecurebootState(events, extract.TPMRegisterConfig, extract.Opts{})
	if err != nil {
		t.Fatalf("failed parsing secureboot state: %v", err)
	}
	if got, want := len(sbs.PostSeparatorAuthority), 3; got != want {
		t.Errorf("len(sbs.PostSeparatorAuthority) = %d, want %d", got, want)
	}
}

func b64MustDecode(input string) []byte {
	b, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		panic(err)
	}
	return b
}

func TestSecureBootOptionRom(t *testing.T) {
	raw, err := os.ReadFile("../testdata/legacydata/option_rom_eventlog")
	if err != nil {
		t.Fatalf("reading test data: %v", err)
	}
	elr, err := tcg.ParseEventLog(raw, tcg.ParseOpts{})
	if err != nil {
		t.Fatalf("parsing event log: %v", err)
	}

	pcrs := []register.PCR{
		{Index: '\x00', Digest: b64MustDecode("AVGK7ch6DvUF0nJh74NYCefaAIY="), DigestAlg: crypto.SHA1},
		{Index: '\x01', Digest: b64MustDecode("vr/0wIpmd0c6tgTO3vuC+FDN6IM="), DigestAlg: crypto.SHA1},
		{Index: '\x02', Digest: b64MustDecode("NmoxoMB1No8OEIVzM+ou1uigD9M="), DigestAlg: crypto.SHA1},
		{Index: '\x03', Digest: b64MustDecode("sqg7Dr8vg3Qpmlsr38MeqVWtcjY="), DigestAlg: crypto.SHA1},
		{Index: '\x04', Digest: b64MustDecode("OfOIw5WekEaUcm9MAVttzq4GgKE="), DigestAlg: crypto.SHA1},
		{Index: '\x05', Digest: b64MustDecode("cjoFIM9/KXhUh0K9FUFwayRGRZ4="), DigestAlg: crypto.SHA1},
		{Index: '\x06', Digest: b64MustDecode("sqg7Dr8vg3Qpmlsr38MeqVWtcjY="), DigestAlg: crypto.SHA1},
		{Index: '\x07', Digest: b64MustDecode("IN59+6a838ytrX4+sJnJHU2Xxa0="), DigestAlg: crypto.SHA1},
	}

	events, err := elr.Verify(register.PCRBank{TCGHashAlgo: state.HashAlgo_SHA1, PCRs: pcrs}.MRs())
	if err != nil {
		t.Errorf("failed to verify log: %v", err)
	}

	sbs, err := extract.ParseSecurebootState(events, extract.TPMRegisterConfig, extract.Opts{})
	if err != nil {
		t.Errorf("failed parsing secureboot state: %v", err)
	}
	if got, want := len(sbs.PostSeparatorAuthority), 2; got != want {
		t.Errorf("len(sbs.PostSeparatorAuthority) = %d, want %d", got, want)
	}

	if got, want := len(sbs.DriverLoadSourceHints), 1; got != want {
		t.Fatalf("len(sbs.DriverLoadSourceHints) = %d, want %d", got, want)
	}
	if got, want := sbs.DriverLoadSourceHints[0], extract.PciMmioSource; got != want {
		t.Errorf("sbs.DriverLoadSourceHints[0] = %v, want %v", got, want)
	}
}

func TestSecureBootEventLogUbuntu(t *testing.T) {
	data, err := os.ReadFile("../testdata/legacydata/ubuntu_2104_shielded_vm_no_secure_boot_eventlog")
	if err != nil {
		t.Fatalf("reading test data: %v", err)
	}
	el, err := tcg.ParseEventLog(data, tcg.ParseOpts{})
	if err != nil {
		t.Fatalf("parsing event log: %v", err)
	}
	evts := el.Events(register.HashSHA256)
	if err != nil {
		t.Fatalf("verifying event log: %v", err)
	}
	_, err = extract.ParseSecurebootState(evts, extract.TPMRegisterConfig, extract.Opts{})
	if err != nil {
		t.Errorf("parsing sb state: %v", err)
	}
}

func TestSecureBootEventLogFedora36(t *testing.T) {
	data, err := os.ReadFile("../testdata/legacydata/coreos_36_shielded_vm_no_secure_boot_eventlog")
	if err != nil {
		t.Fatalf("reading test data: %v", err)
	}
	el, err := tcg.ParseEventLog(data, tcg.ParseOpts{})
	if err != nil {
		t.Fatalf("parsing event log: %v", err)
	}
	evts := el.Events(register.HashSHA256)
	if err != nil {
		t.Fatalf("verifying event log: %v", err)
	}
	_, err = extract.ParseSecurebootState(evts, extract.TPMRegisterConfig, extract.Opts{})
	if err != nil {
		t.Errorf("parsing sb state: %v", err)
	}
}

func TestEncodeUEFIVariableData(t *testing.T) {
	data, err := os.ReadFile("../testdata/legacydata/coreos_36_shielded_vm_no_secure_boot_eventlog")
	if err != nil {
		t.Fatalf("reading test data: %v", err)
	}
	el, err := tcg.ParseEventLog(data, tcg.ParseOpts{})
	if err != nil {
		t.Fatalf("parsing event log: %v", err)
	}
	evts := el.Events(register.HashSHA256)
	if err != nil {
		t.Fatalf("verifying event log: %v", err)
	}
	for _, evt := range evts {
		if evt.Type != tcg.EFIVariableDriverConfig {
			continue
		}
		v, err := tcg.ParseUEFIVariableData(bytes.NewReader(evt.RawData()))
		if err != nil {
			t.Fatal(err)
		}
		data, err := v.Encode()
		if err != nil {
			t.Fatal(err)
		}
		newv, err := tcg.ParseUEFIVariableData(bytes.NewReader(data))
		if err != nil {
			t.Errorf("failed to parse after encoding: %v", err)
		}
		if diff := cmp.Diff(v, newv); diff != "" {
			t.Errorf("Encode() produced different encodings: %v", diff)
		}
	}

}

func TestSecureBootAllowEmptySBVar(t *testing.T) {
	data, err := os.ReadFile("../testdata/legacydata/coreos_36_shielded_vm_no_secure_boot_eventlog")
	if err != nil {
		t.Fatalf("reading test data: %v", err)
	}
	el, err := tcg.ParseEventLog(data, tcg.ParseOpts{})
	if err != nil {
		t.Fatalf("parsing event log: %v", err)
	}
	evts := el.Events(register.HashSHA256)
	if err != nil {
		t.Fatalf("verifying event log: %v", err)
	}
	tests := []struct {
		name       string
		newVar     []byte
		allowEmpty bool
		wantErr    bool
	}{
		{
			name:       "emptyAllowed",
			allowEmpty: true,
		},
		{
			name:    "emptyNotAllowed",
			wantErr: true,
		},
		{
			name:       "1emptyAllowed",
			newVar:     []byte{1},
			allowEmpty: true,
		},
		{
			name:   "1emptyNotAllowed",
			newVar: []byte{1},
		},
		{
			name:       "0emptyAllowed",
			newVar:     []byte{0},
			allowEmpty: true,
		},
		{
			name:   "0emptyNotAllowed",
			newVar: []byte{0},
		},
		{
			name:       "len2emptyAllowed",
			newVar:     []byte{0, 1},
			allowEmpty: true,
			wantErr:    true,
		},
		{
			name:    "len2emptyNotAllowed",
			newVar:  []byte{0, 1},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i, evt := range evts {
				if evt.Type != tcg.EFIVariableDriverConfig {
					continue
				}
				v, err := tcg.ParseUEFIVariableData(bytes.NewReader(evt.RawData()))
				if err != nil {
					t.Fatal(err)
				}
				if v.VarName() == "SecureBoot" {
					v.VariableData = tt.newVar
				}
				data, err := v.Encode()
				if err != nil {
					t.Fatal(err)
				}
				evt.Data = data
				dgst := sha256.Sum256(evt.Data)
				evt.Digest = dgst[:]
				evts[i] = evt
			}
			opts := extract.Opts{}
			if tt.allowEmpty {
				opts.AllowEmptySBVar = true
			}
			_, err = extract.ParseSecurebootState(evts, extract.TPMRegisterConfig, opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSecurebootState() = %v, wantErr %v", err, tt.wantErr)

			}

		})
	}

}
