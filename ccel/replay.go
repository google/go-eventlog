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
	"fmt"

	"github.com/google/go-eventlog/extract"
	pb "github.com/google/go-eventlog/proto/state"
	"github.com/google/go-eventlog/register"
	"github.com/google/go-eventlog/tcg"
)

// ReplayAndExtract parses a Confidential Computing event log and
// replays the parsed event log against the RTMR bank specified by hash.
//
// It then extracts event info from the verified log into a FirmwareLogState.
// It returns an error on failing to replay the events against the RTMR bank or
// on failing to parse malformed events.
//
// The returned FirmwareLogState may be a partial FirmwareLogState.
// In the case of a partially filled state, err will be non-nil.
// Callers can look for individual errors using `errors.Is`.
//
// It is the caller's responsibility to ensure that the passed RTMR values can be
// trusted. Users can establish trust in RTMR values by either calling
// client.ReadRTMRs() themselves or by verifying the values via a RTMR quote.
func ReplayAndExtract(acpiTableFile []byte, rawEventLog []byte, rtmrBank register.RTMRBank, opts extract.Opts) (*pb.FirmwareLogState, error) {
	table, err := parseCCELACPITable(acpiTableFile)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CCEL ACPI Table file: %v", err)
	}
	if table.CCType != TDX {
		return nil, fmt.Errorf("only TDX Confidential Computing event logs are supported: received %v", table.CCType)
	}

	cryptoHash, err := rtmrBank.CryptoHash()
	if err != nil {
		return &pb.FirmwareLogState{}, err
	}
	// CCELs have trailing padding at the end of the event log.
	events, err := tcg.ParseAndReplay(rawEventLog, rtmrBank.MRs(), tcg.ParseOpts{AllowPadding: true})
	if err != nil {
		return nil, err
	}
	return extract.GetFirmwareLogState(events, cryptoHash, extract.RTMRRegisterConfig, opts)
}
