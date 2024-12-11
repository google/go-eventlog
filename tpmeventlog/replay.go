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

// Package tpmeventlog implements event log parsing and replay for the PC Client
// TPM PCR_based event log.
// It supports both the SHA-1 only and crypto agile log formats.
package tpmeventlog

import (
	"github.com/google/go-eventlog/extract"
	pb "github.com/google/go-eventlog/proto/state"
	"github.com/google/go-eventlog/register"
	"github.com/google/go-eventlog/tcg"
)

// ReplayAndExtract parses a PC Client event log and replays the parsed
// event log against the PCR bank specified by hash.
//
// It then extracts event info from the verified log into a FirmwareLogState.
// It returns an error on failing to replay the events against the PCR bank or
// on failing to parse malformed events.
//
// The returned FirmwareLogState may be a partial FirmwareLogState.
// In the case of a partially filled state, err will be non-nil.
// Callers can look for individual errors using `errors.Is`.
//
// It is the caller's responsibility to ensure that the passed PCR values can be
// trusted. Users can establish trust in PCR values by either calling
// client.ReadPCRs() themselves or by verifying the values via a PCR quote.
func ReplayAndExtract(rawEventLog []byte, pcrBank register.PCRBank, opts extract.Opts) (*pb.FirmwareLogState, error) {
	cryptoHash, err := pcrBank.CryptoHash()
	if err != nil {
		return &pb.FirmwareLogState{}, err
	}
	events, err := tcg.ParseAndReplay(rawEventLog, pcrBank.MRs(), tcg.ParseOpts{})
	if err != nil {
		return nil, err
	}

	return extract.GetFirmwareLogState(events, cryptoHash, extract.TPMRegisterConfig, opts)
}
