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
	"encoding/hex"
	"errors"
	"fmt"

	pb "github.com/google/go-eventlog/proto/state"
	"github.com/google/go-eventlog/tcg"
)

// GetGrubStateForRTMRLog extracts GRUB commands from RTMR2.
func GetGrubStateForRTMRLog(hash crypto.Hash, events []tcg.Event, _ RegisterConfig) (*pb.GrubState, error) {
	var commands []string
	for eventNum, event := range events {
		ccMRIndex := event.MRIndex()
		if ccMRIndex != 3 {
			continue
		}

		// Skip parsing EV_EVENT_TAG event since it likely comes from Linux.
		if event.UntrustedType() == tcg.EventTag {
			continue
		}

		if event.UntrustedType() != tcg.Ipl {
			return nil, fmt.Errorf("invalid event type %v for PCR%d, expected EV_IPL", event.UntrustedType().String(), ccMRIndex)
		}

		hasher := hash.New()
		suffixAt := -1
		rawData := event.RawData()
		for _, prefix := range validPrefixes {
			if bytes.HasPrefix(rawData, prefix) {
				suffixAt = len(prefix)
				break
			}
		}
		if suffixAt == -1 {
			continue
		}
		hasher.Write(rawData[suffixAt : len(rawData)-1])
		if !bytes.Equal(event.ReplayedDigest(), hasher.Sum(nil)) {
			// Older GRUBs measure "grub_cmd " with the null terminator.
			// However, "grub_kernel_cmdline " measurements also ignore the null terminator.
			hasher.Reset()
			hasher.Write(rawData[suffixAt:])
			if !bytes.Equal(event.ReplayedDigest(), hasher.Sum(nil)) {
				return nil, fmt.Errorf("invalid digest seen for GRthe UB event log in event %d: %s", eventNum, hex.EncodeToString(event.ReplayedDigest()))
			}
		}
		hasher.Reset()
		commands = append(commands, string(rawData))
	}
	if len(commands) == 0 {
		return nil, errors.New("no GRUB measurements found")
	}
	return &pb.GrubState{Commands: commands}, nil
}
