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

// GetGrubStateForTPMLog extracts GRUB commands from PCR8 and GRUB files from 9.
func GetGrubStateForTPMLog(hash crypto.Hash, events []tcg.Event) (*pb.GrubState, error) {
	var files []*pb.GrubFile
	var commands []string
	for eventNum, event := range events {
		index := event.MRIndex()
		if index != 8 && index != 9 {
			continue
		}

		if event.UntrustedType() != tcg.Ipl {
			return nil, fmt.Errorf("invalid event type for PCR%d, expected EV_IPL", index)
		}

		if index == 9 {
			files = append(files, &pb.GrubFile{Digest: event.ReplayedDigest(),
				UntrustedFilename: event.RawData()})
		} else if index == 8 {
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
				return nil, fmt.Errorf("invalid prefix seen for PCR%d event: %s", index, rawData)
			}
			hasher.Write(rawData[suffixAt : len(rawData)-1])
			if !bytes.Equal(event.ReplayedDigest(), hasher.Sum(nil)) {
				// Older GRUBs measure "grub_cmd " with the null terminator.
				// However, "grub_kernel_cmdline " measurements also ignore the null terminator.
				hasher.Reset()
				hasher.Write(rawData[suffixAt:])
				if !bytes.Equal(event.ReplayedDigest(), hasher.Sum(nil)) {
					return nil, fmt.Errorf("invalid digest seen for GRUB event %d: %s", eventNum, hex.EncodeToString(event.ReplayedDigest()))
				}
			}
			hasher.Reset()
			commands = append(commands, string(rawData))
		}
	}
	if len(files) == 0 && len(commands) == 0 {
		return nil, errors.New("no GRUB measurements found")
	}
	return &pb.GrubState{Files: files, Commands: commands}, nil
}
