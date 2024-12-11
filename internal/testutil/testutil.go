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

package testutil

import (
	pb "github.com/google/go-eventlog/proto/state"
	"github.com/google/go-eventlog/register"
)

// MakePCRBank takes a hash and a map of index to digest and creates the
// corresponding PCRBank.
func MakePCRBank(hashAlgo pb.HashAlgo, pcrIdxToDigest map[uint32][]byte) register.PCRBank {
	pcrs := make([]register.PCR, 0, len(pcrIdxToDigest))
	digestAlg, err := hashAlgo.CryptoHash()
	if err != nil {
		panic(err)
	}
	for pcrIdx, digest := range pcrIdxToDigest {
		pcrs = append(pcrs, register.PCR{
			Index:     int(pcrIdx),
			Digest:    digest,
			DigestAlg: digestAlg,
		})
	}
	return register.PCRBank{
		TCGHashAlgo: hashAlgo,
		PCRs:        pcrs,
	}
}
