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

package register

import (
	"crypto"
)

/*
RTMR0 => PCR1,7
RTMR1 => PCR2-6
RTMR2 => PCR8-15
RTMR3 => N/A (for userspace)
*/

// RTMRBank is a bank of RTMRs that all correspond to the SHA-384 algorithm.
type RTMRBank struct {
	RTMRs []RTMR
}

func (b *RTMRBank) CryptoHash() (crypto.Hash, error) {
	return crypto.SHA384, nil
}

func (b RTMRBank) MRs() []MR {
	mrs := make([]MR, len(b.RTMRs))
	for i, v := range b.RTMRs {
		mrs[i] = v
	}
	return mrs
}

// RTMR encapsulates the value of a TDX runtime measurement register at a point
// in time. The given RTMR must always have a SHA-384 digest.
type RTMR struct {
	// The RTMR Index, not the CC MR Index. e.g., for RTMR[1], put 1, not 2.
	Index  int
	Digest []byte
}

// Confusingly, MRTD uses CC Measurement Register Index 0, so RTMR0 uses 1.
// RTMR1 uses 2, and so on.
// https://cdrdv2-public.intel.com/726792/TDX%20Guest-Hypervisor%20Communication%20Interface_1.5_348552_004%20-%2020230317.pdf
// https://github.com/cc-api/cc-trusted-vmsdk/issues/50
// TODO: should this go in an event log option?
func (r RTMR) Idx() int {
	return r.Index + 1
}

func (r RTMR) Dgst() []byte {
	return r.Digest
}

func (r RTMR) DgstAlg() crypto.Hash {
	return crypto.SHA384
}
