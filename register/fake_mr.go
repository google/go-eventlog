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

// FakeMRBank is a bank of FakeMRs that all correspond to the same hash algorithm.
type FakeMRBank struct {
	Hash    crypto.Hash
	FakeMRs []FakeMR
}

// CryptoHash returns the crypto.Hash algorithm related to the FakeMR bank.
func (f FakeMRBank) CryptoHash() (crypto.Hash, error) {
	return f.Hash, nil
}

// MRs returns a slice of MR from the PCR implementation.
func (f FakeMRBank) MRs() []MR {
	mrs := make([]MR, len(f.FakeMRs))
	for i, v := range f.FakeMRs {
		mrs[i] = v
	}
	return mrs
}

// FakeMR encapsulates the value of a FakeMR at a point in time.
type FakeMR struct {
	Index     int
	Digest    []byte
	DigestAlg crypto.Hash
}

// Idx gives the FakeMR index.
func (f FakeMR) Idx() int {
	return f.Index
}

// Dgst gives the FakeMR digest.
func (f FakeMR) Dgst() []byte {
	return f.Digest
}

// DgstAlg gives the FakeMR digest algorithm as a crypto.Hash.
func (f FakeMR) DgstAlg() crypto.Hash {
	return f.DigestAlg
}
