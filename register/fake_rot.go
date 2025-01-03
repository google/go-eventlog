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
	"fmt"
)

// FakeROT implements a fake root-of-trust for measurement for test.
type FakeROT struct {
	fakeMRBanks map[crypto.Hash]map[int][]byte
}

// CreateFakeRot creates a fake root-of-trust with banks corresponding to the
// given hash algorithms, each of size numIdxs.
func CreateFakeRot(hashes []crypto.Hash, numIdxs int) (FakeROT, error) {
	if len(hashes) == 0 || numIdxs <= 0 {
		return FakeROT{}, fmt.Errorf("hashes (%v) or numIdxs (%v) was empty", hashes, numIdxs)
	}
	fakeMRBanks := make(map[crypto.Hash]map[int][]byte)
	for _, hash := range hashes {
		fakeBank := make(map[int][]byte)
		for idx := 0; idx < numIdxs; idx++ {
			zeroesMR := make([]byte, hash.Size())
			fakeBank[idx] = zeroesMR
		}
		fakeMRBanks[hash] = fakeBank
	}
	return FakeROT{fakeMRBanks: fakeMRBanks}, nil
}

// Digest returns the current digest for the given measurement register indicated by FakeMR.
func (f FakeROT) Digest(mr FakeMR) ([]byte, error) {
	hash := mr.DigestAlg
	idx := mr.Index
	bank, ok := f.fakeMRBanks[hash]
	if !ok {
		return nil, fmt.Errorf("bank %v not present in fake root of trust", hash)
	}

	dgst, ok := bank[idx]
	if !ok {
		return nil, fmt.Errorf("MR index %v in bank %v not present in fake root of trust", idx, hash)
	}
	if len(dgst) != hash.Size() {
		return nil, fmt.Errorf("MR index %v in bank %v contained invalid size %v, expected %v", idx, hash, len(dgst), hash.Size())
	}
	return dgst, nil
}

// ReadMRs returns the MRs given by the hash algo and MR index selection.
func (f FakeROT) ReadMRs(hash crypto.Hash, mrSelection []int) (FakeMRBank, error) {
	bank, ok := f.fakeMRBanks[hash]
	if !ok {
		return FakeMRBank{}, fmt.Errorf("bank %v not present in fake root of trust", hash)
	}
	fakeMRs := make([]FakeMR, 0, len(bank))
	for _, mrIdx := range mrSelection {
		dgst, ok := bank[mrIdx]
		if !ok {
			return FakeMRBank{}, fmt.Errorf("index %v not present in bank %v", mrIdx, hash)
		}
		fakeMRs = append(fakeMRs, FakeMR{
			Index:     mrIdx,
			Digest:    dgst,
			DigestAlg: hash,
		})
	}
	return FakeMRBank{Hash: hash, FakeMRs: fakeMRs}, nil
}

// ExtendMR extends the FakeROT's internal MRs corresponding to the bank, index
// with the digest specified in mr.
func (f FakeROT) ExtendMR(mr FakeMR) error {
	hash := mr.DigestAlg
	digest := mr.Digest
	idx := mr.Index
	if len(digest) != mr.DigestAlg.Size() {
		return fmt.Errorf("invalid digest size %v for algo %v, expected %v", len(digest), hash, hash.Size())
	}

	mrDigest, err := f.Digest(mr)
	if err != nil {
		return fmt.Errorf("failed to extend index %v in bank %v: %v", idx, hash, err)
	}

	hasher := hash.New()
	hasher.Write(mrDigest)
	hasher.Write(digest)

	f.fakeMRBanks[hash][idx] = hasher.Sum(nil)
	return nil
}
