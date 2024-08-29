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

// MRBank is a generic interface for a collection of measurement registers
// associated with the same hash algorithm.
type MRBank interface {
	CryptoHash() (crypto.Hash, error)
	MRs() []MR
}

// MR provides a generic interface for measurement registers to implement.
type MR interface {
	Idx() int
	Dgst() []byte
	DgstAlg() crypto.Hash
}
