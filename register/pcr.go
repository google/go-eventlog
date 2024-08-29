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

// Package register contains measurement register-specific implementations.
package register

import (
	"crypto"
	"fmt"

	pb "github.com/google/go-eventlog/proto/state"
	"github.com/google/go-tpm/legacy/tpm2"
)

// PCRBank is a bank of PCRs that all correspond to the same hash algorithm.
type PCRBank struct {
	TCGHashAlgo pb.HashAlgo
	PCRs        []PCR
}

// CryptoHash returns the crypto.Hash algorithm related to the PCR bank.
func (b PCRBank) CryptoHash() (crypto.Hash, error) {
	cryptoHash, err := b.TCGHashAlgo.CryptoHash()
	if err != nil {
		return crypto.Hash(0), fmt.Errorf("received a bad PCR bank of type %s: %v", b.TCGHashAlgo, err)
	}
	var invalidPCRs []int
	for _, pcr := range b.PCRs {
		if pcr.DgstAlg() != cryptoHash {
			invalidPCRs = append(invalidPCRs, pcr.Idx())
		}
	}
	if len(invalidPCRs) != 0 {
		return crypto.Hash(0), fmt.Errorf("found an invalid hash algorithm in PCRs %v for bank of algorithm type %s", invalidPCRs, b.TCGHashAlgo.String())
	}
	return cryptoHash, nil
}

// MRs returns a slice of MR from the PCR implementation.
func (b PCRBank) MRs() []MR {
	mrs := make([]MR, len(b.PCRs))
	for i, v := range b.PCRs {
		mrs[i] = v
	}
	return mrs
}

// PCR encapsulates the value of a PCR at a point in time.
type PCR struct {
	Index     int
	Digest    []byte
	DigestAlg crypto.Hash

	// quoteVerified is true if the PCR was verified against a quote.
	// NOT for use in go-eventlog.
	// Included for backcompat with the go-attestation API.
	quoteVerified bool
}

// Idx gives the PCR index.
func (p PCR) Idx() int {
	return p.Index
}

// Dgst gives the PCR digest.
func (p PCR) Dgst() []byte {
	return p.Digest
}

// DgstAlg gives the PCR digest algorithm as a crypto.Hash.
func (p PCR) DgstAlg() crypto.Hash {
	return p.DigestAlg
}

// SetQuoteVerified sets that the quote verified is true.
// NOT for use in go-eventlog.
// Included for backcompat with the go-attestation API.
func (p *PCR) SetQuoteVerified() {
	p.quoteVerified = true
}

// QuoteVerified returns true if the value of this PCR was previously
// verified against a Quote, in a call to AKPublic.Verify or AKPublic.VerifyAll.
// NOT for use in go-eventlog.
// Included for backcompat with the go-attestation API.
func (p *PCR) QuoteVerified() bool {
	return p.quoteVerified
}

// HashAlg identifies a hashing Algorithm.
// Included for backcompat with the go-attestation API.
type HashAlg uint8

// Valid hash algorithms.
var (
	HashSHA1   = HashAlg(tpm2.AlgSHA1)
	HashSHA256 = HashAlg(tpm2.AlgSHA256)
	HashSHA384 = HashAlg(tpm2.AlgSHA384)
)

// CryptoHash turns the hash algo into a crypto.Hash
func (a HashAlg) CryptoHash() crypto.Hash {
	switch a {
	case HashSHA1:
		return crypto.SHA1
	case HashSHA256:
		return crypto.SHA256
	case HashSHA384:
		return crypto.SHA384
	}
	return 0
}

// GoTPMAlg returns the go-tpm definition of this crypto.Hash, based on the
// TCG Algorithm Registry.
func (a HashAlg) GoTPMAlg() tpm2.Algorithm {
	switch a {
	case HashSHA1:
		return tpm2.AlgSHA1
	case HashSHA256:
		return tpm2.AlgSHA256
	case HashSHA384:
		return tpm2.AlgSHA384
	}
	return 0
}

// String returns a human-friendly representation of the hash algorithm.
func (a HashAlg) String() string {
	switch a {
	case HashSHA1:
		return "SHA1"
	case HashSHA256:
		return "SHA256"
	case HashSHA384:
		return "SHA384"
	}
	return fmt.Sprintf("HashAlg<%d>", int(a))
}
