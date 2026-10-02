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

package tcg

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm/legacy/tpm2"
)

// unrecognizedType is a UEFI range event type that no spec assigns.
const unrecognizedType EventType = 0x800000FF

func TestUnrecognizedTypeIsNotNamed(t *testing.T) {
	if name, ok := unrecognizedType.KnownName(); ok {
		t.Fatalf("KnownName(%#x) = %q, true; the test needs a type that is not in EventTypeNames",
			uint32(unrecognizedType), name)
	}
}

// The parser stores whatever event type the log holds, so an event can carry a
// type that EventTypeNames does not name.
func TestParseRawEvent2KeepsUnrecognizedType(t *testing.T) {
	digest := bytes.Repeat([]byte{0xAA}, 32)
	data := []byte("event data")

	var log bytes.Buffer
	binary.Write(&log, binary.LittleEndian, uint32(14))
	binary.Write(&log, binary.LittleEndian, uint32(unrecognizedType))
	binary.Write(&log, binary.LittleEndian, uint32(1))
	binary.Write(&log, binary.LittleEndian, uint16(tpm2.AlgSHA256))
	log.Write(digest)
	binary.Write(&log, binary.LittleEndian, uint32(len(data)))
	log.Write(data)

	specID := &specIDEvent{algs: []specAlgSize{{ID: uint16(tpm2.AlgSHA256), Size: 32}}}
	event, err := parseRawEvent2(bytes.NewBuffer(log.Bytes()), specID)
	if err != nil {
		t.Fatalf("parseRawEvent2() error = %v", err)
	}
	if event.typ != unrecognizedType {
		t.Errorf("parsed event type = %#x, want %#x", uint32(event.typ), uint32(unrecognizedType))
	}
	if event.index != 14 {
		t.Errorf("parsed event index = %d, want 14", event.index)
	}
	if !bytes.Equal(event.data, data) {
		t.Errorf("parsed event data = %q, want %q", event.data, data)
	}
}

func TestUntrustedTypeReturnsUnrecognizedType(t *testing.T) {
	event := Event{Type: unrecognizedType}
	if got := event.UntrustedType(); got != unrecognizedType {
		t.Errorf("UntrustedType() = %#x, want %#x", uint32(got), uint32(unrecognizedType))
	}
}

func TestConvertToPbEventsKeepsUnrecognizedType(t *testing.T) {
	data := []byte("event data")
	hasher := crypto.SHA256.New()
	hasher.Write(data)
	events := []Event{{Index: 14, Type: unrecognizedType, Data: data, Digest: hasher.Sum(nil)}}

	pbEvents := ConvertToPbEvents(crypto.SHA256, events)
	if len(pbEvents) != 1 {
		t.Fatalf("ConvertToPbEvents() returned %d events, want 1", len(pbEvents))
	}
	got := pbEvents[0]
	if got.GetUntrustedType() != uint32(unrecognizedType) {
		t.Errorf("UntrustedType = %#x, want %#x", got.GetUntrustedType(), uint32(unrecognizedType))
	}
	if got.GetPcrIndex() != 14 {
		t.Errorf("PcrIndex = %d, want 14", got.GetPcrIndex())
	}
	if !bytes.Equal(got.GetData(), data) {
		t.Errorf("Data = %q, want %q", got.GetData(), data)
	}
	if !got.GetDigestVerified() {
		t.Error("DigestVerified = false, want true")
	}
}

func buildSignatureListBuffer(t *testing.T, hdr efiSignatureListHeader, vendorHeader, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, hdr); err != nil {
		t.Fatalf("binary.Write(hdr) failed: %v", err)
	}
	buf.Write(vendorHeader)
	buf.Write(payload)
	return buf.Bytes()
}

func TestParseEfiSignatureListRejectsSignatureSizeTooSmall(t *testing.T) {
	tests := []struct {
		name string
		size uint32
	}{
		{
			name: "zero",
			size: 0,
		},
		{
			name: "one_byte",
			size: 1,
		},
		{
			name: "less_than_owner_guid",
			size: 15,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			hdr := efiSignatureListHeader{
				SignatureType:       certX509SigGUID,
				SignatureListSize:   100,
				SignatureHeaderSize: 0,
				SignatureSize:       tc.size,
			}
			data := buildSignatureListBuffer(t, hdr, nil, make([]byte, 100-efiSignatureListHeaderSize))

			_, _, err := parseEfiSignatureList(data)
			if err == nil {
				t.Fatalf("parseEfiSignatureList() succeeded for SignatureSize = %d, want error", tc.size)
			}
			const wantErr = "signature size too small"
			if !strings.Contains(err.Error(), wantErr) {
				t.Errorf("parseEfiSignatureList() error = %q, want substring %q", err.Error(), wantErr)
			}
		})
	}
}

func TestParseEfiSignatureListRejectsSignatureSizeExceedingDataSize(t *testing.T) {
	tests := []struct {
		name string
		size uint32
	}{
		{
			name: "exceeds_data_size",
			size: 100,
		},
		{
			name: "max_uint32",
			size: 0xFFFFFFFF,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			hdr := efiSignatureListHeader{
				SignatureType:       certX509SigGUID,
				SignatureListSize:   50,
				SignatureHeaderSize: 0,
				SignatureSize:       tc.size,
			}
			data := buildSignatureListBuffer(t, hdr, nil, make([]byte, 50-efiSignatureListHeaderSize))

			_, _, err := parseEfiSignatureList(data)
			if err == nil {
				t.Fatalf("parseEfiSignatureList() succeeded for SignatureSize = %d, want error", tc.size)
			}
			const wantErr = "signature size too large"
			if !strings.Contains(err.Error(), wantErr) {
				t.Errorf("parseEfiSignatureList() error = %q, want substring %q", err.Error(), wantErr)
			}
		})
	}
}

func TestParseEfiSignatureListRejectsSignatureListSizeSmallerThanHeader(t *testing.T) {
	hdr := efiSignatureListHeader{
		SignatureType:       certX509SigGUID,
		SignatureListSize:   27,
		SignatureHeaderSize: 0,
		SignatureSize:       16,
	}
	data := buildSignatureListBuffer(t, hdr, nil, make([]byte, efiSignatureListHeaderSize))

	_, _, err := parseEfiSignatureList(data)
	if err == nil {
		t.Fatal("parseEfiSignatureList() succeeded, want error for SignatureListSize < 28")
	}
	const wantErr = "signature list too small"
	if !strings.Contains(err.Error(), wantErr) {
		t.Errorf("parseEfiSignatureList() error = %q, want substring %q", err.Error(), wantErr)
	}
}

func TestParseEfiSignatureListRejectsSignatureListSizeExceedingRemainingBuffer(t *testing.T) {
	firstList := buildSignatureListBuffer(t, efiSignatureListHeader{
		SignatureType:     certX509SigGUID,
		SignatureListSize: efiSignatureListHeaderSize,
	}, nil, nil)

	secondListHdr := efiSignatureListHeader{
		SignatureType:     certX509SigGUID,
		SignatureListSize: 100,
		SignatureSize:     16,
	}
	secondList := buildSignatureListBuffer(t, secondListHdr, nil, make([]byte, 10))

	combined := append(firstList, secondList...)
	_, _, err := parseEfiSignatureList(combined)
	if err == nil {
		t.Fatal("parseEfiSignatureList() succeeded, want error for second list overrunning buffer")
	}
	const wantErr = "signature list payload"
	if !strings.Contains(err.Error(), wantErr) {
		t.Errorf("parseEfiSignatureList() error = %q, want substring %q", err.Error(), wantErr)
	}
}

func TestParseEfiSignatureListRejectsTruncatedTrailingHeader(t *testing.T) {
	firstList := buildSignatureListBuffer(t, efiSignatureListHeader{
		SignatureType:     certX509SigGUID,
		SignatureListSize: efiSignatureListHeaderSize,
	}, nil, nil)
	combined := append(firstList, make([]byte, 10)...)
	_, _, err := parseEfiSignatureList(combined)
	if err == nil {
		t.Fatal("parseEfiSignatureList() succeeded, want error for truncated trailing header")
	}
	const wantErr = "reading signature list header"
	if !strings.Contains(err.Error(), wantErr) {
		t.Errorf("parseEfiSignatureList() error = %q, want substring %q", err.Error(), wantErr)
	}
}

func TestParseEfiSignatureListRejectsUnalignedEntrySizes(t *testing.T) {
	hdr := efiSignatureListHeader{
		SignatureType:       certX509SigGUID,
		SignatureListSize:   60, // dataSize = 32
		SignatureHeaderSize: 0,
		SignatureSize:       20, // 32 % 20 != 0
	}
	data := buildSignatureListBuffer(t, hdr, nil, make([]byte, 60-efiSignatureListHeaderSize))

	_, _, err := parseEfiSignatureList(data)
	if err == nil {
		t.Fatal("parseEfiSignatureList() succeeded, want error for unaligned entry size")
	}
	const wantErr = "is not a multiple of signature size"
	if !strings.Contains(err.Error(), wantErr) {
		t.Errorf("parseEfiSignatureList() error = %q, want substring %q", err.Error(), wantErr)
	}
}

func TestParseEfiSignatureListAllowsEmptyListWithZeroSignatureSize(t *testing.T) {
	for _, sigType := range []efiGUID{certX509SigGUID, hashSHA256SigGUID} {
		hdr := efiSignatureListHeader{
			SignatureType:     sigType,
			SignatureListSize: efiSignatureListHeaderSize,
		}
		data := buildSignatureListBuffer(t, hdr, nil, nil)

		certs, hashes, err := parseEfiSignatureList(data)
		if err != nil {
			t.Fatalf("parseEfiSignatureList() failed: %v", err)
		}
		if len(certs) != 0 || len(hashes) != 0 {
			t.Errorf("got %d certs, %d hashes, want empty", len(certs), len(hashes))
		}
	}
}

func TestParseEfiSignatureListParsesSHA256Signatures(t *testing.T) {
	const entrySize = efiSHA256SignatureSize
	hdr := efiSignatureListHeader{
		SignatureType:     hashSHA256SigGUID,
		SignatureListSize: efiSignatureListHeaderSize + entrySize,
		SignatureSize:     entrySize,
	}
	owner := efiGUID{
		Data1: 0x01020304,
		Data2: 0x0506,
		Data3: 0x0708,
		Data4: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	hashData := make([]byte, 32)
	hashData[0] = 0xAA

	var entryBuf bytes.Buffer
	if err := binary.Write(&entryBuf, binary.LittleEndian, owner); err != nil {
		t.Fatalf("binary.Write(owner) failed: %v", err)
	}
	entryBuf.Write(hashData)

	data := buildSignatureListBuffer(t, hdr, nil, entryBuf.Bytes())
	certs, hashes, err := parseEfiSignatureList(data)
	if err != nil {
		t.Fatalf("parseEfiSignatureList() failed: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("len(certs) = %d, want 0", len(certs))
	}
	if diff := cmp.Diff([][]byte{hashData}, hashes); diff != "" {
		t.Errorf("hashes mismatch (-want +got):\n%s", diff)
	}
}

func TestParseEfiSignatureListParsesX509Certificate(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Cert",
		},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate failed: %v", err)
	}

	entrySize := uint32(efiSignatureOwnerSize + len(certDER))
	hdr := efiSignatureListHeader{
		SignatureType:     certX509SigGUID,
		SignatureListSize: efiSignatureListHeaderSize + entrySize,
		SignatureSize:     entrySize,
	}
	owner := efiGUID{
		Data1: 0x01020304,
		Data2: 0x0506,
		Data3: 0x0708,
		Data4: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
	}

	var entryBuf bytes.Buffer
	if err := binary.Write(&entryBuf, binary.LittleEndian, owner); err != nil {
		t.Fatalf("binary.Write(owner) failed: %v", err)
	}
	entryBuf.Write(certDER)

	data := buildSignatureListBuffer(t, hdr, nil, entryBuf.Bytes())
	certs, hashes, err := parseEfiSignatureList(data)
	if err != nil {
		t.Fatalf("parseEfiSignatureList() failed: %v", err)
	}
	if len(hashes) != 0 {
		t.Errorf("len(hashes) = %d, want 0", len(hashes))
	}
	if len(certs) != 1 {
		t.Fatalf("len(certs) = %d, want 1", len(certs))
	}
	if diff := cmp.Diff(certDER, certs[0].Raw); diff != "" {
		t.Errorf("cert raw bytes mismatch (-want +got):\n%s", diff)
	}
}

func TestParseEfiSignatureListSkipsVendorHeader(t *testing.T) {
	const (
		vendorHdrSize = 10
		entrySize     = efiSHA256SignatureSize
	)
	hdr := efiSignatureListHeader{
		SignatureType:       hashSHA256SigGUID,
		SignatureListSize:   efiSignatureListHeaderSize + vendorHdrSize + entrySize,
		SignatureHeaderSize: vendorHdrSize,
		SignatureSize:       entrySize,
	}
	owner := efiGUID{
		Data1: 0x01020304,
		Data2: 0x0506,
		Data3: 0x0708,
		Data4: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	hashData := make([]byte, 32)
	hashData[0] = 0xBB

	var entryBuf bytes.Buffer
	if err := binary.Write(&entryBuf, binary.LittleEndian, owner); err != nil {
		t.Fatalf("binary.Write(owner) failed: %v", err)
	}
	entryBuf.Write(hashData)

	data := buildSignatureListBuffer(t, hdr, make([]byte, vendorHdrSize), entryBuf.Bytes())
	certs, hashes, err := parseEfiSignatureList(data)
	if err != nil {
		t.Fatalf("parseEfiSignatureList() failed: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("len(certs) = %d, want 0", len(certs))
	}
	if diff := cmp.Diff([][]byte{hashData}, hashes); diff != "" {
		t.Errorf("hashes mismatch (-want +got):\n%s", diff)
	}
}

func TestParseEfiSignatureListEmpty(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
	}{
		{
			name: "nil",
			buf:  nil,
		},
		{
			name: "empty_slice",
			buf:  []byte{},
		},
		{
			name: "single_byte",
			buf:  []byte{0x00},
		},
		{
			name: "under_header_size",
			buf:  make([]byte, efiSignatureListHeaderSize-1),
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			certs, hashes, err := parseEfiSignatureList(tc.buf)
			if err != nil {
				t.Fatalf("parseEfiSignatureList() failed: %v", err)
			}
			if len(certs) != 0 || len(hashes) != 0 {
				t.Errorf("got %d certs, %d hashes, want empty", len(certs), len(hashes))
			}
		})
	}
}

func TestParseEfiSignatureListParsesMultipleEntries(t *testing.T) {
	const entrySize = efiSHA256SignatureSize
	hdr := efiSignatureListHeader{
		SignatureType:     hashSHA256SigGUID,
		SignatureListSize: efiSignatureListHeaderSize + (entrySize * 2),
		SignatureSize:     entrySize,
	}
	owner1 := efiGUID{
		Data1: 0x01020304,
		Data2: 0x0506,
		Data3: 0x0708,
		Data4: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	hash1 := make([]byte, 32)
	hash1[0] = 0x11
	owner2 := efiGUID{
		Data1: 0x090a0b0c,
		Data2: 0x0d0e,
		Data3: 0x0f10,
		Data4: [8]byte{8, 7, 6, 5, 4, 3, 2, 1},
	}
	hash2 := make([]byte, 32)
	hash2[0] = 0x22

	var entryBuf bytes.Buffer
	if err := binary.Write(&entryBuf, binary.LittleEndian, owner1); err != nil {
		t.Fatalf("binary.Write(owner1) failed: %v", err)
	}
	entryBuf.Write(hash1)
	if err := binary.Write(&entryBuf, binary.LittleEndian, owner2); err != nil {
		t.Fatalf("binary.Write(owner2) failed: %v", err)
	}
	entryBuf.Write(hash2)

	data := buildSignatureListBuffer(t, hdr, nil, entryBuf.Bytes())
	certs, hashes, err := parseEfiSignatureList(data)
	if err != nil {
		t.Fatalf("parseEfiSignatureList() failed: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("len(certs) = %d, want 0", len(certs))
	}
	if diff := cmp.Diff([][]byte{hash1, hash2}, hashes); diff != "" {
		t.Errorf("hashes mismatch (-want +got):\n%s", diff)
	}
}

func TestParseEfiSignatureListAggregatesMultipleLists(t *testing.T) {
	// First list: 1 SHA256 hash.
	const entrySize = efiSHA256SignatureSize
	hdr1 := efiSignatureListHeader{
		SignatureType:     hashSHA256SigGUID,
		SignatureListSize: efiSignatureListHeaderSize + entrySize,
		SignatureSize:     entrySize,
	}
	owner1 := efiGUID{
		Data1: 0x01020304,
		Data2: 0x0506,
		Data3: 0x0708,
		Data4: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	hash1 := make([]byte, 32)
	hash1[0] = 0xAA

	var entryBuf1 bytes.Buffer
	if err := binary.Write(&entryBuf1, binary.LittleEndian, owner1); err != nil {
		t.Fatalf("binary.Write(owner1) failed: %v", err)
	}
	entryBuf1.Write(hash1)
	list1 := buildSignatureListBuffer(t, hdr1, nil, entryBuf1.Bytes())

	// Second list: 1 X.509 cert.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Multi List Cert",
		},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate failed: %v", err)
	}

	certEntrySize := uint32(efiSignatureOwnerSize + len(certDER))
	hdr2 := efiSignatureListHeader{
		SignatureType:     certX509SigGUID,
		SignatureListSize: efiSignatureListHeaderSize + certEntrySize,
		SignatureSize:     certEntrySize,
	}
	owner2 := efiGUID{
		Data1: 0x090a0b0c,
		Data2: 0x0d0e,
		Data3: 0x0f10,
		Data4: [8]byte{8, 7, 6, 5, 4, 3, 2, 1},
	}
	var entryBuf2 bytes.Buffer
	if err := binary.Write(&entryBuf2, binary.LittleEndian, owner2); err != nil {
		t.Fatalf("binary.Write(owner2) failed: %v", err)
	}
	entryBuf2.Write(certDER)
	list2 := buildSignatureListBuffer(t, hdr2, nil, entryBuf2.Bytes())

	combined := append(list1, list2...)
	certs, hashes, err := parseEfiSignatureList(combined)
	if err != nil {
		t.Fatalf("parseEfiSignatureList() failed: %v", err)
	}
	if diff := cmp.Diff([][]byte{hash1}, hashes); diff != "" {
		t.Errorf("hashes mismatch (-want +got):\n%s", diff)
	}
	if len(certs) != 1 {
		t.Fatalf("len(certs) = %d, want 1", len(certs))
	}
	if diff := cmp.Diff(certDER, certs[0].Raw); diff != "" {
		t.Errorf("cert raw bytes mismatch (-want +got):\n%s", diff)
	}
}

func TestParseEfiSignatureListRejectsInvalidSHA256SignatureSize(t *testing.T) {
	hdr := efiSignatureListHeader{
		SignatureType:     hashSHA256SigGUID,
		SignatureListSize: efiSignatureListHeaderSize + 20,
		SignatureSize:     20,
	}
	data := buildSignatureListBuffer(t, hdr, nil, make([]byte, 20))
	_, _, err := parseEfiSignatureList(data)
	if err == nil {
		t.Fatal("parseEfiSignatureList() succeeded for invalid SHA256 SignatureSize, want error")
	}
	const wantErr = "does not match SHA-256 entry size"
	if !strings.Contains(err.Error(), wantErr) {
		t.Errorf("parseEfiSignatureList() error = %q, want substring %q", err.Error(), wantErr)
	}
}
