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
	"encoding/binary"
	"strings"
	"testing"

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

// signatureListBuffer encodes hdr followed by payloadLen zero bytes.
func signatureListBuffer(t *testing.T, hdr efiSignatureListHeader, payloadLen int) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, hdr); err != nil {
		t.Fatalf("binary.Write failed: %v", err)
	}
	buf.Write(make([]byte, payloadLen))
	return buf.Bytes()
}

func TestParseEfiSignatureListRejectsSignatureSizeTooSmall(t *testing.T) {
	b := signatureListBuffer(t, efiSignatureListHeader{
		SignatureType:       hashSHA256SigGUID,
		SignatureListSize:   44,
		SignatureHeaderSize: 0,
		SignatureSize:       0,
	}, 16)
	if _, _, err := parseEfiSignatureList(b); err == nil || !strings.Contains(err.Error(), "signature size too small") {
		t.Fatalf("parseEfiSignatureList error = %v, want error containing %q", err, "signature size too small")
	}
}

func TestParseEfiSignatureListRejectsSignatureListSizeSmallerThanHeader(t *testing.T) {
	b := signatureListBuffer(t, efiSignatureListHeader{
		SignatureType:       hashSHA256SigGUID,
		SignatureListSize:   27,
		SignatureHeaderSize: 0,
		SignatureSize:       48,
	}, 48)
	if _, _, err := parseEfiSignatureList(b); err == nil || !strings.Contains(err.Error(), "signature list too small") {
		t.Fatalf("parseEfiSignatureList error = %v, want error containing %q", err, "signature list too small")
	}
}

func TestParseEfiSignatureListRejectsSignatureSizeExceedingListSize(t *testing.T) {
	b := signatureListBuffer(t, efiSignatureListHeader{
		SignatureType:       hashSHA256SigGUID,
		SignatureListSize:   44,
		SignatureHeaderSize: 0,
		SignatureSize:       48,
	}, 48)
	if _, _, err := parseEfiSignatureList(b); err == nil || !strings.Contains(err.Error(), "exceeds signature list size") {
		t.Fatalf("parseEfiSignatureList error = %v, want error containing %q", err, "exceeds signature list size")
	}
}

func TestParseEfiSignatureListRejectsPayloadExceedingBuffer(t *testing.T) {
	b := signatureListBuffer(t, efiSignatureListHeader{
		SignatureType:       hashSHA256SigGUID,
		SignatureListSize:   100,
		SignatureHeaderSize: 0,
		SignatureSize:       48,
	}, 10)
	if _, _, err := parseEfiSignatureList(b); err == nil || !strings.Contains(err.Error(), "exceeds remaining buffer") {
		t.Fatalf("parseEfiSignatureList error = %v, want error containing %q", err, "exceeds remaining buffer")
	}
}
