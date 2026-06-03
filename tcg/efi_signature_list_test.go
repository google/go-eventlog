package tcg

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func pocGuidBytes(g efiGUID) []byte {
	b := new(bytes.Buffer)
	binary.Write(b, binary.LittleEndian, g)
	return b.Bytes()
}

func pocBuildSigList(sigType efiGUID, listSize, hdrSize, sigSize uint32, body []byte) []byte {
	b := new(bytes.Buffer)
	b.Write(pocGuidBytes(sigType))
	binary.Write(b, binary.LittleEndian, listSize)
	binary.Write(b, binary.LittleEndian, hdrSize)
	binary.Write(b, binary.LittleEndian, sigSize)
	b.Write(body)
	return b.Bytes()
}

// Regression test for the EFI signature-list hash injection (GHSA-9r4w-jg96-92mv class):
// the SignatureHeaderSize vendor bytes between the fixed header and the signature entries
// must be skipped, not parsed as EFI_SIGNATURE_DATA. Before the fix, a list with zero real
// entries but attacker-chosen vendor bytes made SignatureData() return those bytes as a
// trusted SHA256 db/dbx hash. After the fix, the malformed list must be rejected (or yield
// no entries) and the injected bytes must never appear as a trusted hash.
func TestEfiSignatureList_NoHashInjectionFromVendorHeader(t *testing.T) {
	owner := bytes.Repeat([]byte{0xAA}, 16)
	injected := bytes.Repeat([]byte{0x41}, 32) // attacker-chosen "trusted" SHA256 hash
	vendor := append(append([]byte{}, owner...), injected...)
	listSize := uint32(28 + len(vendor)) // header + vendor bytes; ZERO real signature entries
	data := pocBuildSigList(hashSHA256SigGUID, listSize, uint32(len(vendor)), 48, vendor)

	v := &UEFIVariableData{VariableData: data}
	_, hashes, err := v.SignatureData()
	t.Logf("err=%v hashes=%d", err, len(hashes))
	for _, h := range hashes {
		if bytes.Equal(h, injected) {
			t.Fatalf("hash injection: vendor-header bytes were accepted as a trusted db/dbx hash (%x)", h)
		}
	}
}
