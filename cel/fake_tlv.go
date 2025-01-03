package cel

import (
	"crypto"
	"fmt"
)

const (
	// FakeEventType indicates the CELR event is a Fake content type.
	FakeEventType uint8 = 222
	// FakeEventMR is the PCR which should be used for FakeEventType events.
	FakeEventMR = 23
)

// FakeType represent a Fake content type in a CEL record content.
type FakeType uint8

// Type for Fake nested events
const (
	FakeEvent1 FakeType = iota
	FakeEvent2
)

// FakeTlv is a specific TLV created for testing.
type FakeTlv struct {
	EventType    FakeType
	EventContent []byte
}

// TLV returns the TLV representation of the fake TLV.
func (f FakeTlv) TLV() (TLV, error) {
	data, err := TLV{uint8(f.EventType), f.EventContent}.MarshalBinary()
	if err != nil {
		return TLV{}, err
	}

	return TLV{
		Type:  FakeEventType,
		Value: data,
	}, nil
}

// GenerateDigest generates the digest for the given fake TLV. The whole TLV struct will
// be marshaled to bytes and feed into the hash algo.
func (f FakeTlv) GenerateDigest(hashAlgo crypto.Hash) ([]byte, error) {
	contentTLV, err := f.TLV()
	if err != nil {
		return nil, err
	}

	b, err := contentTLV.MarshalBinary()
	if err != nil {
		return nil, err
	}

	hash := hashAlgo.New()
	if _, err = hash.Write(b); err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

// ParseToFakeTlv constructs a FakeTlv from a TLV. It will check for the correct fake event
// type, and unmarshal the nested event.
func (t TLV) ParseToFakeTlv() (FakeTlv, error) {
	if !t.IsFakeTLV() {
		return FakeTlv{}, fmt.Errorf("TLV type %v is not a Fake event", t.Type)
	}
	nestedEvent := TLV{}
	err := nestedEvent.UnmarshalBinary(t.Value)
	if err != nil {
		return FakeTlv{}, err
	}
	return FakeTlv{FakeType(nestedEvent.Type), nestedEvent.Value}, nil
}

// IsFakeTLV check whether a TLV is a Fake TLV by its Type value.
func (t TLV) IsFakeTLV() bool {
	return t.Type == FakeEventType
}
