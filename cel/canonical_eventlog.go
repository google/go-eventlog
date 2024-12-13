// Package cel contains some basic operations of Canonical Eventlog.
// Based on Canonical EventLog Spec (Draft) Version: TCG_IWG_CEL_v1_r0p37.
package cel

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/google/go-eventlog/register"
	"github.com/google/go-tpm/legacy/tpm2"
)

// TopLevelEventType represents the CEL spec's known CELR data types for TPMS_CEL_EVENT.
type TopLevelEventType uint8

// MRType represents the type of measurement register used in the CEL for field
// CEL_PCR_NVindex TLV.
type MRType TopLevelEventType

const (
	// CEL spec 5.1
	recnumTypeValue TopLevelEventType = 0

	// PCRType indicates a PCR event index
	PCRType MRType = 1
	// NV Indexes are unsupported.
	_ MRType = 2
	// CCMRType indicates a RTMR event index
	CCMRType MRType = 108

	digestsTypeValue TopLevelEventType = 3

	tlvTypeFieldLength   int = 1
	tlvLengthFieldLength int = 4

	recnumValueLength   uint32 = 8 // support up to 2^64 records
	regIndexValueLength uint32 = 1 // support up to 256 registers
)

// MRExtender extends an implementation-specific measurement register at the
// specified bank and index with the supplied digest.
type MRExtender func(crypto.Hash, int, []byte) error

// TLV definition according to CEL spec TCG_IWG_CEL_v1_r0p37, page 16.
// Length is implicitly defined by len(Value), using uint32 big-endian
// when encoding.
type TLV struct {
	Type  uint8
	Value []byte
}

// MarshalBinary marshals a TLV to a byte slice.
func (t TLV) MarshalBinary() (data []byte, err error) {
	buf := make([]byte, len(t.Value)+tlvTypeFieldLength+tlvLengthFieldLength)

	buf[0] = t.Type
	binary.BigEndian.PutUint32(buf[tlvTypeFieldLength:], uint32(len(t.Value)))
	copy(buf[tlvTypeFieldLength+tlvLengthFieldLength:], t.Value)

	return buf, nil
}

// UnmarshalBinary unmarshal a byte slice to a TLV.
func (t *TLV) UnmarshalBinary(data []byte) error {
	valueLength := binary.BigEndian.Uint32(data[tlvTypeFieldLength : tlvTypeFieldLength+tlvLengthFieldLength])

	if valueLength != uint32(len(data[tlvTypeFieldLength+tlvLengthFieldLength:])) {
		return fmt.Errorf("TLV Length doesn't match the size of its Value")
	}
	t.Type = data[0]
	t.Value = data[tlvTypeFieldLength+tlvLengthFieldLength:]

	return nil
}

// unmarshalFirstTLV reads and parse the first TLV from the bytes buffer. The function will
// return io.EOF if the buf ends unexpectedly or cannot fill the TLV.
func unmarshalFirstTLV(buf *bytes.Buffer) (tlv TLV, err error) {
	typeByte, err := buf.ReadByte()
	if err != nil {
		return tlv, err
	}
	var data []byte
	data = append(data, typeByte)

	// get the length
	lengthBytes := make([]byte, tlvLengthFieldLength)
	bytesRead, err := buf.Read(lengthBytes)
	if err != nil {
		return TLV{}, err
	}
	if bytesRead != tlvLengthFieldLength {
		return TLV{}, io.EOF
	}
	valueLength := binary.BigEndian.Uint32(lengthBytes)
	data = append(data, lengthBytes...)

	valueBytes := make([]byte, valueLength)
	bytesRead, err = buf.Read(valueBytes)
	if err != nil {
		return TLV{}, err
	}
	if uint32(bytesRead) != valueLength {
		return TLV{}, io.EOF
	}
	data = append(data, valueBytes...)

	if err = (&tlv).UnmarshalBinary(data); err != nil {
		return TLV{}, err
	}
	return tlv, nil
}

// Record represents a Canonical Eventlog Record.
type Record struct {
	RecNum uint64
	// Generic Measurement Register index number, register type
	// is determined by IndexType
	Index     uint8
	IndexType uint8
	Digests   map[crypto.Hash][]byte
	Content   TLV
}

// Content is a interface for the content in CELR.
type Content interface {
	GenerateDigest(crypto.Hash) ([]byte, error)
	GetTLV() (TLV, error)
}

// CEL represents a Canonical Event Log, which contains a list of Records.
type CEL interface {
	// Records returns all the records in the CEL.
	Records() []Record
	// AppendEvent appends a new record to the CEL.
	AppendEvent(Content, []crypto.Hash, int, MRExtender) error
	// EncodeCEL returns the TLV encoding of the CEL.
	EncodeCEL(*bytes.Buffer) error
	// Replay verifies the contents of the event log with the given MR bank.
	Replay(register.MRBank) error
	// MRType returns the measurement register type used in the CEL.
	MRType() MRType
}

// eventLog represents a Canonical Event Log, which contains a list of Records.
type eventLog struct {
	Recs []Record
	Type MRType
}

// NewPCR returns a CEL with events measured in TPM PCRs.
func NewPCR() CEL {
	return &eventLog{Type: PCRType}
}

// NewConfComputeMR returns a CEL with events measured in confidential
// computing measurement registers.
func NewConfComputeMR() CEL {
	return &eventLog{Type: CCMRType}
}

// generateDigestMap computes hashes with the given hash algos and the given event
func generateDigestMap(hashAlgos []crypto.Hash, event Content) (map[crypto.Hash][]byte, error) {
	digestsMap := make(map[crypto.Hash][]byte)
	for _, hashAlgo := range hashAlgos {
		digest, err := event.GenerateDigest(hashAlgo)
		if err != nil {
			return digestsMap, err
		}
		digestsMap[hashAlgo] = digest
	}
	return digestsMap, nil
}

// AppendEvent appends a new MR record to the CEL.
func (c *eventLog) AppendEvent(event Content, bankAlgos []crypto.Hash, mrIndex int, extender MRExtender) error {
	if len(bankAlgos) == 0 || mrIndex < 0 {
		return fmt.Errorf("failed to append event with banks %v, measurement register index %v", bankAlgos, mrIndex)
	}
	if err := supportedMRType(c.Type); err != nil {
		return err
	}

	digestMap, err := generateDigestMap(bankAlgos, event)
	if err != nil {
		return err
	}

	for bank, dgst := range digestMap {
		if err := extender(bank, mrIndex, dgst); err != nil {
			return fmt.Errorf("failed to extend event to MR%d on bank %v: %v", mrIndex, bank, err)
		}
	}

	eventTlv, err := event.GetTLV()
	if err != nil {
		return err
	}

	celrPCR := Record{
		RecNum:    uint64(len(c.Recs)),
		Index:     uint8(mrIndex),
		Digests:   digestMap,
		Content:   eventTlv,
		IndexType: uint8(c.Type),
	}

	c.Recs = append(c.Recs, celrPCR)
	return nil
}

func supportedMRType(mrType MRType) error {
	if mrType != PCRType && mrType != CCMRType {
		return fmt.Errorf("received unknown type of measurement register: %d", mrType)
	}
	return nil
}

func createRecNumField(recNum uint64) TLV {
	value := make([]byte, recnumValueLength)
	binary.BigEndian.PutUint64(value, recNum)
	return TLV{uint8(recnumTypeValue), value}
}

// UnmarshalRecNum takes in a TLV with its type equals to the recnum type value (0), and
// return its record number.
func unmarshalRecNum(tlv TLV) (uint64, error) {
	if tlv.Type != uint8(recnumTypeValue) {
		return 0, fmt.Errorf("type of the TLV [%d] indicates it is not a recnum field [%d]",
			tlv.Type, recnumTypeValue)
	}
	if uint32(len(tlv.Value)) != recnumValueLength {
		return 0, fmt.Errorf(
			"length of the value of the TLV [%d] doesn't match the defined length [%d] of value for recnum",
			len(tlv.Value), recnumValueLength)
	}
	return binary.BigEndian.Uint64(tlv.Value), nil
}

func createIndexField(indexType uint8, indexNum uint8) TLV {
	return TLV{indexType, []byte{indexNum}}
}

// unmarshalIndex takes in a TLV with its type equals to the PCR or CCMR type value, and
// return its index number.
func unmarshalIndex(tlv TLV) (indexType uint8, pcrNum uint8, err error) {
	if tlv.Type != uint8(PCRType) && tlv.Type != uint8(CCMRType) {
		return 0, 0, fmt.Errorf("type of the TLV [%d] indicates it is not a PCR [%d] or a CCMR [%d] field ",
			tlv.Type, uint8(PCRType), uint8(CCMRType))
	}
	if uint32(len(tlv.Value)) != regIndexValueLength {
		return 0, 0, fmt.Errorf(
			"length of the value of the TLV [%d] doesn't match the defined length [%d] of value for a register index field",
			len(tlv.Value), regIndexValueLength)
	}

	return tlv.Type, tlv.Value[0], nil
}

func createDigestField(digestMap map[crypto.Hash][]byte) (TLV, error) {
	var buf bytes.Buffer
	for hashAlgo, hash := range digestMap {
		if len(hash) != hashAlgo.Size() {
			return TLV{}, fmt.Errorf("digest length [%d] doesn't match the expected length [%d] for the hash algorithm",
				len(hash), hashAlgo.Size())
		}
		tpmHashAlg, err := tpm2.HashToAlgorithm(hashAlgo)
		if err != nil {
			return TLV{}, err
		}
		singleDigestTLV := TLV{uint8(tpmHashAlg), hash}
		d, err := singleDigestTLV.MarshalBinary()
		if err != nil {
			return TLV{}, err
		}
		_, err = buf.Write(d)
		if err != nil {
			return TLV{}, err
		}
	}
	return TLV{uint8(digestsTypeValue), buf.Bytes()}, nil
}

// UnmarshalDigests takes in a TLV with its type equals to the digests type value (3), and
// return its digests content in a map, the key is its TPM hash algorithm.
func unmarshalDigests(tlv TLV) (digestsMap map[crypto.Hash][]byte, err error) {
	if tlv.Type != uint8(digestsTypeValue) {
		return nil, fmt.Errorf("type of the TLV indicates it doesn't contain digests")
	}

	buf := bytes.NewBuffer(tlv.Value)
	digestsMap = make(map[crypto.Hash][]byte)

	for buf.Len() > 0 {
		digestTLV, err := unmarshalFirstTLV(buf)
		if err == io.EOF {
			return nil, fmt.Errorf("buffer ends unexpectedly")
		} else if err != nil {
			return nil, err
		}
		hashAlg, err := tpm2.Algorithm(digestTLV.Type).Hash()
		if err != nil {
			return nil, err
		}
		digestsMap[hashAlg] = digestTLV.Value
	}
	return digestsMap, nil
}

// EncodeCELR encodes the CELR to bytes according to the CEL spec and write them
// to the bytes byffer.
func (r *Record) EncodeCELR(buf *bytes.Buffer) error {
	recnumField, err := createRecNumField(r.RecNum).MarshalBinary()
	if err != nil {
		return err
	}

	indexField, err := createIndexField(r.IndexType, r.Index).MarshalBinary()
	if err != nil {
		return err
	}
	digests, err := createDigestField(r.Digests)
	if err != nil {
		return err
	}
	digestsField, err := digests.MarshalBinary()
	if err != nil {
		return err
	}
	eventField, err := r.Content.MarshalBinary()
	if err != nil {
		return err
	}
	_, err = buf.Write(recnumField)
	if err != nil {
		return err
	}
	_, err = buf.Write(indexField)
	if err != nil {
		return err
	}
	_, err = buf.Write(digestsField)
	if err != nil {
		return err
	}
	_, err = buf.Write(eventField)
	if err != nil {
		return err
	}
	return nil
}

// EncodeCEL encodes the CEL to bytes according to the CEL spec and write them
// to the bytes buffer.
func (c *eventLog) EncodeCEL(buf *bytes.Buffer) error {
	for _, record := range c.Recs {
		if err := record.EncodeCELR(buf); err != nil {
			return err
		}
	}
	return nil
}

// DecodeToCEL will read the buf for CEL, will return err if the buffer
// is not complete.
func DecodeToCEL(buf *bytes.Buffer) (CEL, error) {
	var cel eventLog
	for buf.Len() > 0 {
		celr, err := decodeToCELR(buf)
		if err == io.EOF {
			return &eventLog{}, fmt.Errorf("buffer ends unexpectedly")
		}
		if err != nil {
			return &eventLog{}, err
		}
		cel.Recs = append(cel.Recs, celr)
	}
	if len(cel.Recs) > 1 {
		zeroMRType := MRType(cel.Recs[0].IndexType)
		for _, rec := range cel.Recs {
			mrType := MRType(rec.IndexType)
			if err := supportedMRType(mrType); err != nil {
				return &eventLog{}, fmt.Errorf("bad record %v: %v", rec.RecNum, err)
			}
			if mrType != zeroMRType {
				return &eventLog{}, fmt.Errorf("bad record %v: found differing MR types in the CEL: got %v, expected %v", rec.RecNum, mrType, zeroMRType)
			}
		}
		cel.Type = zeroMRType
	}
	return &cel, nil
}

// decodeToCELR will read the buf for the next CELR, will return err if
// failed to unmarshal a correct CELR TLV from the buffer.
func decodeToCELR(buf *bytes.Buffer) (r Record, err error) {
	recnum, err := unmarshalFirstTLV(buf)
	if err != nil {
		return Record{}, err
	}
	r.RecNum, err = unmarshalRecNum(recnum)
	if err != nil {
		return Record{}, err
	}

	regIndex, err := unmarshalFirstTLV(buf)
	if err != nil {
		return Record{}, err
	}
	r.IndexType, r.Index, err = unmarshalIndex(regIndex)
	if err != nil {
		return Record{}, err
	}

	digests, err := unmarshalFirstTLV(buf)
	if err != nil {
		return Record{}, err
	}
	r.Digests, err = unmarshalDigests(digests)
	if err != nil {
		return Record{}, err
	}

	r.Content, err = unmarshalFirstTLV(buf)
	if err != nil {
		return Record{}, err
	}
	return r, nil
}

// Replay takes the digests from a Canonical Event Log and carries out the
// extend sequence for each register (PCR, RTMR) in the log. It then compares
// the final digests against a bank of register values to see if they match.
// make sure CEL has only one indexType event
func (c *eventLog) Replay(regs register.MRBank) error {
	cryptoHash, err := regs.CryptoHash()
	if err != nil {
		return err
	}
	replayed := make(map[uint8][]byte)
	for _, record := range c.Recs {
		if _, ok := replayed[record.Index]; !ok {
			replayed[record.Index] = make([]byte, cryptoHash.Size())
		}
		hasher := cryptoHash.New()
		digestsMap := record.Digests
		digest, ok := digestsMap[cryptoHash]
		if !ok {
			return fmt.Errorf("the CEL record did not contain a %v digest", cryptoHash)
		}
		hasher.Write(replayed[record.Index])
		hasher.Write(digest)
		replayed[record.Index] = hasher.Sum(nil)
	}

	// to a map for easy matching
	registers := make(map[int][]byte)
	for _, r := range regs.MRs() {
		registers[r.Idx()] = r.Dgst()
	}

	var failedReplayRegs []uint8
	for replayReg, replayDigest := range replayed {
		bankDigest, ok := registers[int(replayReg)]
		if !ok {
			return fmt.Errorf("the CEL contains record(s) for register %d without a matching register in the given bank to verify", replayReg)
		}
		if !bytes.Equal(bankDigest, replayDigest) {
			failedReplayRegs = append(failedReplayRegs, replayReg)
		}
	}

	if len(failedReplayRegs) == 0 {
		return nil
	}

	return fmt.Errorf("CEL replay failed for these registers in bank %v: %v", cryptoHash, failedReplayRegs)
}

func (c *eventLog) Records() []Record {
	return c.Recs
}

func (c *eventLog) MRType() MRType {
	return c.Type
}

// VerifyDigests checks the digest generated by the given record's content to make sure they are equal to
// the digests in the digestMap.
func VerifyDigests(c Content, digestMap map[crypto.Hash][]byte) error {
	for hash, digest := range digestMap {
		generatedDigest, err := c.GenerateDigest(hash)
		if err != nil {
			return err
		}
		if !bytes.Equal(generatedDigest, digest) {
			return fmt.Errorf("CEL record content digest verification failed for %s", hash)
		}
	}
	return nil
}
