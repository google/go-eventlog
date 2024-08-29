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

// Package tcg exposes utilities and constants that correspond to TCG specs
// including TPM 2.0 and the PC Client Platform Firmware Profile.
package tcg

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	pb "github.com/google/go-eventlog/proto/state"
	"github.com/google/go-eventlog/register"
	"github.com/google/go-tpm/legacy/tpm2"
)

type digestVerified int

// Verified statuses.
const (
	UNKNOWN digestVerified = iota
	VERIFIED
	UNVERIFIED
)

// Event is a single event from a TCG event log. This reports descrete items such
// as BIOS measurements or EFI states.
//
// There are many pitfalls for using event log events correctly to determine the
// state of a machine[1]. In general it's much safer to only rely on the raw PCR
// values and use the event log for debugging.
//
// [1] https://github.com/google/go-attestation/blob/master/docs/event-log-disclosure.md
type Event struct {
	// sequence gives the order of the event in the event log.
	sequence int
	// Index of the PCR that this event was replayed against.
	Index int
	// Untrusted type of the event. This value is not verified by event log replays
	// and can be tampered with. It should NOT be used without additional context,
	// and unrecognized event types should result in errors.
	Type EventType

	// Data of the event. For certain kinds of events, this must match the event
	// digest to be valid.
	Data []byte
	// Digest is the verified digest of the event data. While an event can have
	// multiple for different hash values, this is the one that was matched to the
	// PCR value.
	Digest []byte

	hash crypto.Hash

	digestVerified digestVerified

	// TODO(ericchiang): Provide examples or links for which event types must
	// match their data to their digest.
}

// Num is the event number.
func (e Event) Num() uint32 {
	return uint32(e.sequence)
}

// MRIndex is the event measurement register index.
func (e Event) MRIndex() uint32 {
	return uint32(e.Index)
}

// UntrustedType gives the unmeasured event type.
func (e Event) UntrustedType() EventType {
	tcgEvent := EventType(e.Type)
	if _, ok := tcgEvent.KnownName(); !ok {
		panic("library cannot convert between tpmeventlog EventType and tcg EventType for event " + e.UntrustedType().String())
	}
	return tcgEvent
}

// RawData gives the event data.
func (e Event) RawData() []byte {
	return e.Data
}

// ReplayedDigest gives the event's digest
func (e Event) ReplayedDigest() []byte {
	return e.Digest
}

// DigestVerified returns whether the event's data matches its digest.
// This must not be used before calling EventLog.Verify.
func (e Event) DigestVerified() bool {
	if e.digestVerified != UNKNOWN {
		return e.digestVerified == VERIFIED
	}
	hasher := e.hash.New()
	hasher.Write(e.Data)
	digest := hasher.Sum(nil)
	if bytes.Equal(digest, e.Digest) {
		e.digestVerified = VERIFIED
	} else {
		e.digestVerified = UNVERIFIED
	}
	return e.digestVerified == VERIFIED
}

// ConvertToPbEvents returns the state.proto Events from the GenericEvents.
func ConvertToPbEvents(hash crypto.Hash, events []Event) []*pb.Event {
	pbEvents := make([]*pb.Event, len(events))
	for i, event := range events {
		hasher := hash.New()
		hasher.Write(event.RawData())
		digest := hasher.Sum(nil)
		pbEvents[i] = &pb.Event{
			PcrIndex:       event.MRIndex(),
			UntrustedType:  uint32(event.UntrustedType()),
			Data:           event.RawData(),
			Digest:         event.ReplayedDigest(),
			DigestVerified: bytes.Equal(digest, event.ReplayedDigest()),
		}
	}
	return pbEvents
}

// ReplayError describes the parsed events that failed to verify against
// a particular PCR.
type ReplayError struct {
	Events []Event
	// InvalidMRs reports the set of MRs where the event log replay failed.
	InvalidMRs []int
}

// Error returns a human-friendly description of replay failures.
func (e ReplayError) Error() string {
	return fmt.Sprintf("event log failed to verify: the following registers failed to replay: %v", e.InvalidMRs)
}

func (e ReplayError) affected(mr int) bool {
	for _, m := range e.InvalidMRs {
		if m == mr {
			return true
		}
	}
	return false
}

// ParseOpts gives options for parsing the event log.
type ParseOpts struct {
	AllowPadding bool
}

// ParseAndReplay takes a raw TCG measurement log, parses it, and replays it
// against the given measurement registers.
func ParseAndReplay(rawEventLog []byte, mrs []register.MR, parseOpts ParseOpts) ([]Event, error) {
	// Similar to parseCanonicalEventLog, just return an empty array of events for an empty log
	if len(rawEventLog) == 0 {
		return nil, nil
	}
	eventLog, err := ParseEventLog(rawEventLog, parseOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to parse event log: %v", err)
	}
	events, err := eventLog.Verify(mrs)
	if err != nil {
		return nil, fmt.Errorf("failed to replay event log: %v", err)
	}
	return events, nil
}

// ParseEventLog parses an unverified measurement log.
func ParseEventLog(measurementLog []byte, parseOpts ParseOpts) (*EventLog, error) {
	var specID *specIDEvent
	r := bytes.NewBuffer(measurementLog)
	parseFn := parseRawEvent
	var el EventLog
	e, err := parseFn(r, specID)
	if err != nil {
		return nil, fmt.Errorf("parse first event: %v", err)
	}
	if e.typ == eventTypeNoAction && len(e.data) >= binary.Size(specIDEventHeader{}) {
		specID, err = parseSpecIDEvent(e.data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse spec ID event: %v", err)
		}
		for _, alg := range specID.algs {
			switch tpm2.Algorithm(alg.ID) {
			case tpm2.AlgSHA1:
				el.Algs = append(el.Algs, register.HashSHA1)
			case tpm2.AlgSHA256:
				el.Algs = append(el.Algs, register.HashSHA256)
			case tpm2.AlgSHA384:
				el.Algs = append(el.Algs, register.HashSHA384)
			}
		}
		if len(el.Algs) == 0 {
			return nil, fmt.Errorf("measurement log didn't use sha1, sha256, or sha384 digests")
		}
		// Switch to parsing crypto agile events. Don't include this in the
		// replayed events since it intentionally doesn't extend the PCRs.
		//
		// Note that this doesn't actually guarantee that events have SHA256
		// digests.
		parseFn = parseRawEvent2
		el.specIDEvent = specID
	} else {
		el.Algs = []register.HashAlg{register.HashSHA1}
		el.rawEvents = append(el.rawEvents, e)
	}
	sequence := 1
	for r.Len() != 0 {
		e, err := parseFn(r, specID)
		if err == errEventLogPadding && parseOpts.AllowPadding {
			break
		}
		if err != nil {
			return nil, err
		}
		e.sequence = sequence
		sequence++
		el.rawEvents = append(el.rawEvents, e)
	}
	return &el, nil
}

// EventLog is a parsed measurement log. This contains unverified data representing
// boot events that must be replayed against PCR values to determine authenticity.
type EventLog struct {
	// Algs holds the set of algorithms that the event log uses.
	Algs []register.HashAlg

	rawEvents   []rawEvent
	specIDEvent *specIDEvent
}

func (e *EventLog) clone() *EventLog {
	out := EventLog{
		Algs:      make([]register.HashAlg, len(e.Algs)),
		rawEvents: make([]rawEvent, len(e.rawEvents)),
	}
	copy(out.Algs, e.Algs)
	copy(out.rawEvents, e.rawEvents)
	if e.specIDEvent != nil {
		dupe := *e.specIDEvent
		out.specIDEvent = &dupe
	}

	return &out
}

// Events returns events that have not been replayed against the PCR values and
// are therefore unverified. The returned events contain the digest that matches
// the provided hash algorithm, or are empty if that event didn't contain a
// digest for that hash.
//
// This method is insecure and should only be used for debugging.
func (e *EventLog) Events(hash register.HashAlg) []Event {
	var events []Event
	for _, re := range e.rawEvents {
		ev := Event{
			Index: re.index,
			Type:  re.typ,
			Data:  re.data,
		}

		for _, digest := range re.digests {
			if hash.CryptoHash() != digest.hash {
				continue
			}
			ev.Digest = digest.data
			break
		}
		events = append(events, ev)
	}
	return events
}

// Verify replays the event log against a TPM's PCR values, returning the
// events which could be matched to a provided PCR value.
//
// PCRs provide no security guarantees unless they're attested to have been
// generated by a TPM. Verify does not perform these checks.
//
// An error is returned if the replayed digest for events with a given PCR
// index do not match any provided value for that PCR index.
func (e *EventLog) Verify(mrs []register.MR) ([]Event, error) {
	events, err := e.verify(mrs)
	// If there were any issues replaying the PCRs, try each of the workarounds
	// in turn.
	// TODO(jsonp): Allow workarounds to be combined.
	if rErr, isReplayErr := err.(ReplayError); isReplayErr {
		for _, wkrd := range EventlogWorkarounds {
			if !rErr.affected(wkrd.affectedPCR) {
				continue
			}
			el := e.clone()
			if err := wkrd.apply(el); err != nil {
				return nil, fmt.Errorf("failed applying workaround %q: %v", wkrd.id, err)
			}
			if events, err := el.verify(mrs); err == nil {
				return events, nil
			}
		}
	}

	return events, err
}

func (e *EventLog) verify(mrs []register.MR) ([]Event, error) {
	events, err := replayEvents(e.rawEvents, mrs)
	if err != nil {
		if _, isReplayErr := err.(ReplayError); isReplayErr {
			return nil, err
		}
		return nil, fmt.Errorf("registers failed to replay: %v", err)
	}
	return events, nil
}
func extend(pcr register.MR, replay []byte, e rawEvent, locality byte) (pcrDigest []byte, eventDigest []byte, err error) {
	h := pcr.DgstAlg()

	for _, digest := range e.digests {
		if digest.hash != pcr.DgstAlg() {
			continue
		}
		if len(digest.data) != len(pcr.Dgst()) {
			return nil, nil, fmt.Errorf("digest data length (%d) doesn't match PCR digest length (%d)", len(digest.data), len(pcr.Dgst()))
		}
		hash := h.New()
		if len(replay) != 0 {
			hash.Write(replay)
		} else {
			b := make([]byte, h.Size())
			b[h.Size()-1] = locality
			hash.Write(b)
		}
		hash.Write(digest.data)
		return hash.Sum(nil), digest.data, nil
	}
	return nil, nil, fmt.Errorf("no event digest matches pcr algorithm: %v", pcr.DgstAlg())
}

// replayPCR replays the event log for a specific PCR, using pcr and
// event digests with the algorithm in pcr. An error is returned if the
// replayed values do not match the final PCR digest, or any event tagged
// with that PCR does not possess an event digest with the specified algorithm.
func replayPCR(rawEvents []rawEvent, mr register.MR) ([]Event, bool) {
	var (
		replay    []byte
		outEvents []Event
		locality  byte
	)
	mrIdx := mr.Idx()
	for _, e := range rawEvents {
		if e.index != mrIdx {
			continue
		}
		// If TXT is enabled then the first event for PCR0
		// should be a StartupLocality event. The final byte
		// of this event indicates the locality from which
		// TPM2_Startup() was issued. The initial value of
		// PCR0 is equal to the locality.
		if e.typ == eventTypeNoAction {
			if mr.Idx() == 0 && len(e.data) == 17 && strings.HasPrefix(string(e.data), "StartupLocality") {
				locality = e.data[len(e.data)-1]
			}
			continue
		}
		replayValue, digest, err := extend(mr, replay, e, locality)
		if err != nil {
			return nil, false
		}
		replay = replayValue
		outEvents = append(outEvents, Event{
			sequence: e.sequence,
			Data:     e.data,
			Digest:   digest,
			Index:    mrIdx,
			Type:     e.typ,
			hash:     mr.DgstAlg(),
		})
	}

	if len(outEvents) > 0 && !bytes.Equal(replay, mr.Dgst()) {
		return nil, false
	}
	return outEvents, true
}

type pcrReplayResult struct {
	events     []Event
	successful bool
}

func replayEvents(rawEvents []rawEvent, mrs []register.MR) ([]Event, error) {
	var (
		invalidReplays []int
		verifiedEvents []Event
		allPCRReplays  = map[int][]pcrReplayResult{}
	)

	// Replay the event log for every PCR and digest algorithm combination.
	for _, mr := range mrs {
		events, ok := replayPCR(rawEvents, mr)
		allPCRReplays[mr.Idx()] = append(allPCRReplays[mr.Idx()], pcrReplayResult{events, ok})
	}

	// Record PCR indices which do not have any successful replay. Record the
	// events for a successful replay.
pcrLoop:
	for i, replaysForPCR := range allPCRReplays {
		for _, replay := range replaysForPCR {
			if replay.successful {
				// We consider the PCR verified at this stage: The replay of values with
				// one digest algorithm matched a provided value.
				// As such, we save the PCR's events, and proceed to the next PCR.
				verifiedEvents = append(verifiedEvents, replay.events...)
				continue pcrLoop
			}
		}
		invalidReplays = append(invalidReplays, i)
	}

	if len(invalidReplays) > 0 {
		events := make([]Event, 0, len(rawEvents))
		for _, e := range rawEvents {
			events = append(events, Event{
				sequence: e.sequence,
				Index:    e.index,
				Type:     e.typ,
				Data:     e.data,
			})
		}
		return nil, ReplayError{
			Events:     events,
			InvalidMRs: invalidReplays,
		}
	}

	sort.Slice(verifiedEvents, func(i int, j int) bool {
		return verifiedEvents[i].sequence < verifiedEvents[j].sequence
	})
	return verifiedEvents, nil
}

// EV_NO_ACTION is a special event type that indicates information to the parser
// instead of holding a measurement. For TPM 2.0, this event type is used to signal
// switching from SHA1 format to a variable length digest.
//
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf#page=110
const eventTypeNoAction = 0x03

type specIDEvent struct {
	algs []specAlgSize
}

type specAlgSize struct {
	ID   uint16
	Size uint16
}

// Expected values for various Spec ID Event fields.
// https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf#page=19
var wantSignature = [16]byte{0x53, 0x70,
	0x65, 0x63, 0x20, 0x49,
	0x44, 0x20, 0x45, 0x76,
	0x65, 0x6e, 0x74, 0x30,
	0x33, 0x00} // "Spec ID Event03\0"

const (
	wantMajor  = 2
	wantMinor  = 0
	wantErrata = 0
)

type specIDEventHeader struct {
	Signature     [16]byte
	PlatformClass uint32
	VersionMinor  uint8
	VersionMajor  uint8
	Errata        uint8
	UintnSize     uint8
	NumAlgs       uint32
}

// parseSpecIDEvent parses a TCG_EfiSpecIDEventStruct structure from the reader.
//
// https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf#page=18
func parseSpecIDEvent(b []byte) (*specIDEvent, error) {
	r := bytes.NewReader(b)
	var header specIDEventHeader
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("reading event header: %w: %X", err, b)
	}
	if header.Signature != wantSignature {
		return nil, fmt.Errorf("invalid spec id signature: %x", header.Signature)
	}
	if header.VersionMajor != wantMajor {
		return nil, fmt.Errorf("invalid spec major version, got %02x, wanted %02x",
			header.VersionMajor, wantMajor)
	}
	if header.VersionMinor != wantMinor {
		return nil, fmt.Errorf("invalid spec minor version, got %02x, wanted %02x",
			header.VersionMajor, wantMinor)
	}

	// TODO(ericchiang): Check errata? Or do we expect that to change in ways
	// we're okay with?

	specAlg := specAlgSize{}
	e := specIDEvent{}
	for i := 0; i < int(header.NumAlgs); i++ {
		if err := binary.Read(r, binary.LittleEndian, &specAlg); err != nil {
			return nil, fmt.Errorf("reading algorithm: %v", err)
		}
		e.algs = append(e.algs, specAlg)
	}

	var vendorInfoSize uint8
	if err := binary.Read(r, binary.LittleEndian, &vendorInfoSize); err != nil {
		return nil, fmt.Errorf("reading vender info size: %v", err)
	}
	if r.Len() != int(vendorInfoSize) {
		return nil, fmt.Errorf("reading vendor info, expected %d remaining bytes, got %d", vendorInfoSize, r.Len())
	}
	return &e, nil
}

type digest struct {
	hash crypto.Hash
	data []byte
}

type rawEvent struct {
	sequence int
	index    int
	typ      EventType
	data     []byte
	digests  []digest
}

type eventSizeErr struct {
	eventSize uint32
	logSize   int
}

func (e *eventSizeErr) Error() string {
	return fmt.Sprintf("event data size (%d bytes) is greater than remaining measurement log (%d bytes)", e.eventSize, e.logSize)
}

// AppendEvents takes a series of TPM 2.0 event logs and combines
// them into a single sequence of events with a single header.
//
// Additional logs must not use a digest algorithm which was not
// present in the original log.
func AppendEvents(base []byte, additional ...[]byte) ([]byte, error) {
	baseLog, err := ParseEventLog(base, ParseOpts{})
	if err != nil {
		return nil, fmt.Errorf("base: %v", err)
	}
	if baseLog.specIDEvent == nil {
		return nil, errors.New("tpm 1.2 event logs cannot be combined")
	}

	outBuff := make([]byte, len(base))
	copy(outBuff, base)
	out := bytes.NewBuffer(outBuff)

	for i, l := range additional {
		log, err := ParseEventLog(l, ParseOpts{})
		if err != nil {
			return nil, fmt.Errorf("log %d: %v", i, err)
		}
		if log.specIDEvent == nil {
			return nil, fmt.Errorf("log %d: cannot use tpm 1.2 event log as a source", i)
		}

	algCheck:
		for _, alg := range log.specIDEvent.algs {
			for _, baseAlg := range baseLog.specIDEvent.algs {
				if baseAlg == alg {
					continue algCheck
				}
			}
			return nil, fmt.Errorf("log %d: cannot use digest (%+v) not present in base log", i, alg)
		}

		for x, e := range log.rawEvents {
			// Serialize header (PCR index, event type, number of digests)
			binary.Write(out, binary.LittleEndian, rawEvent2Header{
				PCRIndex: uint32(e.index),
				Type:     uint32(e.typ),
			})
			binary.Write(out, binary.LittleEndian, uint32(len(e.digests)))

			// Serialize digests
			for _, d := range e.digests {
				var algID uint16
				switch d.hash {
				case crypto.SHA384:
					algID = uint16(register.HashSHA384)
				case crypto.SHA256:
					algID = uint16(register.HashSHA256)
				case crypto.SHA1:
					algID = uint16(register.HashSHA1)
				default:
					return nil, fmt.Errorf("log %d: event %d: unhandled hash function %v", i, x, d.hash)
				}

				binary.Write(out, binary.LittleEndian, algID)
				out.Write(d.data)
			}

			// Serialize event data
			binary.Write(out, binary.LittleEndian, uint32(len(e.data)))
			out.Write(e.data)
		}
	}

	return out.Bytes(), nil
}

// SHA1 event log format. See "5.1 SHA1 Event Log Entry Format"
// https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf#page=15
type rawEventHeader struct {
	PCRIndex  uint32
	Type      uint32
	Digest    [20]byte
	EventSize uint32
}

func parseRawEvent(r *bytes.Buffer, _ *specIDEvent) (event rawEvent, err error) {
	var h rawEventHeader
	if err = binary.Read(r, binary.LittleEndian, &h); err != nil {
		return event, fmt.Errorf("header deserialization error: %w", err)
	}
	if h.EventSize > uint32(r.Len()) {
		return event, &eventSizeErr{h.EventSize, r.Len()}
	}

	data := make([]byte, int(h.EventSize))
	if _, err := io.ReadFull(r, data); err != nil {
		return event, fmt.Errorf("reading data error: %w", err)
	}

	digests := []digest{{hash: crypto.SHA1, data: h.Digest[:]}}

	return rawEvent{
		typ:     EventType(h.Type),
		data:    data,
		index:   int(h.PCRIndex),
		digests: digests,
	}, nil
}

// Crypto Agile event log format. See "5.2 Crypto Agile Log Entry Format"
// https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf#page=15
type rawEvent2Header struct {
	PCRIndex uint32
	Type     uint32
}

func parseRawEvent2(r *bytes.Buffer, specID *specIDEvent) (event rawEvent, err error) {
	var h rawEvent2Header

	if err = binary.Read(r, binary.LittleEndian, &h); err != nil {
		return event, err
	}
	if h.PCRIndex == 0xFFFFFFFF {
		return event, errEventLogPadding
	}
	event.typ = EventType(h.Type)
	event.index = int(h.PCRIndex)

	// parse the event digests
	var numDigests uint32
	if err := binary.Read(r, binary.LittleEndian, &numDigests); err != nil {
		return event, err
	}

	for i := 0; i < int(numDigests); i++ {
		var algID uint16
		if err := binary.Read(r, binary.LittleEndian, &algID); err != nil {
			return event, err
		}
		var digest digest

		for _, alg := range specID.algs {
			if alg.ID != algID {
				continue
			}
			if r.Len() < int(alg.Size) {
				return event, fmt.Errorf("reading digest: %v", io.ErrUnexpectedEOF)
			}
			digest.data = make([]byte, alg.Size)
			digest.hash = register.HashAlg(alg.ID).CryptoHash()
		}
		if len(digest.data) == 0 {
			digest.data = make([]byte, 8)
			digest.data[0] = 0
			return event, fmt.Errorf("unknown algorithm ID %x", algID)
		}
		if _, err := io.ReadFull(r, digest.data); err != nil {
			return event, err
		}
		event.digests = append(event.digests, digest)
	}

	// parse event data
	var eventSize uint32
	if err = binary.Read(r, binary.LittleEndian, &eventSize); err != nil {
		return event, err
	}
	if eventSize > uint32(r.Len()) {
		return event, &eventSizeErr{eventSize, r.Len()}
	}
	event.data = make([]byte, int(eventSize))
	if _, err := io.ReadFull(r, event.data); err != nil {
		return event, err
	}
	return event, err
}

var errEventLogPadding = errors.New("reached padding before event log EOF")
