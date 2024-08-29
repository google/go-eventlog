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

// Package legacy contains the legacy API adaptors for use by go-attestation.
package legacy

import "github.com/google/go-eventlog/tcg"

// Event is a single event from a TCG event log. This reports descrete items such
// as BIOS measurements or EFI states.
//
// There are many pitfalls for using event log events correctly to determine the
// state of a machine[1]. In general it's much safer to only rely on the raw PCR
// values and use the event log for debugging.
//
// [1] https://github.com/google/go-attestation/blob/master/docs/event-log-disclosure.md
type Event struct {
	// Sequence gives the order of the event in the event log.
	Sequence int
	// Index of the PCR that this event was replayed against.
	Index int
	// Untrusted type of the event. This value is not verified by event log replays
	// and can be tampered with. It should NOT be used without additional context,
	// and unrecognized event types should result in errors.
	Type tcg.EventType

	// Data of the event. For certain kinds of events, this must match the event
	// digest to be valid.
	Data []byte
	// Digest is the verified digest of the event data. While an event can have
	// multiple for different hash values, this is the one that was matched to the
	// PCR value.
	Digest []byte

	// TODO(ericchiang): Provide examples or links for which event types must
	// match their data to their digest.
}
