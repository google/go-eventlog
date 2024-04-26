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

// common provides types and functions for use across event log parsing.
package common

// common.Bootloader refers to the second-stage bootloader that loads and transfers
// execution to the OS kernel.
type Bootloader int

const (
	// UnsupportedLoader refers to a second-stage bootloader that is of an
	// unsupported type. VerifyAttestation will not parse the PC Client Event
	// Log for bootloader events.
	UnsupportedLoader Bootloader = iota
	// GRUB (https://www.gnu.org/software/grub/).
	GRUB
)
