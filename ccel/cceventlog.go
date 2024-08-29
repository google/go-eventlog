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

// Package ccel implements event log parsing and replay for the Confidential Computing event log.
// It only supports the CCEL based on the TCG crypto-agile event log (including
// the "Spec ID Event03" signature).
package ccel

import (
	"encoding/binary"
	"fmt"
)

/*
  MrIndex = 0;
  if (PCRIndex == 0) {
    MrIndex = CC_MR_INDEX_0_MRTD;
  } else if ((PCRIndex == 1) || (PCRIndex == 7)) {
    MrIndex = CC_MR_INDEX_1_RTMR0;
  } else if ((PCRIndex >= 2) && (PCRIndex <= 6)) {
    MrIndex = CC_MR_INDEX_2_RTMR1;
  } else if ((PCRIndex >= 8) && (PCRIndex <= 15)) {
    MrIndex = CC_MR_INDEX_3_RTMR2;
  }
*/

// Defined in Guest Hypervisor Communication Interface (GHCI) for Intel TDX 1.0.
// https://www.intel.com/content/www/us/en/content-details/726790/guest-host-communication-interface-ghci-for-intel-trust-domain-extensions-intel-tdx.html
const (
	// See Section 4.3.3 CC-Event Log
	CCELACPITableSig     = "CCEL"
	CCELACPITableMinSize = 56
)

// CCType describes the Confidential Computing type for the Confidential
// Computing event log.
type CCType uint8

// Known CC types.
// See https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html#cc-event-log-acpi-table.
const (
	Reserved = iota
	SEV
	TDX
)

// CCACPITable represents the confidential computing (CC) event log ACPI table.
type CCACPITable struct {
	Length uint32
	CCType
}

func parseCCELACPITable(acpiTableFile []byte) (CCACPITable, error) {
	if len(acpiTableFile) < CCELACPITableMinSize {
		return CCACPITable{}, fmt.Errorf("received a smaller CCEL ACPI Table size (%v) than expected (%v)", len(acpiTableFile), CCELACPITableMinSize)
	}
	sig := acpiTableFile[0:4]
	if CCELACPITableSig != string(sig) {
		return CCACPITable{}, fmt.Errorf("received an invalid signature (%v) for CCEL ACPI Table size (%v)", string(sig), len(acpiTableFile))

	}

	tableLenBytes := acpiTableFile[4:8]
	tableLen := binary.LittleEndian.Uint32(tableLenBytes)
	if tableLen != uint32(len(acpiTableFile)) {
		return CCACPITable{}, fmt.Errorf("received mismatch CCEL ACPI table length: got %v, expected %v", tableLen, uint32(len(acpiTableFile)))
	}

	ccType := acpiTableFile[36]
	if ccType > 2 {
		return CCACPITable{}, fmt.Errorf("received unknown CC type: %d", ccType)
	}

	logAreaMinLenBytes := acpiTableFile[40:48]
	laml := binary.LittleEndian.Uint32(logAreaMinLenBytes)
	return CCACPITable{
		Length: laml,
		CCType: CCType(ccType),
	}, nil
}
