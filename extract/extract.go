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

// Package extract has tools for extracting boot and runtime information from measurements.
package extract

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	pb "github.com/google/go-eventlog/proto/state"
	"github.com/google/go-eventlog/tcg"
	"github.com/google/go-eventlog/wellknown"
	"github.com/google/go-tpm/legacy/tpm2"
)

var (
	newGrubKernelCmdlinePrefix = []byte("kernel_cmdline: ")
	oldGrubKernelCmdlinePrefix = []byte("grub_kernel_cmdline ")
	// See https://www.gnu.org/software/grub/manual/grub/grub.html#Measured-Boot.
	validPrefixes = [][]byte{[]byte("grub_cmd: "),
		newGrubKernelCmdlinePrefix,
		[]byte("module_cmdline: "),
		// Older style prefixes:
		// https://src.fedoraproject.org/rpms/grub2/blob/c789522f7cfa19a10cd716a1db24dab5499c6e5c/f/0224-Rework-TPM-measurements.patch
		oldGrubKernelCmdlinePrefix,
		[]byte("grub_cmd ")}
)

// Bootloader refers to the second-stage bootloader that loads and transfers
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

// Opts gives options for extracting information from an event log.
type Opts struct {
	Loader Bootloader
}

// FirmwareLogState extracts event info from a verified TCG PC Client event
// log into a FirmwareLogState.
// It returns an error on failing to parse malformed events.
//
// The returned FirmwareLogState may be a partial FirmwareLogState.
// In the case of a partially filled state, err will be non-nil.
// Callers can look for individual errors using `errors.Is`.
//
// It is the caller's responsibility to ensure that the passed events have
// been replayed (e.g., using `tcg.ParseAndReplay`) against a verified measurement
// register bank.
func FirmwareLogState(events []tcg.Event, hash crypto.Hash, registerCfg registerConfig, opts Opts) (*pb.FirmwareLogState, error) {
	var joined error
	tcgHash, err := tpm2.HashToAlgorithm(hash)
	if err != nil {
		return nil, err
	}

	platform, err := registerCfg.PlatformExtracter(hash, events)
	if err != nil {
		joined = errors.Join(joined, err)
	}
	sbState, err := SecureBootState(events, registerCfg)
	if err != nil {
		joined = errors.Join(joined, err)
	}
	efiState, err := EfiState(hash, events, registerCfg)

	if err != nil {
		joined = errors.Join(joined, err)
	}

	var grub *pb.GrubState
	var kernel *pb.LinuxKernelState
	if opts.Loader == GRUB {
		grub, err = registerCfg.GRUBExtracter(hash, events)

		if err != nil {
			joined = errors.Join(joined, err)
		}
		kernel, err = LinuxKernelStateFromGRUB(grub)
		if err != nil {
			joined = errors.Join(joined, err)
		}
	}
	return &pb.FirmwareLogState{
		Platform:    platform,
		SecureBoot:  sbState,
		Efi:         efiState,
		RawEvents:   tcg.ConvertToPbEvents(hash, events),
		Hash:        pb.HashAlgo(tcgHash),
		Grub:        grub,
		LinuxKernel: kernel,
	}, joined
}

func contains(set [][]byte, value []byte) bool {
	for _, setItem := range set {
		if bytes.Equal(value, setItem) {
			return true
		}
	}
	return false
}

type separatorInfo struct {
	separatorData    [][]byte
	separatorDigests [][]byte
}

// getSeparatorInfo is used to return the valid event data and their corresponding
// digests. This is useful for events like separators, where the data is known
// ahead of time.
func getSeparatorInfo(hash crypto.Hash) *separatorInfo {
	hasher := hash.New()
	// From the PC Client Firmware Profile spec, on the separator event:
	// The event field MUST contain the hex value 00000000h or FFFFFFFFh.
	sepData := [][]byte{{0, 0, 0, 0}, {0xff, 0xff, 0xff, 0xff}}
	sepDigests := make([][]byte, 0, len(sepData))
	for _, value := range sepData {
		hasher.Write(value)
		sepDigests = append(sepDigests, hasher.Sum(nil))
	}
	return &separatorInfo{separatorData: sepData, separatorDigests: sepDigests}
}

// checkIfValidSeparator returns true if both the separator event's type and
// digest match the expected event data.
// If the event type is Separator, but the data is invalid, it returns false
// and an error.
// checkIfValidSeparator returns false and a nil error on other event types.
func checkIfValidSeparator(event tcg.Event, sepInfo *separatorInfo) (bool, error) {
	evtType := event.UntrustedType()
	index := event.MRIndex()
	if (evtType != tcg.Separator) && !contains(sepInfo.separatorDigests, event.ReplayedDigest()) {
		return false, nil
	}
	// To make sure we have a valid event, we check any event (e.g., separator)
	// that claims to be of the event type or "looks like" the event to prevent
	// certain vulnerabilities in event parsing. For more info see:
	// https://github.com/google/go-attestation/blob/master/docs/event-log-disclosure.md
	if evtType != tcg.Separator {
		return false, fmt.Errorf("MR%d event contains separator data but non-separator type %d", index, evtType)
	}
	if !event.DigestVerified() {
		return false, fmt.Errorf("unverified separator digest for MR%d", index)
	}
	if !contains(sepInfo.separatorData, event.RawData()) {
		return false, fmt.Errorf("invalid separator data for MR%d", index)
	}
	return true, nil
}

func convertToPbDatabase(certs []x509.Certificate, hashes [][]byte) *pb.Database {
	protoCerts := make([]*pb.Certificate, 0, len(certs))
	for _, cert := range certs {
		wkEnum, err := matchWellKnown(cert)
		var pbCert pb.Certificate
		if err == nil {
			pbCert.Representation = &pb.Certificate_WellKnown{WellKnown: wkEnum}
		} else {
			pbCert.Representation = &pb.Certificate_Der{Der: cert.Raw}
		}
		protoCerts = append(protoCerts, &pbCert)
	}
	return &pb.Database{
		Certs:  protoCerts,
		Hashes: hashes,
	}
}

func matchWellKnown(cert x509.Certificate) (pb.WellKnownCertificate, error) {
	if bytes.Equal(wellknown.WindowsProductionPCA2011Cert, cert.Raw) {
		return pb.WellKnownCertificate_MS_WINDOWS_PROD_PCA_2011, nil
	}
	if bytes.Equal(wellknown.MicrosoftUEFICA2011Cert, cert.Raw) {
		return pb.WellKnownCertificate_MS_THIRD_PARTY_UEFI_CA_2011, nil
	}
	return pb.WellKnownCertificate_UNKNOWN, errors.New("failed to find matching well known certificate")
}

// SecureBootState extracts Secure Boot information from a UEFI TCG2
// firmware event log.
func SecureBootState(replayEvents []tcg.Event, registerCfg registerConfig) (*pb.SecureBootState, error) {
	attestSbState, err := ParseSecurebootState(replayEvents, registerCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SecureBootState: %v", err)
	}
	if len(attestSbState.PreSeparatorAuthority) != 0 {
		return nil, fmt.Errorf("event log contained %v pre-separator authorities, which are not expected or supported", len(attestSbState.PreSeparatorAuthority))
	}
	return &pb.SecureBootState{
		Enabled:   attestSbState.Enabled,
		Db:        convertToPbDatabase(attestSbState.PermittedKeys, attestSbState.PermittedHashes),
		Dbx:       convertToPbDatabase(attestSbState.ForbiddenKeys, attestSbState.ForbiddenHashes),
		Authority: convertToPbDatabase(attestSbState.PostSeparatorAuthority, nil),
	}, nil
}

// PlatformState extracts platform information from a UEFI TCG2 firmware
// event log.
func PlatformState(hash crypto.Hash, events []tcg.Event) (*pb.PlatformState, error) {
	// We pre-compute the separator and EFI Action event hash.
	// We check if these events have been modified, since the event type is
	// untrusted.
	sepInfo := getSeparatorInfo(hash)
	var versionString []byte
	var nonHostInfo []byte
	for _, event := range events {
		index := event.MRIndex()
		if index != 0 {
			continue
		}
		evtType := event.UntrustedType()
		isSeparator, err := checkIfValidSeparator(event, sepInfo)
		if err != nil {
			return nil, err
		}
		if isSeparator {
			// Don't trust any PCR0 events after the separator
			break
		}

		if evtType == tcg.SCRTMVersion {
			if !event.DigestVerified() {
				return nil, fmt.Errorf("invalid SCRTM version event for PCR%d", index)
			}
			versionString = event.RawData()
		}

		if evtType == tcg.NonhostInfo {
			if !event.DigestVerified() {
				return nil, fmt.Errorf("invalid Non-Host info event for PCR%d", index)
			}
			nonHostInfo = event.RawData()
		}
	}

	state := &pb.PlatformState{}
	if gceVersion, err := wellknown.ConvertSCRTMVersionToGCEFirmwareVersion(versionString); err == nil {
		state.Firmware = &pb.PlatformState_GceVersion{GceVersion: gceVersion}
	} else {
		state.Firmware = &pb.PlatformState_ScrtmVersionId{ScrtmVersionId: versionString}
	}

	if tech, err := wellknown.ParseGCENonHostInfo(nonHostInfo); err == nil {
		state.Technology = tech
	}

	return state, nil
}

// EfiState extracts EFI app information from a UEFI TCG2 firmware
// event log.
func EfiState(hash crypto.Hash, events []tcg.Event, registerCfg registerConfig) (*pb.EfiState, error) {
	// We pre-compute various event digests, and check if those event type have
	// been modified. We only trust events that come before the
	// ExitBootServices() request.
	separatorInfo := getSeparatorInfo(hash)

	hasher := hash.New()
	hasher.Write([]byte(tcg.CallingEFIApplication))
	callingEFIAppDigest := hasher.Sum(nil)

	hasher.Reset()
	hasher.Write([]byte(tcg.ExitBootServicesInvocation))
	exitBootSvcDigest := hasher.Sum(nil)

	var efiAppStates []*pb.EfiApp
	var seenSeparator4 bool
	var seenSeparator5 bool
	var seenCallingEfiApp bool
	var seenExitBootServices bool
	for _, event := range events {
		index := event.MRIndex()
		//  MRs corresponding to EFI apps and the Exit Boot Services event.
		if index != registerCfg.EFIAppIdx && index != registerCfg.ExitBootServicesIdx {
			continue
		}
		evtType := event.UntrustedType()

		// Switch statements won't work since duplicate cases will get triggered like an if, else-if, else.			// Process Calling EFI Application event.
		// See https://github.com/golang/go/commit/2d9378c7f6dfbbe82d1bbd806093c2dfe57d7e17
		// PCRs use different indexes, but RTMRs do not.
		if index == registerCfg.EFIAppIdx {
			if bytes.Equal(callingEFIAppDigest, event.ReplayedDigest()) {
				if evtType != tcg.EFIAction {
					return nil, fmt.Errorf("%s%d contains CallingEFIApp event but non EFIAction type: %d",
						registerCfg.Name, index, evtType)
				}
				if !event.DigestVerified() {
					return nil, fmt.Errorf("unverified CallingEFIApp digest for %s%d", registerCfg.Name, index)
				}
				// We don't support calling more than one boot device.
				if seenCallingEfiApp {
					return nil, fmt.Errorf("found duplicate CallingEFIApp event in %s%d", registerCfg.Name, index)
				}
				if seenSeparator4 {
					return nil, fmt.Errorf("found CallingEFIApp event in %s%d after separator event", registerCfg.Name, index)
				}
				seenCallingEfiApp = true
			}

			if evtType == tcg.EFIBootServicesApplication {
				if !seenCallingEfiApp {
					return nil, fmt.Errorf("found EFIBootServicesApplication in %s%d before CallingEFIApp event", registerCfg.Name, index)
				}
				efiAppStates = append(efiAppStates, &pb.EfiApp{Digest: event.ReplayedDigest()})
			}

			isSeparator, err := checkIfValidSeparator(event, separatorInfo)
			if err != nil {
				return nil, err
			}
			if isSeparator {
				if seenSeparator4 {
					return nil, fmt.Errorf("found duplicate Separator event in %s%d", registerCfg.Name, registerCfg.EFIAppIdx)
				}
				seenSeparator4 = true
			}
		}
		if index == registerCfg.ExitBootServicesIdx {
			// Process ExitBootServices event.
			if bytes.Equal(exitBootSvcDigest, event.ReplayedDigest()) {
				if evtType != tcg.EFIAction {
					return nil, fmt.Errorf("%s%d contains ExitBootServices event but non EFIAction type: %d",
						registerCfg.Name, index, evtType)
				}
				if !event.DigestVerified() {
					return nil, fmt.Errorf("unverified ExitBootServices digest for %s%d", registerCfg.Name, index)
				}
				// Don't process any events after Boot Manager has requested
				// ExitBootServices().
				seenExitBootServices = true
				break
			}

			isSeparator, err := checkIfValidSeparator(event, separatorInfo)
			if err != nil {
				return nil, err
			}
			if isSeparator {
				if seenSeparator5 {
					return nil, fmt.Errorf("found duplicate Separator event in %s%d", registerCfg.Name, registerCfg.ExitBootServicesIdx)
				}
				seenSeparator5 = true
			}
		}
	}
	// Only write EFI digests if we see an ExitBootServices invocation.
	// Otherwise, software further down the bootchain could extend bad
	// PCR4/RTMR2 measurements.
	if seenExitBootServices {
		return &pb.EfiState{Apps: efiAppStates}, nil
	}
	return nil, nil
}

// LinuxKernelStateFromGRUB extracts the kernel command line from GrubState.
func LinuxKernelStateFromGRUB(grub *pb.GrubState) (*pb.LinuxKernelState, error) {
	var cmdline string
	seen := false

	for _, command := range grub.GetCommands() {
		// GRUB config is always in UTF-8: https://www.gnu.org/software/grub/manual/grub/html_node/Internationalisation.html.
		cmdBytes := []byte(command)
		suffixAt := getGrubKernelCmdlineSuffix(cmdBytes)
		if suffixAt == -1 {
			continue
		}

		if seen {
			return nil, fmt.Errorf("more than one kernel commandline in GRUB commands")
		}
		seen = true
		cmdline = command[suffixAt:]
	}

	return &pb.LinuxKernelState{CommandLine: cmdline}, nil
}

func getGrubKernelCmdlineSuffix(grubCmd []byte) int {
	for _, prefix := range [][]byte{oldGrubKernelCmdlinePrefix, newGrubKernelCmdlinePrefix} {
		if bytes.HasPrefix(grubCmd, prefix) {
			return len(prefix)
		}
	}
	return -1
}
