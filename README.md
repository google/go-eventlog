# Go Event Log

Go Event Log is a library for handling various event logs for use in Measured Boot protocols.

It is a companion for technologies that provide measurement registers and an event log, such as TPM PCRs and the TCG PC Client event log.

Packages:
- `ccel`
- `cel`
- `legacy`
- `tpmeventlog`
- `proto`
- `register`
- `wellknown`

# Terminology
Event log parsing is the process of resolving event log events against the registers in the Root of Trust for Measurement and extracting useful information from the verified events. At a high level, we can break it down into Quote Verification, Event Log Replay, and Event Parsing.

## Measured Boot
To ensure the integrity of the event log, measurement registers contain the final digest of a chain of measurements. These registers are typically located on tamper-proof storage on a root-of-trust, like a TPM. With measurement registers, a verifier can detect changes to an event log through a mechanism called event log replay. On TPMs, measurement registers are called platform configuration registers, or PCRs.

Typically, these measurement registers are not directly writable. They usually expose an Extend command that takes the existing value in the MR, concatenates it with the new event hash, and then hashes the concatenated value.

MRnew = hash(MRold  ||  hash(measured data))

Since hash functions are one way, replicating the same MR values without the same measurements is difficult. This is a good property: only the same boot configuration should yield the same MR values. However, in the same vein, MRs are difficult to use to craft a machine policy since any small change in the input or in measurement order yields wildly different MR values.

## Quote Verification
A measured boot root of trust can issue a report of the measurement registers, often called a quote or attestation report. This quote is typically a digitally-signed digest of measurement registers.

A verifier then checks that the digest of measurement registers are signed by a trustworthy key, the Root of Trust for Reporting (RTR). This RTR, aka attestation key, is typically a certified key that signs a report of the measurement registers. This certification is known as an Endorsement in the [IETF RATS Architecture](https://datatracker.ietf.org/doc/rfc9334/).

NOTE: This library does not support quote verification. Integrating code is expected to first verify a quote before using the facilities for event log replay and parsing.

## Event Log Replay
Event log replay involves deserializing a raw event log and using the events to recalculate all of the measurement registers. Each event contains a digest and a measurement register index. The verifier will create simulated measurement registers and, for each event, extend the event digest into its corresponding simulated register. At the end, the verifier compares the simulated register values against the actual quoted measurement register values from the first step.

Technology-specific logic in this repo includes deserializing a raw event log binary. For example, there will be different logic to parse a TCG PC Client event log, a Canonical Event Log, and a Confidential Computing Event Log (CCEL). Furthermore, different technologies use different types/number of measurement registers.

## Event Parsing
Event parsing is the process of pulling information from the events. The verifier uses the output to make verification decisions against the appraisal policy, endorsements, and reference values. Since parsing events securely often requires examining state transitions from other events, this is also somewhat technology specific. For example, the ExitBootServices transition is measured in PCR5 on TPMs and RTMR0 on Intel TDX.

Some examples of useful measurement information:
* Firmware
* Secure Boot configuration
* Bootloaders
  * GRUB is supported by this library
* Kernel
  * Command line
  * Initramfs
* Integrity Measurement Architecture
  * Not supported

## Reference Measurements
This library does not vend reference measurements or any specific Reference Integrity Manifests (RIMs). It is the responsibility of integrators to supply or fetch appropriate reference measurements.

# Disclaimers
This repo is part of a larger [go-attestation](https://github.com/google/go-attestation) migration.
Expect pre-release commits and even v0.* releases to have plenty of breaking changes.

This is not an officially supported Google product.
