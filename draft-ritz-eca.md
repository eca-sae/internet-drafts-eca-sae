%%%
title = "Entity and Compute Attestation (ECA)"
abbrev = "ECA"
category = "exp"
docname = "draft-ritz-eca-01"
date = "2025-10-04T00:00:00Z"
ipr = "trust200902"
area = "Security"
pi = ["toc", "sortrefs", "symrefs", "strict"]
stand_alone = true

[[author]]
fullname = "Nathanael Ritz"
organization = "Independent"
  [author.address]
  email = "nathanritz@gmail.com"
  
[[author]]
fullname = "Muhammad Usama Sardar"
organization = "TU Dresden"
  [author.address]
  email = "muhammad_usama.sardar@tu-dresden.de"

[seriesInfo]
name = "Internet-Draft"
value = "draft-ritz-eca-01"
stream = "IETF"
status = "experimental"
%%%

.# Abstract

This document specifies Entity and Compute Attestation (ECA), a protocol for continuous attestation of high-assurance workloads such as Trusted Execution Environments (TEEs) using RATS architecture. ECA defines two ceremonies: a bootstrap ceremony to establish verifiable identity in credential-vacuum environments (bare-metal, sovereign clouds, edge), and a re-attestation ceremony enabling single round-trip verification over (D)TLS using TLS Exported Authenticators with the `cmw_attestation` extension. Both ceremonies are transport-agnostic and complement frameworks like WIMSE. Bootstrap security properties are formally analyzed using ProVerif (work-in-progress).

{mainmatter}

# Scope {#scope}

ECA profiles the RATS [@!RFC9334] architecture and defines reusable cryptographic ceremonies for attestation. It assumes familiarity with the vocabulary and concepts defined in the RATS architecture. 

The protocol's security properties regarding verifiable identity bootstrapping have been explored formally using ProVerif, with detailed analysis in [](#app-formal-modelling-informative) demonstrating resilience against network attackers and defining precise security boundaries under key compromise scenarios.

# Problem Statement and Motivation

Secure remote workloads, especially long-running Trusted Execution Environments (TEEs), require more than just initial, point-in-time attestation; they need continuous verification to prove their ongoing trustworthiness. While this addresses the lifecycle of established identities, it creates an operational gap: how do we handle instances in environments that lack an initial, verifiable identity, such as bare-metal servers or multi-cloud VMs? This inconsistency creates significant challenges for portability and security. A complete solution must therefore address both the initial, verifiable bootstrapping of an identity from a credential vacuum and the continuous, stateful re-attestation of that identity throughout its lifecycle.

## ECA: A Unified Pattern for the Attestation Lifecycle

The **Entity and Compute Attestation (ECA)** protocol provides a unified pattern for the attestation lifecycle, centered on a lightweight **re-attestation ceremony**. This ceremony is designed for the continuous, stateful verification of high-assurance workloads like Trusted Execution Environments (TEEs), enabling a single round-trip health check over protocols like (D)TLS.

For re-attestation over (D)TLS, ECA leverages TLS Exported Authenticators [@?RFC9261] with the `cmw_attestation` extension [@?I-D.fossati-tls-exported-attestation], which this specification integrates to enable attestation credentials to be conveyed directly in the Certificate message during post-handshake authentication. This eliminates reliance on real-time certificate issuance from a Certificate Authority (CA), reducing handshake delays while ensuring attestation evidence remains cryptographically bound to the TLS session.

To enable this in environments that lack a built-in hardware identity—such as bare-metal, multi-cloud, or edge deployments—ECA also defines a foundational **bootstrap ceremony**. This ceremony establishes a verifiable cryptographic identity from a "credential vacuum," bridging the gap for 
workloads without a pre-existing trust anchor.

ECA is designed to realize the Passport Model from the RATS Architecture. In this model, an **Attester** engages in a ceremony with a **Verifier** to obtain a portable, signed **Attestation Result** (the "passport"). This passport, typically an **Entity Attestation Token (EAT)**, can then be presented to any number of **Relying Parties** (RPs) to make trust decisions.  In this specification, the workload server is the Attester, the Verifier provides the attestation service, and the consuming application or service (e.g., a KMS) is the Relying Party.

> **Working with Existing Frameworks:** ECA design focus was to complement, not replace, existing identity and attestation frameworks. For detailed exploration of how ECA integrates with ACME, BRSKI, SPIFFE/SPIRE, and other systems, see [](https://www.google.com/search?q=%23integration-with-existing-frameworks).

-----

## ECA Ceremonies

ECA defines two related ceremonies that create a complete attestation lifecycle: a workload without a verifiable identity can be bootstrapped on Day 0 to obtain a signed EAT/AR and then use that credential for efficient re-attestation on Day N. Workloads already backed with verifiable identities like long running Trusted Execution Environments (TEEs) are ready for attested connections implicitly. 

~~~
                                 +---------------------------+
                                 |  Re-attestation Ceremony  |
                                 |  (Warm Start Cycle)       |
                                 +---------------------------+
                                             ^
              Input: prior credential (RF)   | 
                     "Re-attestation Factor" |
 +------------------>---------------------+-------+
 | (Updated AR becomes RF for next cycle) |  RF   |
 |                                        +-------+
 ^                                            | Output: Updated AR/EAT
 |                                            v
 |                                        +----------+
 |    [ Day N: Periodic Health-check ]    | Updated  |
 +-------------------<--------------------| AR / EAT |
                                          +----------+
                                              ^
                                              |
                                              | Verifiable Credential
                                              | (Enters the cycle)
                                              |
                                 +--------------------------+
 [ Day 0: On-Ramp ]              |    Bootstrap Ceremony    |
 (Lacks Verifiable Identity      |      (Cold Start)        |
                                 +--------------------------+
~~~

### Continuous Verification (Re-attestation Ceremony)

This single-phase ceremony enables ongoing verification for instances that already possess a credential from a prior attestation (the **Re-attestation Factor, or RF**).

1.  **Attester presents** its existing credential (RF) along with fresh measurements (Instance Factor, IF).
2.  **Verifier validates** the credential and appraises the new measurements against its policy.

Its primary use case is for periodic health checks of long-running TEE-based services, and it derives its security from the initial bootstrap ceremony and the secure transport.

### Initial Identity Bootstrap (Bootstrap Ceremony)

This three-phase ceremony establishes initial identity for instances starting without any credentials.

1.  **Attester proves possession** of a public **Binding Factor (BF)** and a measurable **Instance Factor (IF)**.
2.  **Verifier validates this proof** and releases a secret challenge (**Validator Factor, VF**).
3.  **Attester proves joint possession** of the factors to receive its initial credential.

Its primary use case is cold-start identity establishment, with security anchored in cryptographic proofs analyzed in the formal model.

### Transport Agnosticism

ECA's security is derived from the cryptographic content of its exchanged artifacts, not the transport layer. Both ceremonies are transport-agnostic, with recommended patterns including TLS Exported Authenticators for interactive re-attestation and the pull-only Static Artifact Exchange (SAE) for bootstrapping in constrained networks.

# Conventions and Definitions {#conventions-and-definitions}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [@!RFC2119] [@!RFC8174] when, and only when, they appear in all capitals, as shown here.

**Binding Factor (BF):** A publicly verifiable, high-entropy value (≥128 bits) that cryptographically scopes an attestation ceremony to a specific context. The BF does not require confidentiality; protocol security relies on its binding to the Instance Factor, not secrecy. Context-specific semantics:

- **Bootstrap:** Image digest, signed manifest, or SBOM reference
- **Re-attestation:** Server's X.509 certificate public key

The protocol's specific design allows BF to appear in logs or metadata services without compromising security. Non-exhaustive examples include:

- An ACME account public key thumbprint published by an operator.
- An orchestrator-published artifact like an image digest or signed manifest.
- A version control tag combined with a signed Software Bill of Materials (SBOM) or other supply-chain attestation.

**Instance Factor (IF):** An inherent, measurable property of the instance that is verifiable by the Verifier. The IF value itself is never transmitted directly; instead, the Attester proves possession through cryptographic means (e.g., signature, quote, attestation report).

**Ceremony Binding:** The IF MUST be bound to the ceremony identifier (e.g., the `eca_uuid` for ECA bootstrap) to ensure freshness and prevent replay.

Examples:
- **Hardware-Rooted (Pattern A):** TPM quote, TEE attestation report against a CORiM [@?I-D.ietf-rats-corim]
- **Orchestrator-Provisioned (Pattern B):** Instance-unique value (e.g., `vendor_uuid`)
- **Artifact-Based (Pattern C):** Provisioned file content
- **Session-Bound:** TEE quote with ceremony ID in REPORTDATA

See [](#instance-factor-patterns-ifp) for additional examples and patterns.

**Validator Factor (VF):** A confidential, ephemeral challenge generated and released by the Verifier used during **bootstrap ceremonies** after successful initial authentication of BF+IF possession. The VF MUST be bound to the IF (e.g., `VF = SHA-256(seed || IF)`) to ensure secrecy against network attackers.

**Re-attestation Factor (RF):** A cryptographic credential proving identity continuity from a prior attestation ceremony. The RF enables simplified re-attestation without requiring a fresh interactive challenge.

Examples:
- **EAT from bootstrap:** The signed token produced by an ECA bootstrap ceremony
- **Signed IMDS token:** Vendor-provided instance identity document
- **Session key:** Credential established during prior attestation
- **X.509 certificate:** Cert issued based on prior attestation

The Verifier validates RF out-of-band against expected identity before accepting re-attestation evidence.

**Joint Possession:** The cryptographic property where security derives from proving knowledge of multiple factors (`BF`+`VF` for bootstrap, `BF`+`RF`+`IF` for re-attestation) rather than secrecy of individual components.

**Integrity Hash Beacon (IHB):** A SHA-256 binding of `BF` to `IF` that enables exposure-tolerant authentication while preventing pre-computation attacks to mitigate MiTM threats.

**Instance Factor Pattern (IFP):** The set of defined methods for sourcing the private value for Instance Factor (`IF`). Three patterns are defined: hardware-rooted (Pattern A), orchestrator-provisioned (Pattern B), and artifact-based (Pattern C). For detailed specifications, see [](#instance-factor-patterns-ifp).

**Entity Attestation Token (EAT):** A standardized token format [@!RFC9711] used to convey attestation evidence in a cryptographically verifiable form.

**Exchange Identifier (eca_uuid):** A unique identifier for each attestation lifecycle instance, used to construct artifact repository paths and prevent replay attacks in SAE-based deployments.

**Artifact Repository:** A simple, addressable store (e.g., a web server, an object store) where peers can publish and retrieve cryptographic artifacts in SAE-based deployments.

**Attestation Ceremony ("ceremony"):** The RATS architecture [@!RFC9334] refers to the exchange between participants as "attestation procedures." This document uses "Attestation Ceremony" (or "ceremony") synonymously to describe the complete, multi-phase sequence of cryptographic exchanges required for an attestation. The term "ceremony" is used conventionally throughout this specification.

**Attester:** In the RATS (Remote Attestation Procedures) architecture, the Attester is the entity that engages in an "attestation ceremony" to prove its identity and integrity. In WIMSE (Workload Identity in Multi-Cloud Secure Environments), this role is mapped to the **Workload**, such as an ephemeral compute instance that requires an identity.

* **Verifier:** The Verifier is the entity that appraises the evidence provided by the Attester. It enforces a series of validation gates and, upon successful appraisal, produces a signed Attestation Result (often an EAT, or Entity Attestation Token) that can be presented to other parties. Within a WIMSE architecture, this role is often fulfilled by an **Identity or Attestation Service**.

* **Relying Party (RP):** A Relying Party is an entity that consumes the signed Attestation Result from a Verifier to make a trust or authorization decision about an Attester. The Relying Party is the ultimate consumer of the attestation "passport" and can be a service like a Key Management Service (KMS), API Gateway, or any other service that needs to verify the Attester before granting access or releasing credentials.

# Conceptual Model (Non-Normative) {#conceptual-model}

ECA defines two cryptographic ceremonies:

## Bootstrap Ceremony (Cold Start) {#bootstrap-ceremony-cold-start}

Establishes initial identity when no prior credential exists.

**Ceremony Flow:** `(BF+IF) → VF → PoP(BF+VF) → AR`

**Purpose:** Cryptographically prove possession of public context (BF) and measurable property (IF) to receive first credential.

**Output:** Attestation Result (AR) with unique `eca_attester_id`

See [](#protocol-overview) for detailed specification.

## Re-attestation Ceremony (Warm Start) {#re-attestation-ceremony-warm-start}

Verifies current state when credential from prior attestation exists.

**Ceremony Flow:** `(BF+RF+IF) → AR` (single round-trip)

**Purpose:** Present existing credential (RF) and prove current state (IF) to receive updated attestation.

**Output:** Updated AR with refreshed measurements

See [](#re-attestation-ceremony-specification) for detailed specification.

## Key Distinction

- **VF (Validator Factor)**: Bootstrap-specific interactive challenge
- **RF (Re-attestation Factor)**: Re-attestation credential proving identity continuity

Both ceremonies use the same cryptographic primitives and validation gates, but differ in their trust assumptions and round-trip requirements.

# Instance Factor Patterns (IFP) {#instance-factor-patterns-ifp}

ECA supports full integration with hardware roots of trust (HRoT) where available, and such integration is RECOMMENDED. ECA does not replace the need for HRoTs where the threat model must assume a compromised service provider, hypervisor or related platform risks.

The choice of IFP pattern determines the source of the Instance Factor (IF) and the strength of the resulting security guarantee. The security of the ECA protocol's initial phase depends on the Attester cryptographically proving the property represented by the `IF`, which is bound to the public Binding Factor (BF).

The three defined patterns are:

**IFP Pattern A (Hardware-Rooted):** The `IF` represents a measurement or cryptographic quote from a hardware root of trust (HRoT), such as a vTPM or TEE. The Attester proves possession by generating this artifact, which the Verifier appraises against expected values (e.g., golden PCR measurements). This pattern provides the highest level of security.

**IFP Pattern B (Orchestrator-Provisioned):** The `IF` is a one-time, instance-unique value delivered by a trusted orchestrator through a secure channel. The Verifier knows the expected value based on its provisioning request. This protects against network attackers but assumes the infrastructure provider is trusted.

**IFP Pattern C (Artifact-Based):**  The `IF` is the full content of a provisioned artifact (e.g., an `authorized_keys` file) that also contains the BF. The Verifier can reconstruct the expected IF because it generated the original artifact. This pattern addresses TOFU vulnerabilities in constrained environments. For security considerations with this pattern, see [](#impersonation-risk).

In the case of re-attestation using ECA, the IF typically represents current platform state (e.g., fresh TEE measurements) rather than initial provisioning state. See [](#re-attestation-ceremony-specification).

## Minimal Deployment and Trust Chain Sketch (Pattern C) {#minimal-deployment-and-trust-chain-sketch-pattern-c}

This section illustrates how ECA can be used even at a small, human-driven scale—such as by an individual developer—to provide cryptographic assurance for ephemeral instances without requiring complex infrastructure or hardware roots of trust, using `IFP Pattern C`. 

In this sketch, the Instance Factor (IF) is an artifact-based value such as the full content of an injected file containing the Binding Factor (BF). Mapped to RATS architecture roles, the laptop is the `Verifier`, the VM is the `Attester` and the individual developer acts effectively as the `Relying Party` (RP).

1. Developer trusts their local ECA toolchain CLI for `BF` generation
2. Developer trusts Service Provider to correctly inject `BF`/`SSH public key`
3. Developer trusts their laptop to keep `VF` confidential
4. VM proves possession of `BF`+`IF` to receive `VF`
5. VM proves possession of `BF`+`VF` to complete attestation
6. Developer has acceptable assurance to connect directly with VM

> Implementation note: Preliminary tests with a prototype CLI toolchain suggest a total attestation latency of approx. 1.5 seconds—from VM liveliness to actionable results. See [](#implementation-status) for further implementation details.

# Core Design Principles {#core-design-principles}

**Publicly Sourced Binding Factor:** The protocol is designed to use a Binding Factor (BF) that can be public information. Its security does not depend on the BF's confidentiality. This architectural choice reduces the operational burden of protecting bootstrap material and allows for flexible provisioning, such as using the digest of a public software manifest as the `BF`. Security is anchored entirely on the cryptographic proof that binds this public `BF` to the non-transmitted, measurable Instance Factor (IF).

**Deterministic Identity:** All cryptographic keys are derived deterministically from high-entropy factors, ensuring repeatable identity generation without dependence on potentially weak runtime entropy sources.

**Transport Agnostic:** The protocol's security is derived from the cryptographic content of exchanged artifacts, not the properties of the transport layer. This allows flexible deployment over any simple retrieval mechanism.

**Relationship to Static Artifact Exchange (SAE):** While ECA is a transport-agnostic protocol, the Static Artifact Exchange (SAE) [@I-D.ritz-sae] is the recommended transport mechanism for bootstrap ceremonies. SAE's static, pull-only model is intentionally minimal to reduce the overall attack surface. This approach reduces common attack surfaces like injection and parser vulnerabilities. By relying on SAE, it reinforces ECA's proof-driven design that relies solely on the cryptographic content of the exchanged artifacts to achieve its security goals, while mitigating risks particularly regarding freshness guarantees (see [](#verifier-key-compromise-impact-analysis)).

# Protocol Requirements (Normative) {#protocol-requirements-normative}

This section defines abstract properties that MUST hold for any conforming implementation. Concrete algorithms and encodings are defined by profiles (see [](#sec-profiles)).

1. **Accept-Once Ceremony**

   - Each attestation ceremony is identified by a globally unique identifier (e.g., `eca_uuid` for SAE, `certificate_request_context` for (D)TLS).
   - A Verifier MUST accept each ceremony identifier at most once and MUST treat re-observations as replay and abort. Verifiers SHOULD use a persistent store (e.g., a database or file) to track accepted ceremony identifiers for at least the expected lifetime of an Attestation Result to prevent replay.

2. **Dual-Channel Binding**

   - The protocol maintains two logically independent channels:

     - an **Attester channel** (artifacts the Attester serves), and
     - a **Verifier channel** (artifacts the Verifier serves).
   - Implementations MUST bind these channels cryptographically so that artifacts from one channel authenticate critical inputs from the other (i.e., no single channel can unilaterally complete the ceremony).

3. **Privileged Credential Vacuum**

   - Any privileged credential or capability MUST NOT be released to the Attester prior to successful appraisal by the Verifier.
   - Success is signaled only by a profile-defined positive terminal artifact; failure is signaled by a profile-defined authenticated failure artifact.

4. **Authenticated Artifacts**

   - Each phase artifact that influences appraisal MUST be integrity-protected under a key bound to ceremony inputs defined by the active profile.
   - Integrity protection MUST cover at minimum: ceremony identifier, channel role (Attester/Verifier), and a profile-defined set of claims sufficient for appraisal.

5. **Replay & Freshness**

   - Implementations MUST enforce replay resistance for phase artifacts within the ceremony lifetime.
   - Freshness semantics (e.g., timestamps or nonces) MUST be provided by the active profile and included in the authenticated data.

6. **Termination & State**

   - The Verifier MUST publish a terminal status (success or authenticated failure).
   - After terminalization, subsequent artifacts for the same ceremony identifier MUST be ignored.

7. **No Attester-Supplied Trust Pinning**

   - Verifiers MUST NOT establish trust for appraisal by pinning any CA or key material supplied by the Attester.

    > Note: The security properties of ceremony isolation depend significantly on the transport mechanism. See [](#verifier-key-compromise-impact-analysis) for transport-specific security considerations regarding Verifier key management.

8. **Transport Minimalism**

   - The protocol MUST be realizable over a static artifact repository (poll/pull) or via (D)TLS Exported Authenticators. Profiles MAY specify additional transports but MUST NOT weaken the requirements above.

# Protocol Overview {#protocol-overview}

This section specifies the **bootstrap ceremony** in detail. For re-attestation ceremony specification, see [](#re-attestation-ceremony-specification).

The bootstrap ceremony is the security-critical foundation of ECA. All formal security analysis ([](#app-formal-modelling-informative)) applies to this ceremony type. Re-attestation builds upon bootstrap security by assuming a valid initial credential.

The ECA protocol follows a three-phase ceremony for bootstrap attestation, as illustrated in the figure below. The ceremony begins with the Attester in a privileged credential vacuum, possessing only its initial factors. It concludes with the Verifier producing a signed Attestation Result (AR) upon successful validation, which can then be delivered to the Attester for presentation to Relying Parties (RP).

~~~
 BF (public): ACME acct pubkey, signed image manifest, SBOM, etc.
 IF (private): TPM/vTPM/SEV/TDX quote, enclave key.

  Attester                             Verifier
     |                                     |
     |  Evidence: prove BF (public) + IF (private)     [ECA]
     |====================================>|        [BOOTSTRAP]
     |                                     |    (Verifier issues VF
     |                                     |     only after BF+IF)
     |<------------------------------------| VF
     |                                     |
     |========= PoP with VF ==============>|
     |                                     |
     |<------------------------------------| AR/EAT (day-0 claims)
     |
  AR/EAT includes: image_digest, measurements, eca_uuid, nonce, time
~~~
    Figure 1: ECA Bootstrap Ceremony Detail

## Validation Gates {#sec-validation-gates}

The Verifier enforces a sequence of fail-closed validation gates in a specific order derived from the protocol's formal model. Each gate represents a critical check that must pass before proceeding.

### Phase 1 Appraisal Gates (Bootstrap)

1.  **MAC Verification:** Verifies the integrity of the Phase-1 payload using an HMAC tag derived from `BF` and `IF`.

       - Failure Action: Immediate termination. Publish error status `MAC_INVALID`.

2.  **Instance Authorization:** Checks if the Attester's identity (e.g., derived from ceremony identifier or IF) is authorized to proceed.

       - Failure Action: Immediate termination. Publish error status `ID_MISMATCH`.

3.  **IHB Validation:** Confirms that the received Integrity Hash Beacon (IHB) matches the expected value for the authorized instance.

       - Failure Action: Immediate termination. Publish error status `IHB_MISMATCH`.

4.  **KEM Public Key Match:** Ensures the ephemeral encryption public key in the payload matches the expected key for the session.

       - Failure Action: Immediate termination. Publish error status `KEM_MISMATCH`.

### Phase 3 Appraisal Gates (Bootstrap)

5.  **Evidence Time Window:** Validates that the `iat`, `nbf`, and `exp` claims in the final EAT are within an acceptable time skew (e.g., ±60 seconds).

       - Failure Action: Immediate termination. Publish error status `TIME_EXPIRED`.

6.  **EAT Schema Compliance:** Checks that the EAT contains all required claims with the correct types and encodings.

       - Failure Action: Immediate termination. Publish error status `SCHEMA_ERROR`.

7.  **EAT Signature:** Verifies the Ed25519 signature on the EAT using the public key derived from `BF` and `VF`.

       - Failure Action: Immediate termination. Publish error status `SIG_INVALID`.

8.  **Nonce Match:** Ensures the nonce in the EAT matches the nonce the Verifier issued in Phase 2, proving freshness.

       - Failure Action: Immediate termination. Publish error status `NONCE_MISMATCH`.

9.  **JP Validation:** Verifies the Joint Possession proof, ensuring the final identity key is bound to the ceremony context.

       - Failure Action: Immediate termination. Publish error status `KEY_BINDING_INVALID`.

10. **PoP Validation:** Verifies the final Proof-of-Possession tag, confirming the Attester's knowledge of both `BF` and `VF`.

       - Failure Action: Immediate termination. Publish error status `POP_INVALID`.

11. **Identity Uniqueness (Replay):** Persists the terminal state for the ceremony identifier and rejects any future attempts to use it.

       - Failure Action: Immediate termination. Publish error status `IDENTITY_REUSE`.

These gates align with the formal model's events (see [](#core-security-properties-baseline-model)):
- Gate 8 Nonce Match (per AttesterUsesNonce event).
- Gate 9 JP Validation (per VerifierValidatesWithKey event).
- Gate 10 PoP Validation (See [](#sec-pop)) (per VerifierAccepts event).

## Phase 1: Authenticated Channel Setup (Bootstrap) {#phase-1-authenticated-channel-setup}

- **Attester** generates an ephemeral X25519 keypair deterministically from `BF` + `IF`.
- Computes the Integrity Hash Beacon (IHB): `IHB = SHA-256(BF || IF)`.
- Publishes a CBOR payload containing `{kem_pub, ihb}` and an associated HMAC tag to the repository.
- **Verifier** retrieves the published artifacts and validates them against Gates 1-4.

## Phase 2: Challenge and Validator Factor Release (Bootstrap) {#phase-2-challenge-and-validator-factor-release}

- **Verifier** generates a fresh `VF` (≥128 bits) and a 16-byte nonce.
- Encrypts `{VF, nonce}` using HPKE to the Attester's ephemeral public key.
- Signs the encrypted payload with its Ed25519 key and publishes it to the repository.
- **Attester** retrieves the published payload, verifies its authenticity, and decrypts the `VF`.

## Phase 3: Joint Possession Proof (Bootstrap) {#phase-3-joint-possession-proof}

- **Attester** derives a final Ed25519 signing keypair deterministically from `BF`+`VF`.
- Creates a signed EAT containing identity claims, the Verifier's nonce, and a final Proof-of-Possession HMAC.
- Publishes the signed EAT to the repository.
- **Verifier** retrieves the final EAT and validates it against Gates 5-11, yielding an Attestation Result (AR) upon success.

## Key Lifecycle {#key-lifecycle}

When using SAE transport [@I-D.ritz-sae]:
- Implementations MAY use long-term or ephemeral Verifier keys
- Ephemeral per-ceremony keys are RECOMMENDED for operational best practice

When using (D)TLS transport:
- Implementations MAY use long-term or ephemeral Verifier keys
- For re-attestation, Client typically validates the Re-attestation Factor (RF) directly without separate Verifier involvement

When using other transports:
- Implementations MUST use ephemeral per-ceremony Verifier keys (see [](#with-direct-communication-transports) for rationale)

# Protocol States {#sec-states}

| State | Description |
| :------------------------ | :------------------------------------------------- |
| `INIT` | New attestation lifecycle initiated. |
| `AWAITING_ATTESTER_PROOF` | Awaiting Phase 1 artifacts. |
| `PROVING_TO_ATTESTER` | Publishing Phase 2 artifacts. |
| `AWAITING_EVIDENCE` | Awaiting Phase 3 artifacts. |
| `VALIDATING` | Appraisal of evidence. |
| `SUCCESS` | Terminal success state. |
| `FAIL` | Terminal failure state. |

## State Transitions {#sec-state-transitions}

| State | Event | Next State |
| :------------------------ | :----------------------------------------------- | :------------------------ |
| `INIT` | New attestation lifecycle. | `AWAITING_ATTESTER_PROOF` |
| `AWAITING_ATTESTER_PROOF` | Phase 1 artifacts retrieved and validated. | `PROVING_TO_ATTESTER` |
| `PROVING_TO_ATTESTER` | Phase 2 artifacts published. | `AWAITING_EVIDENCE` |
| `AWAITING_EVIDENCE` | Phase 3 artifacts retrieved. | `VALIDATING` |
| `VALIDATING` | Appraisal results pass. | `SUCCESS` |
| Any | Any validation check fails or timeout. | `FAIL` |

# Re-attestation Ceremony Specification {#re-attestation-ceremony-specification}

This section specifies the re-attestation ceremony for instances with existing credentials from prior attestation.

## Prerequisites {#re-attestation-prerequisites}

- Instance possesses Re-attestation Factor (RF): A credential from prior ECA bootstrap or re-attestation
- Verifier has record of expected identity associated with RF
- Binding Factor (BF) remains stable or is updated according to policy

## Generic Re-attestation Pattern {#generic-re-attestation-pattern}

### Single-Phase Exchange

**Attester actions:**
1. Collect current Instance Factor (IF): Fresh measurements, quotes, or state indicators
2. Construct Evidence payload: `{BF, RF, IF, ceremony_id, timestamp}`
3. Sign Evidence with key from Re-attestation Factor (RF)
4. Publish signed Evidence to Verifier

**Verifier actions:**
1. Retrieve Evidence payload
2. Validate RF signature against known credential
3. Verify RF subject matches expected identity for BF
4. Appraise IF measurements against policy
5. Confirm ceremony_id uniqueness (replay protection)
6. Emit updated Attestation Result (AR)

### Validation Gates {#re-attestation-validation-gates}

1. **RF Signature Verification**: Validates credential authenticity
   - Failure: `CREDENTIAL_INVALID`

2. **Identity Continuity**: Confirms RF subject matches expected identity
   - Failure: `IDENTITY_MISMATCH`

3. **Measurement Appraisal**: Verifies IF against policy (e.g., CoRIM)
   - Failure: `MEASUREMENT_REJECTED`

4. **Freshness Binding**: Ensures ceremony_id is unique and properly bound
   - Failure: `REPLAY_DETECTED` or `BINDING_INVALID`

5. **Timestamp Validation**: Confirms Evidence timestamp within acceptable window
   - Failure: `TIME_EXPIRED`

## Transport-Specific Implementations {#re-attestation-transport-specific}

The generic pattern above can be realized over different transports:

### Session-Bound (D)TLS Pattern

When using TLS Exported Authenticators [@?RFC9261]:

- **BF**: Server's X.509 certificate public key
- **RF**: Prior EAT from bootstrap
- **IF**: Fresh TEE Quote with ceremony_id in REPORTDATA
- **ceremony_id**: `certificate_request_context` from CertificateRequest

**Freshness**: Cryptographic binding of Quote to session context ensures per-connection freshness.

**Security**: TLS 1.3 forward secrecy + RF validation + Quote appraisal

See [](#concrete-example-continuous-tee-attestation-over-dtls) for complete example.

### Repository-Based SAE Pattern

When using Static Artifact Exchange [@?I-D.ritz-sae]:

- **BF**: Deployment manifest hash, image digest, or stable identifier
- **RF**: Prior EAT from bootstrap ceremony
- **IF**: Current measurements, runtime hashes, or provisioned secrets
- **ceremony_id**: `eca_uuid` (new unique identifier for this re-attestation)

**Freshness**: Accept-once semantics for `eca_uuid`

**Security**: RF signature + repository access control + cryptographic binding

Repository structure:
```
/<eca_uuid>/evidence.eat
/<eca_uuid>/evidence.sig
/<eca_uuid>/result.ar
/<eca_uuid>/status
```

### Custom Transport Pattern

Implementations using other transports MUST ensure:
- RF signature verification
- Ceremony identifier uniqueness (replay protection)
- IF freshness (e.g., timestamps, nonces, or context binding)
- Integrity protection of Evidence payload

## Security Properties {#re-attestation-security-properties}

Re-attestation security derives from:

1. **Bootstrap foundation**: Initial credential established via cryptographically verified bootstrap acts as Re-attestation Factor (RF)
2. **Transport security**: Channel properties (e.g., TLS 1.3 forward secrecy)
3. **Continuous appraisal**: Fresh IF measurements validated against policy
4. **Replay protection**: Ceremony identifier uniqueness enforcement

**Note**: Unlike bootstrap ceremonies, re-attestation does NOT protect against initial identity forgery. If an attacker compromises the bootstrap ceremony, they can obtain a valid `RF` and perform subsequent re-attestations. Therefore, bootstrap ceremony security (including hardware-rooted IF for zero-trust scenarios) remains critical for overall system security.

# Post-Attestation Patterns {#post-attestation-patterns}

Once the ceremony has concluded, operators can make policy decisions about how to handle the Attestation Result (AR). This may include transmitting the `AR` directly to the successful Attester so that it may present the `AR` to Relying Parties (RPs) who trust the Verifier's signature. The full scope and mechanism of presenting and accepting `AR`s to `RP`s is outside the scope of this document.

~~~
  Attester                      Verifier                       KMS/RP
     |                             |                            |
     |====== ECA CEREMONY ========>|                            |
     |<------------- AR/EAT -------|                            |
     |------------------------------ AR/EAT + request --------> |
     |                                                     eval |
     |<---------------------------------------------------------|
     |                  short-lived key / token (if policy OK)  |
     |
  Policy evaluates AR/EAT day-0 claims before issuing material.
~~~
    Figure 2: Relying Party Consumption of Attestation Result

## Credential Lifecycle {#credential-lifecycle}

Once a bootstrap ceremony concludes successfully, the Attester possesses a signed Attestation Result (AR) that serves as its renewable credential. This credential enables simplified re-attestation workflows.

**Typical Lifecycle:**

1. **Bootstrap (SAE):** Instance performs full BF+IF→VF→PoP ceremony, receives initial EAT with `eca_attester_id`

2. **Transition:** Instance establishes (D)TLS connection to service, presenting EAT as client certificate or authentication token

3. **Re-attestation ((D)TLS):** Service periodically challenges instance using BF+RF+IF pattern to verify current state

4. **Renewal:** Before credential expiration, instance performs re-attestation to receive updated AR with extended validity

**Key insight:** The `eca_attester_id` from bootstrap becomes the stable identity, while re-attestation updates only the state/measurement claims.

## Stateful Re-Attestation for Long-Running Instances {#stateful-re-attestation-for-long-running-instances}

Long-running workloads require periodic verification throughout their operational lifetime. Re-attestation ceremonies provide this capability without requiring full bootstrap interaction.

### High-Assurance Re-attestation (TEE) {#high-assurance-re-attestation-tee}

For confidential computing environments requiring hardware-backed guarantees:

**Prerequisites:**
- Instance runs in TEE with Quote capability
- Prior bootstrap established identity
- TEE measurements policy defined in CoRIM

**Ceremony:**

~~~
Client                    Server (TEE)
  |                          |
  | CertificateRequest       |
  | {context}                |
  |------------------------->|
  |                          | Generate:
  |                          |  Quote ← TEE.attest(
  |                          |    REPORTDATA=hash(context)
  |                          |  )
  |                          |
  | EAT{                     |
  |   RF: signed_AR,         |
  |   IF: Quote,             |
  |   nonce: context         |
  | }                        |
  |<-------------------------|
  |                          |
  | Verify:                  |
  |  - Quote signature       |
  |  - REPORTDATA binding    |
  |  - Measurements vs CoRIM |
  |  - RF continuity         |
~~~

**Benefits:**
- Hardware-rooted proof of current state
- Cryptographic binding to session (context)
- Standard RATS interoperability (CoRIM, CMW, AR4SI)
- Protection against platform compromise

**See [](#concrete-example-continuous-tee-attestation-over-dtls) for complete integration example.**

## Relying Party Integration {#relying-party-integration}

Relying Parties (RPs) consume Attestation Results to make authorization decisions:

~~~
Attester                Verifier                RP (KMS, Service)
  |                        |                         |
  |==== Ceremony =========>|                         |
  |<------- AR ------------|                         |
  |                                                  |
  |--------------- AR + Request -------------------->|
  |                                             Evaluate:
  |                                             - AR signature
  |                                             - Claims vs policy
  |                                             - Freshness
  |                                                   |
  |<-------------- Response (if policy OK) -----------|
~~~

**Policy examples:**
- KMS: "Release encryption key only if measurements match golden values"
- API Gateway: "Allow access only if TEE firmware version ≥ X"
- Scheduler: "Place workload only on nodes with valid attestation < 5min old"

Full scope of AR presentation and RP appraisal is outside this specification.

## Chaining and Hierarchical Trust {#chaining-and-hierarchical-trust}

ECA ceremonies can chain to propagate trust across layers:

**Pattern:** Use signed AR from one ceremony as RF for next ceremony

**Example (Bare-metal → VM):**

1. Physical host performs bootstrap with TPM-based IF (Pattern A)
   - Output: `AR_host` proving hardware integrity

2. VM on that host performs re-attestation
   - **RF:** `AR_host` (proves running on attested hardware)
   - **IF:** VM-specific measurements
   - Output: `AR_vm` proving "healthy VM on healthy host"

**Use cases:**
- Nested virtualization trust chains
- Container-on-VM attestation
- Cross-domain trust federation

Future ECA profiles may standardize chaining metadata and validation rules.

## Risks and Mitigations for Composable Deployments {#risks-and-mitigations-for-composable-deployments}

While ECA is designed to be composable (e.g., chaining attestations), realizing this benefit in large teams is expected to require significant operational discipline. Operators should be aware of the following risks:

**The "Glue Code" Trap:** The security of the overall system depends on the integrity of each link in the chain. Custom scripts or shims used to connect different attestation layers can inadvertently reintroduce the very vulnerabilities (e.g., parsing flaws, state management bugs) that SAE [@I-D.ritz-sae] is designed to eliminate. It is STRONGLY RECOMMENDED to use standardized, well-vetted integrations (e.g., official plugins for tools like Vault or SPIRE) over bespoke "glue code."

**Organizational Friction:** In multi-team environments, clear ownership of the end-to-end attestation process is critical. Without a shared governance model, configuration drift between what DevOps provisions, what Security expects, and what the application implements can lead to systemic failures.

# Transport Considerations {#transport-considerations}

The ECA protocol is transport-agnostic. Both bootstrap and re-attestation ceremonies can be deployed over any mechanism that supports:

1. Artifact exchange (publishing and retrieving cryptographic payloads)
2. Freshness guarantees (ceremony identifiers, nonces, or timestamps)
3. Immutability (artifacts cannot be modified after publication)

This section provides non-normative guidance on transport selection based on operational requirements.

## Bootstrap Ceremony Transports {#bootstrap-transports}

### SAE - Recommended for Constrained Environments

**Static Artifact Exchange (SAE)** [@I-D.ritz-sae] is RECOMMENDED for bootstrap ceremonies in:

- Environments without direct network connectivity
- Zero-trust networks with deny-all ingress/egress
- Bare-metal or alt-cloud deployments
- Air-gapped scenarios

**Characteristics**:
- Pull-only communication (no listening endpoints required)
- Repository-based artifact exchange
- Minimal attack surface (no parser vulnerabilities at transport layer)

**Security properties**: See [](#with-sae-transport-pull-only-model) for analysis of Verifier key compromise impact when using SAE.

### Other Bootstrap Transports

Implementations MAY use alternative transports for bootstrap:

- **Direct HTTP/HTTPS**: If both parties have stable endpoints
- **Message queues**: For asynchronous cloud environments
- **Custom protocols**: As required by specific deployment constraints

When using non-SAE transports, implementations MUST use ephemeral per-ceremony Verifier keys (see [](#with-direct-communication-transports)).

## Re-attestation Ceremony Transports {#re-attestation-transports}

### Session-Bound - Recommended for Interactive Services

**TLS 1.3 Exported Authenticators** [@?RFC9261] with the `cmw_attestation` extension ([@?I-D.fossati-tls-exported-attestation]) are RECOMMENDED for re-attestation in:

- Long-running TEE-based services
- Interactive client-server architectures
- Scenarios requiring per-connection freshness

**Characteristics**:
- Single round-trip re-attestation
- Cryptographic binding to TLS session context
- Forward secrecy from TLS 1.3 ECDHE

**Security properties**: TLS channel security + RF validation provides continuous verification without separate Verifier involvement.

### Repository-Based Re-attestation

Implementations MAY use SAE or similar repository-based transports for re-attestation when:

- TLS connectivity is unavailable
- Asynchronous verification is required
- Existing SAE infrastructure can be reused

**Pattern**: Simplified single-phase exchange (RF + current IF) with ceremony identifier for freshness.

### Other Re-attestation Transports

Any transport meeting the core requirements (artifact exchange, freshness, immutability) is acceptable. Examples:

- **gRPC streams**: For high-frequency health checks
- **WebSockets**: For browser-based attestation
- **Custom protocols**: For embedded or IoT scenarios

## Transport Selection Guidance {#transport-selection-guidance}

| Scenario | Bootstrap | Re-attestation |
|----------|-----------|----------------|
| **Zero-trust cloud** | SAE | (D)TLS |
| **Bare-metal** | SAE | SAE or (D)TLS |
| **TEE services** | SAE or (D)TLS | (D)TLS |
| **Air-gapped** | SAE | SAE |
| **Embedded/IoT** | Custom | Custom |

**Note**: These are recommendations, not requirements. Operators should select transports based on their specific security requirements, network topology, and operational constraints.

# Security Considerations {#security-considerations}

This section addresses security properties and considerations for ECA ceremonies.

## Security Analysis Scope {#security-analysis-scope}

The formal security analysis presented in this document (see [](#app-formal-modelling-informative)) and the cryptographic security properties verified apply specifically to the **bootstrap ceremony** in zero-trust scenarios. The bootstrap ceremony assumes no prior relationship between Attester and Verifier and must establish initial trust through cryptographic proof of factor possession.

Re-attestation ceremonies, which assume an existing credential from prior attestation, operate under different threat models and are not covered by the formal verification presented here. Security properties of re-attestation depend on:

- The security of the initial bootstrap ceremony
- The integrity of the Re-attestation Factor (RF) credential
- Transport-specific security properties (e.g., TLS 1.3 channel security for session-bound re-attestation)

Future work may extend formal analysis to re-attestation scenarios.

## Bootstrap Ceremony Security {#bootstrap-ceremony-security}

**Trust Boundaries:** Without hardware roots of trust, the security scope is limited to passive network observers rather than compromised infrastructure providers. Hardware-rooted Instance Factor Pattern A addresses this limitation. For detailed pattern specifications, see [](#instance-factor-patterns-ifp). This hardware-based protection is critical for mitigating State Reveal attacks; a formal analysis confirmed that a compromise of the Attester's software environment can expose the ephemeral decryption keys used in Phase 2, thereby compromising the ceremony's core secrets (see [](#attester-state-reveal)).

**Secrets Handling:** Derived keys are sensitive cryptographic material. Implementations MUST handle them securely in memory (e.g., using locked memory pages) and explicitly zeroize them after use.

## Re-attestation Ceremony Security {#re-attestation-ceremony-security}

Re-attestation security depends on:

1. **Initial Bootstrap Integrity**: If bootstrap is compromised, all subsequent re-attestations are invalid
2. **RF Protection**: The Re-attestation Factor credential must be protected against theft or forgery
3. **Transport Security**: Session-bound re-attestations depend on (D)TLS channel security; repository-based re-attestations depend on access control

**Key limitation**: Re-attestation CANNOT detect if initial identity was forged during bootstrap. Operators deploying re-attestation MUST ensure bootstrap ceremonies use appropriate Instance Factor Patterns (Pattern A for zero-trust environments).

## Exposure Tolerance {#exposure-tolerance}

A core design principle of this protocol is that the Binding Factor (BF) **can be public information without compromising security** during identity bootstrapping. Its value may be derived from public sources (e.g., an image digest) or appear in logs and metadata services.

This design places the entire security burden for the initial authentication on the proof of possession of the Instance Factor (IF). The protocol's security is anchored on the Attester demonstrating knowledge of the measurable `IF` in conjunction with the public `BF`. Operational risk is therefore focused on the integrity of the measurement process and the out-of-band verification channel for the `IF`, not on protecting the `BF`'s confidentiality. The "`accept-once`" policy for each ceremony identifier ensures that even if an adversary could forge a valid proof for a given `IF`, it would be useless for replaying a completed ceremony.

The operational risk is therefore focused on preventing the concurrent exposure of both `BF` and `IF`. This risk is tightly time-bounded by two key factors:

1. **The Accept-Once Policy:** The window of vulnerability is extremely short. Once a Verifier consumes a ceremony identifier and successfully completes the ceremony, the "accept-once" rule renders any stolen factors for that specific ceremony useless for future impersonation attacks.

2. **Transport Security (SAE):** When using a transport like SAE, an attacker cannot mount a meaningful impersonation attack without gaining write access to the secure artifact repository, which represents a significant and independent security boundary.

Therefore, operational hygiene should focus on protecting the end-to-end provisioning process to ensure the secrecy of the `IF` until the ceremony is complete, rather than on attempting to hide the public `BF`.

## Security Properties (Formal Model) {#security-properties-formal-model}

The protocol's security properties have been analyzed using an exploratory ProVerif model. The model positively identifies key security goals such as authentication, freshness, key binding, and confidentiality against a network attacker, assuming a public Binding Factor (BF). For a detailed summary of the formal model, its queries, and the proven properties within the models, see [](#app-formal-modelling-informative).

## Impersonation Risk {#impersonation-risk}

The security properties described in [](#security-properties-formal-model) depend on an adversary being unable to generate a valid cryptographic proof for an Instance Factor (IF) that they do not legitimately possess. An impersonation attack would require an adversary to forge a proof (e.g., a TPM quote or a signature) corresponding to a known `IF` for a specific ceremony's Binding Factor (BF). The protocol's primary defense is that the `IF` itself is never transmitted, only a proof derived from it. Therefore, operational controls MUST protect the integrity of the measurement source (e.g., the vTPM) and the out-of-band channel through which the Verifier learns the expected measurement.

To reduce this risk, operators SHOULD minimize the time window between when an Attester becomes operational with its `BF` and when a Verifier is available to appraise the Attester's evidence.

## Threat Models {#threat-models}

ECA is designed to address two key threat models: the **Network Attacker** (a Dolev-Yao-style MiTM who controls communication but not participant state) and the **Malicious Provider** (a privileged insider with control-plane access). The analysis from an exploratory ProVerif model suggests that the protocol, as modelled, defeats the Network Attacker through its Phase 1 MAC and joint possession proofs.

The choice of Instance Factor Pattern directly maps to the desired security goals:

- **IFP Patterns B and C** are sufficient to achieve **workload portability and standardization**. They protect against Network Attackers but assume the underlying infrastructure provider is trusted.

- **IFP Pattern A** is designed for **high-assurance and zero-trust environments**. By anchoring the `IF` in a hardware root of trust (HRoT), it enables strong isolation and is sufficient to mitigate the Malicious Provider threat model.

For detailed pattern specifications and implementation guidance, see [](#instance-factor-patterns-ifp).

## Attester State Compromise {#attester-state-compromise}

The formal model confirms that the protocol cannot maintain secrecy of the Validator Factor (VF) if the Attester's runtime state is compromised and the ephemeral decryption key is extracted. The confidentiality of `VF` is critically dependent on the secrecy of the Attester's ephemeral private decryption key. A formal "State Reveal" analysis was conducted, where the Attester's ephemeral private key was deliberately leaked to an attacker (see [](#attester-state-reveal)). The model confirmed that this compromise allows a passive network attacker to intercept the Phase 2 ciphertext from the Verifier and successfully decrypt it, thereby revealing the `VF`.

This result establishes the protocol's security boundary regarding the Attester's runtime state. The only viable mitigation for this threat is the use of IFP Pattern A (hardware-rooted), where the Instance Factor (IF), and by extension all keys derived from it, are protected by a hardware root of trust, making them resilient to software-level compromise.

## Verifier Key Compromise Impact Analysis {#verifier-key-compromise-impact-analysis}

The security impact of Verifier signing key compromise depends on ceremony type and transport characteristics.

### Bootstrap Ceremonies {#bootstrap-ceremonies}

**Threat:** Attacker with compromised Verifier signing key attempts to impersonate Verifier during bootstrap.

**Impact:** The formal model ([](#verifier-key-compromise)) demonstrates that cryptographic binding limits impact to denial of service:

- Attacker could inject Phase 2 messages with forged VF
- However, resulting Evidence will fail validation:
  - Wrong VF derivation → fails Gate 9 (JP Validation)
  - Wrong PoP calculation → fails Gate 10 (PoP Validation)
  - Wrong ceremony context → fails Gate 8 (Nonce Match)

**Maximum impact:** Ceremony termination without credential issuance (DoS)

**Mitigation:** The protocol's cryptographic binding ensures corrupted ceremonies produce invalid Evidence that legitimate Verifiers will reject.

### Re-attestation Ceremonies {#re-attestation-ceremonies}

**Session-Bound ((D)TLS):**

When using (D)TLS transport, re-attestation security derives from:

1. **TLS 1.3 channel security:** ECDHE provides forward secrecy
2. **RF validation:** Client verifies RF signature against known credential
3. **Context binding:** e.g., TEE Quote binds `certificate_request_context`
4. **Cryptographic gates:** Same validation logic as bootstrap

**Impact of compromised keys:** None for re-attestation, as Client validates RF directly without Verifier involvement in the critical path.

**Repository-Based (SAE):**

When using SAE for re-attestation:
- Repository access control provides ceremony isolation
- Attacker cannot inject artifacts without write access
- Corrupted Evidence fails cryptographic validation at legitimate Verifiers

**Normative guidance:**
- Long-term Verifier keys are ACCEPTABLE for all deployments
- Ephemeral per-ceremony keys remain RECOMMENDED for operational hygiene
- Security derives from cryptographic binding, not key ephemerality

See [](#verifier-key-compromise) for formal analysis details.

### With SAE Transport (Pull-Only Model) {#with-sae-transport-pull-only-model}

When using the Static Artifact Exchange (SAE) protocol [@I-D.ritz-sae]:

- Compromise of Verifier signing keys is limited to denial-of-service impact
- Attackers cannot inject forged Phase 2 artifacts without repository write access
- Evidence produced under attacker-controlled inputs will fail appraisal at legitimate Verifiers (Gates 8-10 will reject the malformed evidence)

This mitigation arises from SAE's architectural properties:
- Pull-only communication (no push channel to Attester)
- Repository-based artifact exchange with access control
- Immutability requirements preventing artifact replacement

### With Direct Communication Transports {#with-direct-communication-transports}

For implementations using direct peer-to-peer communication or push-capable transports, the formal model ([](#verifier-key-compromise)) demonstrates that:

- Long-term Verifier keys enable injection of (`VF'`, `nonce'`) pairs.
- This breaks the formal Freshness property.
- While authentication still fails (corrupted Evidence is rejected), the DoS potential justifies mandatory ephemeral keys.

Therefore, ephemeral per-ceremony keys are normatively mandated (MUST) when not using SAE [@I-D.ritz-sae] or equivalent pull-only, repository-based transports.

### Recommendation Rationale {#recommendation-rationale}

While SAE mitigates the immediate security impact of key compromise, ephemeral keys remain RECOMMENDED for all implementations because they provide:

- Ceremony isolation (compromise affects only single attestation)
- Operational hygiene through regular key rotation
- Clear security boundaries for audit and analysis
- Future-proofing against transport mechanism changes

# Non-Goals {#non-goals}

ECA explicitly does not attempt to address several related but distinct problems:

**Software-Based Mitigation of Hypervisor Threats:** ECA supports full integration with hardware roots of trust (HRoT) where available, and such integration is RECOMMENDED. ECA does not replace the need for HRoTs where the threat model must assume a compromised service provider, hypervisor or related platform, including protections against Attester state compromise (see [](#attester-state-compromise)).

**Replacement for Single-Cloud IMDS:** ECA is not intended to replace provider-native IMDS for simple workloads operating within a single, trusted cloud environment. For such use cases, IMDS provides a simpler, adequate solution. ECA's value is realized in multi-cloud, high-assurance, or non-IMDS environments.

**Infrastructure Trust Bootstrapping:** ECA assumes operational mechanisms exist for manifest distribution, verifier discovery, and PKI infrastructure. It integrates with existing trust foundations rather than replacing them.

**Identity Framework Replacement:** ECA complements rather than competes with systems like SPIFFE/SPIRE, potentially serving as a high-assurance node attestor for existing identity frameworks. For detailed integration patterns, see [](#integration-with-existing-frameworks).

**Manufacturer Provenance:** ECA does not provide supply-chain attestation or manufacturer-anchored trust. ECA handles runtime attestation for transient instances at the software layer.

**Real-time Performance Optimization:** Sub-second attestation is not a design goal. The reference implementation achieves ~1.3s protocol execution, which is acceptable for ephemeral compute bootstrap scenarios where typical VM startup times are 10-30 seconds.

# Integration with Existing Frameworks {#integration-with-existing-frameworks}

The ECA protocol is designed to complement, not replace, existing identity and attestation systems. It acts as a foundational "attestation engine" that fills specific gaps in cross-domain portability and high-assurance bootstrapping for both ephemeral and long-running workloads. Its role is to provide a verifiable, portable proof of identity that can be consumed by a wide range of higher-level identity frameworks and certificate issuance protocols, as illustrated below.

~~~
┌─────────────────┐  ┌──────────────────┐   ┌──────────────────┐
│   Ephemeral     │  │   Identity &     │  │   Certificate    │
│   Compute       │  │   Access         │  │   Authority      │
│   Environment   │  │   Management     │  │   Ecosystems     │
├─────────────────┤  ├──────────────────┤  ├──────────────────┤
│ • Cloud VMs     │  │ • SPIFFE/SPIRE   │  │ • ACME-RATS      │
│ • Containers    │◄─│ • Vault          │◄─│ • PKI            │
│ • Bare Metal    │  │ • IAM Systems    │  │ • CA/Browser     │
└─────────────────┘  └──────────────────┘  └──────────────────┘
         │                    │                       │
         └────────────────────┼───────────────────────┘
                              │
                       ┌──────▼───────┐
                       │      ECA     │
                       │  Attestation │
                       │    Engine    │
                       └──────────────┘
~~~
    Figure 3: Integration with Existing Frameworks

## Alignment with Proposed SEAL Working Group {#seal-working-group-alignment}

This specification's **re-attestation ceremony** directly implements the proposed SEAL WG charter requirements for attested (D)TLS:

| SEAL Requirement | How ECA Satisfies |
|------------------|-------------------|
| **Per-connection freshness** | `certificate_request_context` bound into TEE Quote |
| **Leverage (D)TLS 1.3** | Via RFC 9261 Exported Authenticators |
| **Leverage RATS formats** | CMW, CoRIM, AR4SI, EAT |
| **No core (D)TLS modifications** | Only `cmw_attestation` extension |
| **Mutual attestation support** | Symmetric client/server ceremonies |

The `cmw_attestation` extension from [@?I-D.fossati-tls-exported-attestation] serves as the transport mechanism for ECA **re-attestation ceremonies** over (D)TLS.

**Note**: ECA bootstrap ceremonies are typically performed over SAE before establishing (D)TLS connections. Once an instance has its initial credential, it can then use the re-attestation ceremony over (D)TLS for continuous verification.

## ECA + ACME-RATS {#eca--acme-rats}

A powerful use case for ECA is as a mechanism to satisfy the attestation challenges proposed within the ACME working group, as described in the "(ACME) rats Identifier and Challenge Type" (ACME-RATS) Internet-Draft [@I-D.liu-acme-rats]. The `ACME-RATS` specification defines an abstract challenge/response mechanism for device attestation but intentionally leaves the implementation of the attestation procedure itself out of scope. ECA can act as a bridge, providing the full three-phase ceremony—from initial bootstrap to final proof-of-possession—that an ACME client can execute to produce the verifiable Attestation Result (AR) required by the `attestation-result-01` challenge (Passport Model).

When you combine ECA with the ACME-RATS framework, you create a complete, end-to-end automated flow.

This integration approach enables a powerful vision: just as ACME enabled the automation of web server certificates and brought about ubiquitous HTTPS, the combination of ACME-RATS and ECA can enable the automated issuance of high-assurance identities to ephemeral workloads, realizing a "Let's Encrypt for Machines."

### Conceptual Integration {#conceptual-integration}

An integration of an ACME client with an ECA Attester would follow this sequence:

~~~
  Attester                      Verifier                     ACME CA
     |                             |                            |
     |====== ECA CEREMONY ========>|                            |
     |<------------- AR/EAT -------|                            |
     | newOrder/CSR                                          |
     |-------------------------------> challenge: attestation-result-01
     |  payload: AR/EAT (profile=eca-bootstrap)               |
     |-----------------------------------------------> verify AR/EAT, map
     |<----------------------------------------------- short-lived cert
     |
  Binding example: image_digest -> cert SAN URI (per CA policy).
~~~
    Figure 4: ECA Integration with ACME-RATS

1. **ACME Challenge:** The ACME client (running on the ephemeral instance) requests a certificate and receives an `attestation-result-01` challenge from the ACME server. This challenge includes a server-provided `token` (acting as a nonce for freshness) and optional `claimsHint` (e.g., required claims like `FIPS_mode` or `OS_patch_level`).

2. **ECA Initiation:** The ACME client triggers an ECA ceremony with a trusted Verifier (separate from the ACME Server). The ACME `token` is passed to the ECA Verifier to be used as (or bound to) the `vnonce` for the ceremony, ensuring freshness binding.

3. **ECA Ceremony:** The Attester (ACME client/instance) and Verifier execute the full, three-phase ECA protocol as defined in this document. If a `claimsHint` was provided, the Attester collects corresponding measurements/claims in its Evidence (e.g., EAT). The Verifier ensures the ACME `token` is included as the `nonce` claim in the final Evidence EAT (validated at Gate 8: Nonce Match).

4. **Attestation Result:** Upon successful validation (including appraisal against Verifier policy), the Verifier produces a signed Attestation Result (AR) and delivers it to the Attester (e.g., via SAE transport).

5. **ACME Response:** The ACME client wraps the signed AR in a Conceptual Message Wrapper (CMW) with `type=attestation-result` and submits it to the ACME server, completing the challenge.

6. **ACME Validation (as RP):** The ACME Server verifies the Verifier's signature on the AR (using pre-configured trust anchors), checks the `nonce` matches its issued `token`, appraises claims against policy (including any required `claimsHint`), and—if valid—issues the certificate.

### Roles and Artifacts {#roles-and-artifacts}

This section provides a conceptual, speculative composition where an ECA ceremony supplies an Attestation Result (AR) that satisfies the ACME `attestation-result-01` challenge.

**Attester:** Ephemeral instance (e.g., VM/workload) running the ACME client and ECA Attester logic. It possesses initial factors (BF + IF), collects Evidence (e.g., from TPM/TEE/platform measurer), and performs the ECA ceremony to obtain an AR.

**Evidence Source:** Implementation-specific (e.g., TPM/TEE for hardware-rooted IFP Pattern A; see [](#instance-factor-patterns-ifp)).

**Verifier:** Separate trusted entity (e.g., enterprise-operated or manufacturer-designated). Appraises Evidence against policy, issues signed AR. Trusts anchors for Evidence sources but is *not* the ACME Server.

**ACME Server (RP/RA/CA):** Issues challenges, acts as Relying Party (validates AR signature/claims/nonce), enforces policy, and finalizes certificate issuance. Pre-configured with trust anchors for one or more Verifiers.

**Inputs:** 
  - **ACME Challenge Token:** Freshness nonce; bound to ECA `vnonce`.
  - **Claims Hint** (optional): Guides Evidence collection (e.g., `FIPS_mode`, `OS_patch_level`); reflected in AR claims.

**Outputs:**
  - **Attestation Result (AR):** Verifier-signed (delivered to Attester).
  - **CMW Object:** Wraps AR (Attester → ACME Server); `type=attestation-result`, `format` = AR profile (e.g., AR4SI or EAT).

### ECA + ACME-RATS Trust Chain Sketch {#eca--acme-rats-trust-chain-sketch}

* **ACME Server** is pre-configured with trust anchors (e.g., key set or CA) for one or more Verifiers.
* **Attester** trusts its local Evidence source (e.g., HRoT) and the Verifier (via ECA's cryptographic proofs) but starts in a privileged credential vacuum—no ACME-specific creds prior to challenge completion.
* **Verifier** publishes a stable identifier (e.g., `key id`) discoverable by the ACME Server (e.g., via directory or config).
* **Freshness/Nonce Binding:** ACME `token` is bound to ECA `vnonce` (e.g., `vnonce = token` or `vnonce = SHA-256(token || eca_uuid)`), included in Evidence EAT, and reflected in AR. ACME Server checks match at validation.

## ECA in a WIMSE Architecture {#eca-in-a-wimse-architecture}

In WIMSE (Workload Identity in Multi-Cloud Secure Environments) deployments, ECA provides both bootstrap and continuous attestation:

**Deployment pattern:**
1. **Bootstrap:** Instance performs ECA/SAE ceremony, obtains initial EAT
2. **Transition:** Establishes (D)TLS to WIMSE identity service
3. **Re-attestation:** Periodic health checks using BF+RF+IF pattern
4. **Token exchange:** Presents validated EAT to receive WIMSE tokens (OAuth, SVID, etc.)

**Benefits:**
- Zero-touch provisioning in TEE environments
- Continuous attestation for long-lived workloads
- Trust domain bridging via AR chaining
- Hardware-backed identity for zero-trust architectures

### Role Mapping {#role-mapping}

When integrating ECA into a WIMSE-compliant system, the roles map as follows:

| ECA Role | WIMSE Role | Description |
| :--- | :--- | :--- |
| **Attester** | **Workload** | The ephemeral compute instance requiring identity. |
| **Verifier** | **Identity or Attestation Service** | The entity within the trust domain that validates the workload's claims. |
| **Relying Party** | **Service Consumer or Authorization Service** | An entity that consumes the Attestation Result to make an authorization decision. |

### Workflow Integration {#workflow-integration}

ECA's primary function in a WIMSE workflow is to produce the initial, high-assurance credential.

1.  A **Workload** (Attester) executes the ECA ceremony upon boot.
2.  The **Attestation Service** (Verifier) validates the claims and issues an Attestation Result (AR).
3.  This AR serves as a secure, short-lived **initial workload credential**.
4.  The Workload can then exchange this AR with a WIMSE **Identity Service** to obtain longer-lived runtime credentials (e.g., SVIDs, OAuth tokens) for interacting with other services.

### WIMSE Terminology Alignment {#wimse-terminology-alignment}

To align with WIMSE concepts, ECA's components can be framed as follows:

-   **Trust Domain**: The security boundary defined by the Verifier's trust anchors and policies.
-   **Attestation Scope Token / Provisioning Context**: The public **Binding Factor (BF)**, which scopes the attestation ceremony to a specific provisioning event.
-   **Workload Identity Roots**: The private **Instance Factor (IF)** patterns, which anchor the workload's identity in hardware (Pattern A), an orchestrator (Pattern B), or an artifact (Pattern C).

## The SPIFFE/SPIRE Framework {#the-spiffespire-framework}

SPIFFE/SPIRE provides a robust framework for issuing short-lived cryptographic identities (SVIDs) to workloads, enabling zero-trust authentication in distributed systems. While SPIFFE/SPIRE addresses "secret zero" in many scenarios through platform-specific node attestors (e.g., AWS EC2 or Kubernetes), it relies on extensible plugins for custom environments which is a natural fit for an ECA plugin implementation. SPIFFE/SPIRE is a CNCF-graduated community standard rather than an IETF standard.

~~~
  Attester                      Verifier                 SPIRE Server
     |                             |                           |
     |====== ECA CEREMONY ========>|                           |
     |<------------- AR/EAT -------|                           |
     |-------------------------------------------------------> |
     |         node attestor input = AR/EAT (eca-bootstrap)    |
     |<------------------------------------------------------- |
     |                    SVID (mTLS/JWT) bound to claims      |
     |
  Example bindings: image_digest, attested_at, environment tags.
~~~
    Figure 5: ECA as a Node Attestor for SPIFFE/SPIRE

**What ECA/SAE adds:** ECA defines an exposure-tolerant, accept-once bootstrap that binds artifacts across dual channels and emits standardized EAT-based evidence and Attestation Results (AR). SAE provides a pull-only, static-artifact transport that works in heterogeneous or constrained networks. These properties make ECA a good fit as a high-assurance *node* attestor feeding SPIRE, without changing SPIFFE's SVID/workload APIs.

**Integration surface (SPIRE):** SPIRE supports authoring custom plugins via its extension points, including node-attestors. Prior work integrates TPM-/IMA-based attestation via Keylime, illustrating the "hardware- or higher-assurance attestor" pattern that ECA can follow.

**Operational intent:** ECA does not replace SPIFFE/SPIRE. It *precedes* or *augments* SPIRE node admission where provider metadata is weak, join-token operations are costly, or transports are constrained. After ECA succeeds, SPIRE issues SVIDs and federates as usual.

> *Terminology note.* In SPIRE, node-attestor plugins expose **selectors** (key-value attributes used in SPIRE's policy engine) that registration policies can match. In the ECA→SPIRE mapping, fields from ECA's EAT/AR (e.g., `eca_uuid`, EUID, JP/PoP artifacts, integrity beacons) naturally become such selectors. *SPIRE selector/registration context:* [[SPIRE-CONCEPTS](#ext-links)]

```
# Example of SPIRE registration entry using ECA-derived selectors
spire-server entry create -spiffeID "spiffe://example.org/my-service" \
  -parentID "spiffe://example.org/spire/agent/eca/<verifier_id>" \
  -selector "eca:euid:a1b2c3d4..." \
  -selector "eca:ihb:e5f6g7h8..."
```

Complementary deployment patterns:

**Alt-cloud / bare-metal without signed metadata:**
 
* *Today:* defaults to join tokens or bespoke attestors where robust, signed instance identity is absent.
* *ECA integration:* implement ECA as a node-attestor plugin; ECA's EAT/AR fields (e.g., EUID, IHB, PoP, nonces) become SPIRE selectors for registration, then SPIRE issues SVIDs.

**High-assurance with HRoT (Confidential/edge):** 

* *Today:* SPIRE can leverage TPM/IMA via Keylime but still depends on environment-specific control planes.
* *ECA integration:* ECA Pattern A binds identity to HRoT and proves joint possession via SAE; SPIRE consumes the AR to gate SVID issuance.
* *Keylime integrations:* [[KEYLIME-SPIRE-PLUGIN](#ext-links)], [[REDHAT-KEYLIME-SPIRE](#ext-links)]; *SPIRE plugin surface:* [[SPIRE-EXTENDING](#ext-links)], [[SPIRE-PLUGIN-SDK](#ext-links)]

**Dynamic multi-cluster aliasing/federation:** 

* *Today:* coordinating join tokens and node aliases across domains can be operationally heavy.
* *ECA integration:* selectors derived from ECA's EAT/AR (e.g., `eca_uuid`, EUID, JP) provide portable, verifiable bindings without maintaining a separate join-token database.

**Standards position:** SPIFFE/SPIRE are CNCF community standards; ECA/SAE are IETF Internet-Drafts. This document positions ECA to *interoperate with* SPIFFE/SPIRE—augmenting bootstrap where needed—rather than to replace them. *(Status/background:* [[CNCF-GRADUATION](#ext-links)], [[SPIFFE-OVERVIEW](#ext-links)].)

## BRSKI (Bootstrapping Remote Secure Key Infrastructure) {#brski-bootstrapping-remote-secure-key-infrastructure}

BRSKI [@?RFC8995] solves *manufacturer-anchored onboarding* for physical devices that ship with an IEEE 802.1AR IDevID and a manufacturer voucher service (MASA). ECA targets *ephemeral compute* (VMs, containers) that typically lack such an identity.

The mechanisms are complementary: **BRSKI** is for day-0 hardware onboarding based on supply-chain provenance, while ECA is for just-in-time software and instance attestation at runtime. An operator could use BRSKI to securely enroll a physical device into their network, and then use ECA as a subsequent, continuous attestation check to validate the software state running on that device before releasing application-level privileges.

## Summary of Integration Benefits {#summary-of-integration-benefits}

Adopting ECA as a foundational attestation engine provides several key benefits:

* **Standards-Based:** Built on emerging and established IETF standards like RATS, EAT, and ACME.
* **Portable:** The protocol's transport-agnostic design works across cloud, on-premise, and edge environments.
* **Composable:** Can be layered with existing systems like SPIFFE/SPIRE to enhance their security posture.
* **High-Assurance:** Supports hardware roots of trust (`IFP Pattern A`) for zero-trust environments.
* **Automation-Friendly:** Designed from the ground up for ephemeral, dynamic, and automated infrastructures.
* **Continuous Verification:** Supports both initial bootstrap and ongoing re-attestation throughout workload lifecycle.

# Operational Considerations {#operational-considerations}

**Scalability:** The use of a simple artifact repository allows for high scalability using standard web infrastructure like CDNs and object storage.

**Time Synchronization:** Reasonably synchronized time is REQUIRED for proper validation of the `nbf` and `exp` time windows (Gate 5 skew tolerance: ±60s). The use of a time synchronization protocol like NTP [@?RFC5905] is RECOMMENDED. Polling MUST use exponential backoff with jitter.

**Addressing Complexity:** The multi-phase design of ECA is intentionally confined to the infrastructure layer to provide a simple and secure operational experience. ECA's cryptographic machinery is expected to be abstracted away from the end-user. The prototype implementation demonstrates this, executing a complete, parallel attestation with a single command (e.g., `eca-toolchain attest --manifest ./manifest.yml`), similar to how a sophisticated suite of standards (SMTP, DKIM, etc.) underpins a simple email "send" button.

## Provisioning and Repository Access {#provisioning-and-repository-access}

The ECA protocol requires the Attester to publish artifacts while adhering to the **Privileged Credential Vacuum** design principle (see [](#core-design-principles)). This is achievable using standard cloud primitives that grant ephemeral, narrowly-scoped write capabilities without provisioning long-term secrets. Common patterns include the control plane injecting a time-limited pre-signed URL (e.g., for Amazon S3 or GCS) or a short-lived, scoped OAuth2 token for the instance to use. In this model, the Attester is granted the temporary *capability* to write to its specific repository path, fulfilling the protocol's needs without violating the zero-trust principle of verify-then-trust. Verifiers MUST NOT rely on any CA or key material delivered by the Attester for appraisal trust establishment. This reinforces the requirement in [](#protocol-requirements-normative).

# IANA Considerations {#iana-considerations}

TODO IANA

# Implementation Status {#implementation-status}

An end-to-end happy-path implementation of the bootstrap profile is publicly available at [[ECA-SAE-PROTOTYPE](#ext-links)], demonstrating complete identity bootstrap functionality including:

**Protocol Coverage:**
- Three-phase attestation ceremony with all validation gates
- HPKE-based VF delivery with AAD binding  
- COSE_Sign1 Evidence generation and verification
- Replay protection via persistent UUID tracking
- SAE transport with pull-only artifact exchange

**Performance (Docker-based deployment):**
- Protocol execution: 1.3s (Phase 1-3)
- Total attestation: ~6s (including container startup)
- Parallel sessions: 3+ concurrent attestations validated

**Security Features:**
- Fixed-size padding (2048 bytes) for side-channel mitigation
- Domain-separated HKDF key derivation
- Constant-time cryptographic comparisons
- HMAC-authenticated error codes

**Deployment Model:**
- Docker Compose orchestration
- Isolated attester/verifier containers
- Mock S3 for artifact repository
- Comprehensive error classification

| Metric | Value | Notes |
|--------|-------|-------|
| Protocol Execution | ~1.3s | Phases 1-3, excluding infra |
| Full Attestation (incl. containers) | ~6s | Parallel runs, randomized mode |
| Scalability | 3 concurrent | No failures observed |

# Acknowledgments {#acknowledgments}

The design of this protocol was heavily influenced by the simplicity and security goals of the age file encryption tool. The protocol's core cryptographic mechanisms would not be as simple or robust without the prior work of the IETF community in standardizing modern primitives, particularly Hybrid Public Key Encryption (HPKE) in [@?RFC9180].

The integration with Exported Authenticators draws from [@?I-D.fossati-tls-exported-attestation].

The SEAL Working Group charter and Confidential Computing Consortium Attestation SIG provided the use case requirements that shaped the re-attestation model.

The authors wish to thank the contributors of these foundational standards for making this work possible.

# External Links {#ext-links}

**[AGE]**

: Valsorda, F. and Cartwright-Cox, B., "The age encryption specification", <https://age-encryption.org/v1>, February 2022.

**[ECA-FORMAL-MODELS]**

: "ECA ProVerif Formal Models", <https://github.com/eca-sae/internet-drafts-eca-sae/blob/pv0.3.0/formal-model/>, September 2025.

**[ECA-SAE-PROTOTYPE]**

: "OSS MTI prototype for the ECA & SAE Internet-Drafts", <https://github.com/eca-sae/prototype-eca-sae/tree/proto-0.1.0>, September 2025.

**[SPIFFE-CONCEPTS]**

: CNCF SPIFFE Project, "SPIFFE Concepts (SVID, Workload API)", <https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/>, January 2025.

**[SPIFFE-OVERVIEW]**

: CNCF SPIFFE Project, "SPIFFE Overview", <https://spiffe.io/docs/latest/spiffe-about/overview/>, January 2025.

**[SPIRE-EXTENDING]**

: CNCF SPIRE Project, "Extending SPIRE (Authoring Plugins)", <https://spiffe.io/docs/latest/planning/extending/>, January 2025.

**[SPIRE-PLUGIN-SDK]**

: CNCF SPIRE Project, "SPIRE Plugin SDK (service definitions and stubs)", <https://github.com/spiffe/spire-plugin-sdk>, August 2025.

**[CNCF-GRADUATION]**

: Cloud Native Computing Foundation, "SPIFFE and SPIRE Projects Graduate from CNCF Incubator", <https://www.cncf.io/announcements/2022/09/20/spiffe-and-spire-projects-graduate-from-cloud-native-computing-foundation-incubator/>, September 2022.

**[KEYLIME-SPIRE-PLUGIN]**

: Keylime Project, "Keylime SPIRE Agent Plugin (TPM/IMA attestation integration)", <https://github.com/keylime/spire-keylime-plugin>, January 2025.

**[REDHAT-KEYLIME-SPIRE]**

: Red Hat (Emerging Tech), "SPIFFE/SPIRE and Keylime: Software identity based on secure machine state", <https://next.redhat.com/2025/01/24/spiffe-spire-and-keylime-software-identity-based-on-secure-machine-state/>, January 2025.

{backmatter}

# Formal Modelling (Informative) {#app-formal-modelling-informative}

This appendix presents formal security analysis of the **ECA bootstrap ceremony** using ProVerif [[ECA-FORMAL-MODELS](#ext-links)]. The analysis assumes a powerful Dolev-Yao network attacker and verifies core security properties.

**Scope limitation**: This analysis covers ONLY bootstrap ceremonies. Re-attestation ceremonies operate under different trust assumptions (existing credential from prior attestation) and are not modeled here. Future work may extend formal analysis to re-attestation scenarios.

The protocol's bootstrap security properties were analyzed using an exploratory formal model in ProVerif. The model assumes a powerful Dolev-Yao network attacker who can intercept, modify, and inject messages. It also correctly models the Binding Factor (`BF`) as public knowledge from the start, as per the protocol's "exposure tolerance" principle ([](#core-design-principles)).

The analysis was conducted in two parts: verification of the core security properties against a network attacker, and an analysis of the protocol's behavior under specific key compromise scenarios to define its security boundaries.

## Core Security Properties (Baseline Model) {#core-security-properties-baseline-model}

In the baseline model, all core security goals were successfully shown to hold against a network attacker.

| Property | ProVerif Query | Result | Interpretation |
| :--- | :--- | :--- | :--- |
| **Authentication** | `inj-event(VerifierAccepts(...)) ==> inj-event(AttesterInitiates(...))` | **True** | The Verifier only accepts an attestation if a unique Attester legitimately initiated it. This prevents an attacker from impersonating the Attester. |
| **Freshness** | `event(AttesterUsesNonce(n)) ==> event(VerifierGeneratesNonce(n))` | **True** | The Attester will only use a nonce that was genuinely generated by the Verifier for that ceremony. This property is the basis for **Gate 8 (Nonce Match)** and prevents replay attacks. |
| **Key Binding** | `event(VerifierValidatesWithKey(pk)) ==> event(AttesterPresentsKey(pk))` | **True** | The final identity key that the Verifier checks is unambiguously bound to the Attester that participated in the ceremony, validating **Gate 9 (JP Validation)**. |
| **Confidentiality** | `not (event(VFReleased(vf)) && attacker(vf))` | **True** | The secret `ValidatorFactor` (`VF`) is never revealed to a network attacker, satisfying a fundamental security goal of the protocol. |

## Boundary Analysis (Advanced Threat Models) {#boundary-analysis-advanced-threat-models}

Additional tests were performed to formally define the protocol's security boundaries under specific compromise scenarios.

### Key Compromise Impersonation (KCI) {#key-compromise-impersonation-kci}

A test was conducted where an attacker compromises an `InstanceFactor` (`IF`) from one ceremony and attempts to impersonate a Verifier in a different ceremony. The model indicated this attack is not possible. The KCI security query passed, confirming that compromising a secondary factor (`IF`) does not allow an attacker to forge messages from a primary party (the Verifier), as they still lack the Verifier's private signing key.

### Verifier Key Compromise {#verifier-key-compromise}

A test was conducted modeling a compromised long-term Verifier signing key:

- **Result:** The model demonstrated that an attacker can inject arbitrary (VF', nonce') pairs, breaking the Freshness property (`event(AttesterUsesNonce(n)) ==> event(VerifierGeneratesNonce(n))` was **False**).

- **Interpretation:** While the formal model identifies a freshness violation, the protocol's cryptographic design ensures this only enables denial of service, not authentication bypass:

- The attacker can cause the Attester to derive keys from (`BF`, `VF'`)
- However, the resulting Evidence will contain:
  - Wrong nonce (fails Gate 8)
  - Wrong JP proof (fails Gate 9)
  - Wrong PoP tag (fails Gate 10)
  - No correctly implemented Verifier should accept this Evidence

Furthermore, when using SAE transport [@I-D.ritz-sae], even this DoS attack becomes infeasible without repository write access, as noted in [](#with-sae-transport-pull-only-model).

- **Mitigation:** This analysis provides the formal rationale for:
  - the requirement in [](#with-direct-communication-transports) for ephemeral keys with push-capable transports
  - the relaxed guidance in [](#with-sae-transport-pull-only-model) when using SAE transport

### Attester State Reveal {#attester-state-reveal}

A test was conducted modeling a compromised Attester whose ephemeral private decryption key is leaked:

- **Result:** The model demonstrated that this allows a passive attacker to decrypt the Phase 2 ciphertext and steal the `ValidatorFactor` (`VF`) (`not (event(VFReleased(vf)) && attacker(vf))` was **False**).

- **Interpretation:** This result formally establishes the security boundary discussed in [](#attester-state-compromise)

- **Mitigation:** This analysis provides the formal rationale for hardware-rooted Instance Factor Pattern A when the threat model must assume compromise of the underlying provisioning platform. For pattern specifications, see [](#instance-factor-patterns-ifp).

# Concrete Example: Continuous TEE Attestation over (D)TLS {#concrete-example-continuous-tee-attestation-over-dtls}

This appendix provides a complete example of re-attestation for a long-running TEE workload using (D)TLS Exported Authenticators, integrating the work established by Fossati et al. [@?I-D.fossati-tls-exported-attestation].

## Scenario {#scenario}

We consider Server as Attester.
- Client establishes initial TLS 1.3 connection to TEE-based service
- Service performed bootstrap via ECA/SAE during provisioning
- Client needs to verify TEE health before processing sensitive data
- Service presents current measurements via re-attestation

## Message Flow {#message-flow}

~~~
Client                              Server (TEE)
  |                                      |
  | TLS 1.3 Handshake                    |
  |<------------------------------------>|
  |                                      |
  | ClientCertificateRequest             |
  | {                                    |
  |   context: random_32_bytes,          |
  |   extensions: [cmw_attestation]      |
  | }                                    |
  |------------------------------------->|
  |                                      |
  |                         Generate TEE Quote:
  |                  REPORTDATA = hash(context)
  |                                      |
  | Authenticator                        |
  | {                                    |
  |   Certificate,                       |
  |   cmw_attestation: {                 |
  |     RF: signed_EAT_from_bootstrap,   |
  |     IF: TEE_Quote,                   |
  |     timestamp: current_time          |
  |   },                                 |
  |   CertificateVerify,                 |
  |   Finished                           |
  | }                                    |
  |<-------------------------------------|
  |                                      |
  |  Validate:                           |
  |  - RF signature against known cert   |
  |  - Quote signature vs manuf. key     |
  |  - REPORTDATA binding to context     |
  |  - Measurements against CoRIM policy |
  |  - Timestamp freshness               |
  |                                      |
  | [Continue with application data]     |
~~~

## Validation Details {#validation-details}

**RF Verification:**
- Extract public key from bootstrap EAT
- Verify signature on current Evidence
- Check EAT not expired

**IF (TEE Quote) Verification:**
- Verify Quote signature against TEE manufacturer key
- Confirm `REPORTDATA = SHA-256(certificate_request_context)`
- Appraise measurements against expected values (CoRIM)
- Validate TCB version meets minimum requirements

**Context Binding:**
- Ensures Quote was generated specifically for this request
- Prevents replay of old Quotes across sessions

# Change log

## Changes since -00

This revision represents a significant architectural evolution of the ECA protocol based on deeper understanding of the existing Attestation landscape. The scope has been expanded from a single bootstrap ceremony to a comprehensive attestation pattern.

### Major Architectural Changes

* **Dual-Ceremony Model:** The protocol is no longer a single three-phase ceremony. It now defines two distinct but related ceremonies:
    1.  **Bootstrap Ceremony:** For initial "cold start" identity establishment in environments without existing credentials.
    2.  **Re-attestation Ceremony:** A lightweight, single round-trip ceremony for continuous verification of an established identity, ideal for long-running workloads and TEEs.

* **New Session-Bound Deployment Model:** A primary deployment model using **(D)TLS Exported Authenticators** has been introduced. This aligns the protocol with the **SEAL WG charter** and directly supports continuous attestation for Trusted Execution Environments (TEEs).

* **Consolidation of Implementation Guide:** Key concepts from the separate implementation guide (`draft-ritz-eca-impl-00`) have been merged into this core specification for clarity and completeness. This includes:
    * **Instance Factor Patterns (IFP):** The Hardware-Rooted (A), Orchestrator-Provisioned (B), and Artifact-Based (C) patterns are now formally part of the core draft.
    * **Reference Profile and Examples:** A concrete reference profile (`ECA-VM-BOOTSTRAP-V1`) and a detailed (D)TLS example have been included as appendices.
    * **Implementation Status:** The section detailing the prototype's status is now included.

### Scope and Terminology Refinements

* **Protocol Renaming:** The draft is now titled **"Entity and Compute Attestation"** (formerly "Ephemeral Compute Attestation") to reflect its broadened applicability to both ephemeral and long-running entities.
* **New Terminology:** Introduced new core terms to support the dual-ceremony model, most notably the **Re-attestation Factor (RF)**, which is the credential used to prove identity continuity in re-attestation ceremonies. The roles of **Binding Factor (BF)** and **Instance Factor (IF)** have been clarified for each ceremony type.

### Expanded Integration and Use Cases

* **WIMSE and SEAL Alignment:** The document now explicitly maps ECA roles and concepts to the **WIMSE (Workload Identity in Multi-Cloud Secure Environments)** architecture and details its alignment with the proposed **SEAL (Secure Evidence and Attestation Layer)** working group's goals.
* **Post-Attestation Patterns:** Added a new section that describes the credential lifecycle, stateful re-attestation, and patterns for chaining attestations to build hierarchical trust.

### Editorial Changes

* Added **Muhammad Usama Sardar** as a co-author.
* Restructured the document significantly to introduce the conceptual model and deployment patterns upfront.
* Updated the formal model analysis in the appendix to reflect the protocol's evolution and provide clearer interpretations of the security boundary tests.
