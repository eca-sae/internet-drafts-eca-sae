%%%
title = "Ephemeral Compute Attestation (ECA) Protocol"
abbrev = "ECA"
category = "exp"
docname = "draft-ritz-eca-01"
date = "2025-09-30T00:00:00Z"
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

This document specifies the Ephemeral Compute Attestation (ECA) protocol, which enables ephemeral compute instances to prove their identity without pre-shared operational credentials. ECA uses a three-phase ceremony that cryptographically combines a public Boot Factor (a high-entropy provisioning value), a secret Instance Factor, and a dynamically released Validator Factor to establish attestation evidence. The protocol is transport-agnostic and produces Entity Attestation Tokens (EAT) for consumption by Relying Parties, such as within automated certificate issuance protocols. 

{mainmatter}

# Scope {#scope}

ECA profiles the RATS [@!RFC9334] "passport model". It assumes familiarity with the roles defined in the RATS architecture. This document includes security considerations, implementation guidance, deployment patterns, and integration considerations for deploying ECA across diverse compute environments from cloud VMs to bare-metal systems.

# Problem Statement and Motivation {#scope-problem-statement-and-motivation}

Modern software architecture increasingly relies on ephemeral compute instances, which require a secure and reliable method to bootstrap their identity upon creation. While solutions exist for this problem, they are often tied to a specific vendor's ecosystem or lack the robustness required for certain environments. This creates significant challenges for portability, security, and operational consistency across diverse computing landscapes.

## The Provider-Native Identity Dilemma {#the-provider-native-identity-dilemma}

Hyperscale cloud providers (e.g., AWS, GCP, Azure) offer Instance Metadata Services (IMDS) that can provide a cryptographically signed token attesting to an instance's identity. This is a mature model for applications developed to run within a single provider's environment. However, IMDS typically relies on HTTP-based access within the instance's network, which can introduce latency in high-throughput scenarios and requires instances to trust the provider's metadata endpoint.

## Limitations of the Current Landscape {#limitations-of-the-current-landscape}

Despite the success of provider-native solutions, their approach creates a new set of challenges in a world that is increasingly multi-cloud and security-conscious.

### Vendor Lock-In and Portability {#vendor-lock-in-and-portability}

Workloads are now frequently designed to be portable across different providers, but their identity bootstrapping mechanisms are not. An application architected to use the AWS Instance Identity Document cannot be moved to GCP, a private cloud, or a bare-metal server without significant re-engineering of its security and trust establishment logic. This friction couples a workload's identity to its location, undermining the core goal of portability.

### The Trust Gap in High-Assurance Environments {#the-trust-gap-in-high-assurance-environments}

Provider-native identity mechanisms fundamentally require that the cloud provider itself is a trusted entity. The identity token is issued by the provider's infrastructure and its validity rests on that trust. However, in Confidential Computing and other zero-trust scenarios, the threat model must include a potentially malicious or compromised provider. AMD SEV or Intel TDX, for instance, offer memory encryption and remote attestation, but their reports are tied to specific hardware generations, complicating migration across diverse fleets. In these cases, an identity token issued by the infrastructure is insufficient; trust must be anchored in a separate, verifiable source, such as a hardware root of trust (HRoT). TPM-based systems, such as those in TCG specifications, provide measured boot integrity but often require platform-specific endorsement keys, limiting interoperability in hybrid setups.

### Inconsistency in "Alt-Cloud" and On-Premise Environments {#inconsistency-in-alt-cloud-and-on-premise-environments}

For the vast ecosystem of smaller cloud providers, private clouds, and on-premise data centers, a standardized IMDS-like service does not exist. This forces operators into less secure or bespoke bootstrapping patterns, such as injecting pre-shared secrets via user-data. While a practical starting point, this approach re-introduces TOFU risks and creates a broad exposure surface for secrets in logs, state files, and metadata services, compounding operational complexity at scale. Traditional TOFU, as seen in SSH key exchanges, assumes initial connections are secure but can fail in automated deployments where instances are spun up frequently without human oversight. For example, in systems like Kubernetes or OpenStack, user-data injection requires careful configuration management to prevent accidental exposure during cluster scaling or migrations. For concrete patterns addressing these risks, see [](#instance-factor-patterns-ifp).

## ECA: An Alternative Approach {#eca-an-alternative-approach}

The Ephemeral Compute Attestation (ECA) protocol is designed to address these limitations directly. It provides a single, open standard that:

- **Decouples Identity from Infrastructure:** ECA establishes instance identity through a transport-agnostic protocol, facilitating portability of workloads across environments.

- **Supports Trust Anchoring:** ECA's design, allows trust to be anchored by a hardware root of trust (HRoT), providing cryptographic proof of identity that remains effective even if the underlying provider is untrusted.

- **Provides a Standard for Various Environments:** ECA offers a standardized bootstrapping mechanism for on-premise, bare-metal, and "alt-cloud" deployments that lack a native identity service.

ECA approaches the bootstrapping problem as a cryptographic challenge based on verifiable proof of factor possession, independent of location.

> **Working with Existing Frameworks:** ECA design focus was to complement, not replace, existing identity and attestation frameworks. For detailed exploration of how ECA integrates with ACME, BRSKI, SPIFFE/SPIRE, and other systems, see [](#integration-with-existing-frameworks).

# Conventions and Definitions {#conventions-and-definitions}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [@!RFC2119] [@!RFC8174] when, and only when, they appear in all capitals, as shown here.

**Boot Factor (BF):** An exposure-tolerant, high-entropy value (≥128 bits) provisioned during instance creation. The `BF` value acts as a public challenge token; the protocol security is maintained even if `BF` may be exposed in logs or metadata.

**Instance Factor (IF):** A per-instance secret value, known only to the Attester and the Verifier, that is never transmitted over the public channel. The Attester must prove possession of the `IF` in conjunction with the `BF` to authenticate. It may be hardware-derived, orchestrator-provided, or artifact-based. For concrete patterns and implementation guidance, see [](#instance-factor-patterns-ifp).

**Validator Factor (VF):** A confidential value generated and released by the Verifier only after successful initial authentication of `BF`+`IF` possession. **The VF MUST be bound to the IF** (e.g., `VF = SHA-256(seed || IF)`). This binding ensures `VF` secrecy against network attackers, as noted in the formal model (see [](#core-security-properties-baseline-model)).

**Joint Possession:** The cryptographic property where security derives from proving knowledge of multiple factors (`BF`+`VF`) rather than secrecy of individual components.

**Integrity Hash Beacon (IHB):** A SHA-256 binding of `BF` to `IF` that enables exposure-tolerant authentication while preventing pre-computation attacks.

**Instance Factor Pattern (IFP):** The set of defined methods for sourcing the secret value for Instance Factor (`IF`). Three patterns are defined: hardware-rooted (Pattern A), orchestrator-provisioned (Pattern B), and artifact-based (Pattern C). For detailed specifications, see [](#instance-factor-patterns-ifp).

**Entity Attestation Token (EAT):** A standardized token format [@!RFC9711] used to convey attestation evidence in a cryptographically verifiable form.

**Exchange Identifier (eca_uuid):** A unique identifier for each attestation lifecycle instance, used to construct artifact repository paths and prevent replay attacks.

**Artifact Repository:** A simple, addressable store (e.g., a web server, an object store) where peers can publish and retrieve cryptographic artifacts.

**Attestation Ceremony ("ceremony"):** The RATS architecture [@!RFC9334] refers to the exchange between participants as "attestation procedures." This document uses "Attestation Ceremony" (or "ceremony") synonymously to describe the complete, multi-phase sequence of cryptographic exchanges required for an attestation. The term "ceremony" is used conventionally throughout this specification.

# Instance Factor Patterns (IFP) {#instance-factor-patterns-ifp}

ECA supports full integration with hardware roots of trust (HRoT) where available, and such integration is RECOMMENDED. ECA does not replace the need for HRoTs where the threat model must assume a compromised service provider, hypervisor or related platform risks.

The choice of IFP pattern determines the source of the `IF` and the strength of the resulting security guarantee. The security of the ECA protocol's initial phase depends on the Attester proving possession of this secret `IF`, which is bound to the public **Boot Factor (`BF`)**.

The three defined patterns are:

**IFP Pattern A (Hardware-Rooted):** The `IF` is a secret value derived from a hardware root of trust (HRoT), such as a vTPM or TEE. This pattern provides the highest level of security, as it can mitigate threats from a compromised provider.

**IFP Pattern B (Orchestrator-Provisioned):** The `IF` is a secret provided by a trusted orchestrator through a secure channel, like instance metadata. This approach protects against network attackers but assumes the infrastructure provider is trusted.

* **IFP Pattern C (Artifact-Based):** The `IF` is the entire content of a larger provisioned file (e.g., an `authorized_keys` file) that also contains the `BF`. This pattern is designed to address Trust-on-First-Use (TOFU) vulnerabilities in constrained environments.

## Minimal Deployment and Trust Chain Sketch (Pattern C) {#minimal-deployment-and-trust-chain-sketch-pattern-c}

This section illustrates how ECA can be used even at a small, human-driven scale—such as by an individual developer—to provide cryptographic assurance for ephemeral instances without requiring complex infrastructure or hardware roots of trust, using `IFP Pattern C`. For security considerations with this pattern, see [](#impersonation-risk).

In this sketch, the Instance Factor (IF) is an artifact-based secret such as the full content of an injected file containing the Boot Factor (BF). Mapped to RATS architecture roles, the laptop is the `Verifier`, the VM is the `Attester` and the individual developer acts effectively as the `Relying Party` (RP).

1. Developer trusts their local ECA toolchain CLI for `BF` generation
2. Developer trusts Service Provider to correctly inject `BF`/`SSH public key`
3. Developer trusts their laptop to keep `VF` confidential
4. VM proves possession of `BF`+`IF` to receive `VF`
5. VM proves possession of `BF`+`VF` to complete attestation
6. Developer has acceptable assurance to connect directly with VM

> Implementation note: Preliminary tests with a prototype CLI toolchain suggest a total attestation latency of approx. 1.5 seconds—from VM liveliness to actionable results. See [](#implementation-status) for further implementation details.

# Core Design Principles {#core-design-principles}

**Exposure Tolerance:** Protocol security is maintained even if the Boot Factor becomes public. This reduces the operational burden of protecting bootstrap secrets in logs, configuration systems, or during provisioning.

**Deterministic Identity:** All cryptographic keys are derived deterministically from high-entropy factors, ensuring repeatable identity generation without dependence on potentially weak runtime entropy sources.

**Transport Agnostic:** The protocol's security is derived from the cryptographic content of exchanged artifacts, not the properties of the transport layer. This allows flexible deployment over any simple retrieval mechanism.

**Relationship to Static Artifact Exchange (SAE):** While ECA is a transport-agnostic protocol, the Static Artifact Exchange (SAE) [@I-D.ritz-sae] is the recommended transport mechanism. SAE's static, pull-only model is intentionally minimal to reduce the overall attack surface. This approach reducing common attack surfaces like injection and parser vulnerabilities. By relying on SAE, it re-inforces ECA's proof-driven design that relies solely from the cryptographic content of the exchanged artifacts to achieve its security goals, while mitigating risks particularly regarding freshness guarantees (see [](#verifier-key-compromise)).

**Privileged Credential Vacuum:** The Attester begins its lifecycle with no privileged operational credentials (e.g., API keys, service tokens, or passwords). This operationalizes a "verify-then-trust" model, ensuring that trust is never assumed but must be cryptographically proven through successful attestation. Operational credentials are only delivered after a Relying Party (RP) appraises the Attestation Result (AR) from the Verifier and deems it acceptable. For post-attestation patterns including re-attestation and hierarchical trust, see [](#post-attestation-patterns).

## Protocol Requirements (Normative) {#protocol-requirements-normative}

This section defines abstract properties that MUST hold for any conforming implementation. Concrete algorithms and encodings are defined by profiles (see [](#sec-profiles)).

1. **Accept-Once Ceremony**

   - Each attestation ceremony is identified by a globally unique `eca_uuid`.
   - A Verifier MUST accept each `eca_uuid` at most once and MUST treat re-observations as replay and abort. Verifiers SHOULD use a persistent store (e.g., a database or file) to track accepted `eca_uuid` values for at least the expected lifetime of an Attestation Result to prevent replay.

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
   - Integrity protection MUST cover at minimum: `eca_uuid`, channel role (Attester/Verifier), and a profile-defined set of claims sufficient for appraisal.

5. **Replay & Freshness**

   - Implementations MUST enforce replay resistance for phase artifacts within the ceremony lifetime.
   - Freshness semantics (e.g., timestamps or nonces) MUST be provided by the active profile and included in the authenticated data.

6. **Termination & State**

   - The Verifier MUST publish a terminal status (success or authenticated failure).
   - After terminalization, subsequent artifacts for the same `eca_uuid` MUST be ignored.

7. **No Attester-Supplied Trust Pinning**

   - Verifiers MUST NOT establish trust for appraisal by pinning any CA or key material supplied by the Attester.

    > Note: The security properties of ceremony isolation depend significantly on the transport mechanism. See [](#verifier-key-compromise-impact-analysis) for transport-specific security considerations regarding Verifier key management.

8. **Transport Minimalism**

   - The protocol MUST be realizable over a static artifact repository (poll/pull). Profiles MAY specify additional transports but MUST NOT weaken the requirements above.

# Protocol Overview {#protocol-overview}

The ECA protocol follows a three-phase ceremony, as illustrated in the figure below. The ceremony begins with the Attester in a privileged credential vacuum, possessing only its initial factors. It concludes with the Verifier producing a signed Attestation Result (AR) upon successful validation, which can then be delivered to the Attester for presentation to Relying Parties (RP).

~~~
   Attester                                           Verifier
(possesses BF, IF)                                (expects BF, IF)
      |                                                  |
      |  Phase 1: Prove Possession of BF+IF              |
      |  (publishes IHB, kem_pub, HMAC)                  |
      |------------------------------------------------->|
      |                                                  |
      |                                             (Validates proof
      |                                               at Gates 1-4)
      |                                                  |
      |  Phase 2: Receive Validator Factor               |
      |  (retrieves Encrypted {VF, nonce} + Signature)   |
      |<-------------------------------------------------|
      |                                                  |
      |  Phase 3: Prove Joint Possession of BF+VF        |
      |  (publishes signed Evidence EAT)                 |
      |------------------------------------------------->|
      |                                                  |
      |                                             (Appraises EAT
      |                                               at Gates 5-11)
      |                                                  |
      |<.................................................. (SUCCESS)
      |                                              Attestation
(receives AR for RP)                                  Result (AR)
~~~

## Validation Gates {#sec-validation-gates}

The Verifier enforces a sequence of fail-closed validation gates in a specific order derived from the protocol's formal model. Each gate represents a critical check that must pass before proceeding.

1. **MAC Verification:** Verifies the integrity of the Phase-1 payload using an HMAC tag derived from `BF` and `IF`.
   - Failure Action: Immediate termination. Publish error status `MAC_INVALID`.

2. **Instance Authorization:** Checks if the Attester's identity (e.g., derived from `eca_uuid` or IF) is authorized to proceed.
   - Failure Action: Immediate termination. Publish error status `ID_MISMATCH`.

3. **IHB Validation:** Confirms that the received Integrity Hash Beacon (IHB) matches the expected value for the authorized instance.
   - Failure Action: Immediate termination. Publish error status `IHB_MISMATCH`.

4. **KEM Public Key Match:** Ensures the ephemeral encryption public key in the payload matches the expected key for the session.
   - Failure Action: Immediate termination. Publish error status `KEM_MISMATCH`.

5. **Evidence Time Window:** Validates that the `iat`, `nbf`, and `exp` claims in the final EAT are within an acceptable time skew (e.g., ±60 seconds).
   - Failure Action: Immediate termination. Publish error status `TIME_EXPIRED`.

6. **EAT Schema Compliance:** Checks that the EAT contains all required claims with the correct types and encodings.
   - Failure Action: Immediate termination. Publish error status `SCHEMA_ERROR`.

7. **EAT Signature:** Verifies the Ed25519 signature on the EAT using the public key derived from `BF` and `VF`.
   - Failure Action: Immediate termination. Publish error status `SIG_INVALID`.

8. **Nonce Match:** Ensures the nonce in the EAT matches the nonce the Verifier issued in Phase 2, proving freshness.
   - Failure Action: Immediate termination. Publish error status `NONCE_MISMATCH`.

9. **JP Validation:** Verifies the Joint Possession proof, ensuring the final identity key is bound to the ceremony context.
   - Failure Action: Immediate termination. Publish error status `KEY_BINDING_INVALID`.

10. **PoP Validation:** Verifies the final Proof-of-Possession tag, confirming the Attester's knowledge of both `BF` and `VF`.
    - Failure Action: Immediate termination. Publish error status `POP_INVALID`.

11. **Identity Uniqueness (Replay):** Persists the terminal state for the `eca_uuid` and rejects any future attempts to use it.
    - Failure Action: Immediate termination. Publish error status `IDENTITY_REUSE`.

These gates align with the formal model's events (see [](#core-security-properties-baseline-model)):
- Gate 8 Nonce Match (per AttesterUsesNonce event).
- Gate 9 JP Validation (per VerifierValidatesWithKey event).
- Gate 10 PoP Validation (See [](#sec-pop)) (per VerifierAccepts event).

## Phase 1: Authenticated Channel Setup {#phase-1-authenticated-channel-setup}

- **Attester** generates an ephemeral X25519 keypair deterministically from `BF` + `IF`.
- Computes the Integrity Hash Beacon (IHB): `IHB = SHA-256(BF || IF)`.
- Publishes a CBOR payload containing `{kem_pub, ihb}` and an associated HMAC tag to the repository.
- **Verifier** retrieves the published artifacts and validates them against Gates 1-4.

## Phase 2: Challenge and Validator Factor Release {#phase-2-challenge-and-validator-factor-release}

- **Verifier** generates a fresh `VF` (≥128 bits) and a 16-byte nonce.
- Encrypts `{VF, nonce}` using HPKE to the Attester's ephemeral public key.
- Signs the encrypted payload with its Ed25519 key and publishes it to the repository.
- **Attester** retrieves the published payload, verifies its authenticity, and decrypts the `VF`.

## Phase 3: Joint Possession Proof {#phase-3-joint-possession-proof}

- **Attester** derives a final Ed25519 signing keypair deterministically from `BF`+`VF`.
- Creates a signed EAT containing identity claims, the Verifier's nonce, and a final Proof-of-Possession HMAC.
- Publishes the signed EAT to the repository.
- **Verifier** retrieves the final EAT and validates it against Gates 5-11, yielding an Attestation Result (AR) upon success.

## Key Lifecycle {#key-lifecycle}

When using SAE transport [@I-D.ritz-sae]:
- Implementations MAY use long-term or ephemeral Verifier keys
- Ephemeral per-ceremony keys are RECOMMENDED for operational best practice

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

# Post-Attestation Patterns {#post-attestation-patterns}

Once the ceremony has concluded, operators can make policy decisions about how to handle the Attestation Result (AR). This may include transmitting the `AR` directly to the successful Attester so that it may present the `AR` to Relying Parties (RPs) who trust the Verifier's signature. The full scope and mechanism of presenting and accepting `AR`s to `RP`s is outside the scope of this document.

## Stateful Re-Attestation for Long-Running Instances {#stateful-re-attestation-for-long-running-instances}

The ECA protocol is primarily designed for the initial identity bootstrap of ephemeral compute instances. However, long-running workloads may require a mechanism for renewing their operational credentials. A credential renewal can be modeled as a "re-attestation" ceremony.

In this model, the original, stable `eca_attester_id` identity would serve as a Renewal Factor (`RF`), analogous to the `BF`. The new Instance Factor (`IF`) would be a manifest of "known good" measurements of the instance's current state (e.g., hashes of critical binaries or configuration files). This turns the renewal into a periodic health and integrity check, ensuring the instance remains in a known-good state throughout its lifecycle. A future profile of ECA may define a renewal protocol based on stateful re-attestation.

## Chaining and Hierarchical Trust {#chaining-and-hierarchical-trust}

The ECA protocol is inherently composable, enabling the creation of multi-layer trust architectures that can propagate trust from hardware up through layers of software. This is achieved by using the signed Attestation Result (AR) from one ceremony as a cryptographic input—specifically, the Instance Factor (IF)—for a subsequent ceremony.

A straightforward deployment pattern for this is represented by the following "bare-metal-to-VM" attestation chain:

1. **Initial Attestation (Hardware Layer):** A physical host (`Attester i`) performs an ECA ceremony using an **Instance Factor** derived from a hardware root of trust (e.g., a TPM quote, per `IFP Pattern A`). It attests to a low-level Verifier (`Verifier i`) that is trusted to appraise hardware integrity. The successful result is a signed Attestation Result, `AR_i`.

2. **Second-Level Attestation (VM Layer):** A virtual machine (`Attester ii`) is instantiated on the host. Its provisioned **Instance Factor** is the signed `AR_i` from the hardware layer. `Attester ii` performs its own ECA ceremony with a higher-level cloud orchestrator (`Verifier ii`). To validate, `Verifier ii` first cryptographically verifies `AR_i` (confirming it trusts `Verifier i`), and if valid, proceeds with the rest of the ECA ceremony.

The final result, `AR_ii`, is a portable credential that cryptographically proves a healthy VM is running on a specific, healthy, and previously attested physical host. The same pattern can be used to bridge trust domains, for example by consuming an `SVID` from an existing `SPIFFE/SPIRE` infrastructure as the Instance Factor for an attester in a separate cloud environment. A future profile of ECA may define a specific profile for chaining and hierarchical trust.

## Risks and Mitigations for Composable Deployments {#risks-and-mitigations-for-composable-deployments}

While ECA is designed to be composable (e.g., chaining attestations), realizing this benefit in large teams is expected to require significant operational discipline. Operators should be aware of the following risks:

**The "Glue Code" Trap:** The security of the overall system depends on the integrity of each link in the chain. Custom scripts or shims used to connect different attestation layers can inadvertently reintroduce the very vulnerabilities (e.g., parsing flaws, state management bugs) that SAE [@I-D.ritz-sae] is designed to eliminate. It is STRONGLY RECOMMENDED to use standardized, well-vetted integrations (e.g., official plugins for tools like Vault or SPIRE) over bespoke "glue code."

**Organizational Friction:** In multi-team environments, clear ownership of the end-to-end attestation process is critical. Without a shared governance model, configuration drift between what DevOps provisions, what Security expects, and what the application implements can lead to systemic failures.

# Security Considerations {#security-considerations}

**Trust Boundaries:** Without hardware roots of trust, the security scope is limited to passive network observers rather than compromised infrastructure providers. Hardware-rooted Instance Factor Pattern A addresses this limitation. For detailed pattern specifications, see [](#instance-factor-patterns-ifp). This hardware-based protection is critical for mitigating State Reveal attacks; a formal analysis confirmed that a compromise of the Attester's software environment can expose the ephemeral decryption keys used in Phase 2, thereby compromising the ceremony's core secrets (see [](#attester-state-reveal)).

**Exposure tolerance:** The protocol is designed to tolerate incidental exposure of the unique per-use Boot Factor token (BF) (e.g., in control-plane logs), however this tolerance does not replace the need for sound operational hygiene. Operators SHOULD avoid unnecessary public dissemination of `BF` to minimize attracting targeted attacks. Security is layered; cryptographic strength complements, but does not replace, good operational practices.

**Secrets Handling:** Derived keys are sensitive cryptographic material. Implementations MUST handle them securely in memory (e.g., using locked memory pages) and explicitly zeroize them after use.

## Exposure Tolerance {#exposure-tolerance}

A core design principle of this protocol is that the Boot Factor (BF) is considered **public information** and its security does not depend on the BF's confidentiality. This exposure tolerance is a deliberate architectural choice that enables powerful, flexible provisioning patterns, such as using a public key from an ACME certificate as a verifiable Boot Factor.

This design places the entire security burden for the initial authentication on the confidentiality of the **Instance Factor (IF)**. The protocol's security is anchored on the Attester proving its knowledge of the secret `IF` in conjunction with the public `BF`.

The operational risk is therefore focused on preventing the concurrent exposure of both `BF` and `IF`. This risk is tightly time-bounded by two key factors:

1. **The Accept-Once Policy:** The window of vulnerability is extremely short. Once a Verifier consumes an `eca_uuid` and successfully completes the ceremony, the "accept-once" rule renders any stolen factors for that specific ceremony useless for future impersonation attacks.

2. **Transport Security (SAE):** When using a transport like SAE, an attacker cannot mount a meaningful impersonation attack without gaining write access to the secure artifact repository, which represents a significant and independent security boundary.

Therefore, operational hygiene should focus on protecting the end-to-end provisioning process to ensure the secrecy of the `IF` until the ceremony is complete, rather than on attempting to hide the public `BF`.

## Security Properties (Formal Model) {#security-properties-formal-model}

The protocol's security properties have been analyzed using an exploratory ProVerif model. The model positively identifies key security goals such as authentication, freshness, key binding, and confidentiality against a network attacker, assuming a public Boot Factor (BF). For a detailed summary of the formal model, its queries, and the proven properties within the models, see [](#appendix-a-formal-modelling-informative).

## Impersonation Risk {#impersonation-risk}

The security properties described in [](#security-properties-formal-model) depend on the secrecy of the joint factors. These properties will be compromised if both the Boot Factor (BF) and Instance Factor (IF) are exposed concurrently before a successful ceremony completes. Therefore, `BF` and `IF` MUST NOT be transmitted together over an unsecured channel prior to the conclusion of the ceremony. Such exposure would allow an adversary to intercept the Validator Factor (VF) and perfectly impersonate the intended Attester.

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

Formal analysis ([](#verifier-key-compromise)) identified that long-term Verifier keys enable freshness attacks in theory. However, the protocol's cryptographic binding design **ensures** these attacks cannot produce valid authentication, limiting impact to denial of service at worst.

When using SAE transport [@I-D.ritz-sae], compromise of Verifier signing keys has negligible security impact:

- **Authentication remains secure:** Attackers cannot forge acceptable evidence
- **Protocol integrity maintained:** All validation gates (8-10) will reject evidence derived from attacker-injected values
- **Maximum impact:** Denial of service only

This resilience results from two factors:
1. SAE's pull-only architecture prevents message injection without repository access
2. ECA's cryptographic binding ensures evidence from corrupted ceremonies fails appraisal

Given these mitigations, implementations using SAE MAY use long-term Verifier keys with acceptable security properties, though ephemeral keys remain RECOMMENDED for operational hygiene and ceremony isolation.

Note: Implementations using push-capable or direct-communication transports MUST use ephemeral per-ceremony keys, as these transports enable active injection attacks that compromise freshness.

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

**Real-time Performance Optimization:** The asynchronous design prioritizes security and reliability over minimal latency. Preliminary efforts suggest total latency of less than 2 seconds using SAE for VM attestation, which is minimal compared to standard cloud VM startup time. Sub-second attestation is not a primary goal, however feedback for secure optimizations are welcomed.

# Integration with Existing Frameworks {#integration-with-existing-frameworks}

The ECA protocol is designed to complement, not replace, existing identity and attestation systems. It acts as a foundational "attestation engine" that fills specific gaps in cross-domain portability and high-assurance bootstrapping for ephemeral workloads. Its role is to provide a verifiable, portable proof of identity that can be consumed by a wide range of higher-level identity frameworks and certificate issuance protocols, as illustrated below.

~~~
┌─────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│   Ephemeral     │    │   Identity &     │    │   Certificate    │
│   Compute       │    │   Access         │    │   Authority      │
│   Environment   │    │   Management     │    │   Ecosystems     │
├─────────────────┤    ├──────────────────┤    ├──────────────────┤
│ • Cloud VMs     │    │ • SPIFFE/SPIRE   │    │ • ACME-RATS      │
│ • Containers    │◄───│ • Vault          │◄───│ • PKI            │
│ • Bare Metal    │    │ • IAM Systems    │    │ • CA/Browser     │
└─────────────────┘    └──────────────────┘    └──────────────────┘
         │                        │                       │
         └────────────────────────┼───────────────────────┘
                                  │
                         ┌────────▼────────┐
                         │   ECA + SAE     │
                         │  Attestation    │
                         │    Engine       │
                         └─────────────────┘
~~~

## Realizing the RATS Passport Model {#realizing-the-rats-passport-model}

ECA aligns with the Passport Model of the RATS Architecture [@!RFC9334], where the Attester obtains a portable Attestation Result (e.g., an EAT [@!RFC9711]) from the Verifier for presentation to Relying Parties. While RATS provides the roles and terminology for remote attestation, it does not specify a concrete protocol for cross-cloud identity bootstrapping. ECA fills this gap by defining a phased exchange that produces standardized EATs bound to joint ephemeral factors, enabling interoperability across heterogeneous providers.

## ECA + ACME-RATS {#eca--acme-rats}

A powerful use case for ECA is as a mechanism to satisfy the attestation challenges proposed within the ACME working group, as described in the "(ACME) rats Identifier and Challenge Type" (ACME-RATS) Internet-Draft [@I-D.liu-acme-rats]. The `ACME-RATS` specification defines an abstract challenge/response mechanism for device attestation but intentionally leaves the implementation of the attestation procedure itself out of scope. ECA can act as a bridge, providing the full three-phase ceremony—from initial bootstrap to final proof-of-possession—that an ACME client can execute to produce the verifiable Attestation Result (AR) required by the `attestation-result-01` challenge (Passport Model).

When you combine ECA with the ACME-RATS framework, you create a complete, end-to-end automated flow.

This integration approach enables a powerful vision: just as ACME enabled the automation of web server certificates and brought about ubiquitous HTTPS, the combination of ACME-RATS and ECA can enable the automated issuance of high-assurance identities to ephemeral workloads, realizing a "Let's Encrypt" for Machines."

### Conceptual Integration {#conceptual-integration}

An integration of an ACME client with an ECA Attester would follow this sequence:

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

### Operational Flow (Conceptual) {#operational-flow-conceptual}

~~~
   +----------------+        +-----------------+        +-------------------+
   |    Attester    |        |     Verifier    |        |    ACME Server    |
   | (ACME client)  |        |  (RATS role)    |        |   (RA/CA roles)   |
   +--------+-------+        +--------+--------+        +---------+---------+
            |                         |                           |
   (1) New Order / AuthZ              |                           |
            |------------------------>|  [normal ACME steps]      |
            |                         |                           |
   (2) Challenge: attestation-result-01 (token, [claimsHint])     |
            |<----------------------------------------------------|
            |                                                     |
   (3) Start ECA ceremony (freshness := token)                    |
   (3a) Collect evidence (incl. hinted claims)                    |
            |------------------------ evidence ------------------->|
            |                         |                           |
   (4) Appraise evidence; produce Attestation Result (AR)         |
            |<---------------------- signed AR --------------------|
            |                         |                           |
   (5) Wrap AR in CMW (type=attestation-result, format=AR profile)|
            |                                                     |
   (6) Respond to challenge with CMW-wrapped AR                   |
            |---------------------------------------------------->|
            |                         |                           |
   (7) Verify Verifier signature; evaluate claims vs. policy      |
            |<----------------------- challenge=valid -------------|
            |                         |                           |
   (8) Finalize order; issue certificate                          |
            |<----------------------------------------------------|
            |                         |                           |
~~~

### ECA + ACME-RATS Trust Chain Sketch {#eca--acme-rats-trust-chain-sketch}

* **ACME Server** is pre-configured with trust anchors (e.g., key set or CA) for one or more Verifiers.
* **Attester** trusts its local Evidence source (e.g., HRoT) and the Verifier (via ECA's cryptographic proofs) but starts in a privileged credential vacuum—no ACME-specific creds prior to challenge completion.
* **Verifier** publishes a stable identifier (e.g., `key id`) discoverable by the ACME Server (e.g., via directory or config).
* **Freshness/Nonce Binding:** ACME `token` is bound to ECA `vnonce` (e.g., `vnonce = token` or `vnonce = SHA-256(token || eca_uuid)`), included in Evidence EAT, and reflected in AR. ACME Server checks match at validation.

## The SPIFFE/SPIRE Framework {#the-spiffespire-framework}

SPIFFE/SPIRE provides a robust framework for issuing short-lived cryptographic identities (SVIDs) to workloads, enabling zero-trust authentication in distributed systems. While SPIFFE/SPIRE addresses "secret zero" in many scenarios through platform-specific node attestors (e.g., AWS EC2 or Kubernetes), it relies on extensible plugins for custom environments which is a natural fit for an ECA plugin implementation. SPIFFE/SPIRE is a CNCF-graduated community standard rather than an IETF standard.

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

BRSKI [@!RFC8995] solves *manufacturer-anchored onboarding* for physical devices that ship with an IEEE 802.1AR IDevID and a manufacturer voucher service (MASA). ECA targets *ephemeral compute* (VMs, containers) that typically lack such an identity.

The mechanisms are complementary: **BRSKI** is for day-0 hardware onboarding based on supply-chain provenance, while ECA is for just-in-time software and instance attestation at runtime. An operator could use BRSKI to securely enroll a physical device into their network, and then use ECA as a subsequent, continuous attestation check to validate the software state running on that device before releasing application-level privileges.

## Summary of Integration Benefits {#summary-of-integration-benefits}

Adopting ECA as a foundational attestation engine provides several key benefits:

* **Standards-Based:** Built on emerging and established IETF standards like RATS, EAT, and ACME.
* **Portable:** The protocol's transport-agnostic design works across cloud, on-premise, and edge environments.
* **Composable:** Can be layered with existing systems like SPIFFE/SPIRE to enhance their security posture.
* **High-Assurance:** Supports hardware roots of trust (`IFP Pattern A`) for zero-trust environments.
* **Automation-Friendly:** Designed from the ground up for ephemeral, dynamic, and automated infrastructures.

# Profiles (Normative) {#sec-profiles}

This document defines the protocol abstractly. Concrete cryptographic mechanisms are supplied by profiles. A conforming implementation MUST implement at least one profile, and any chosen profile MUST preserve all requirements in [](#protocol-requirements-normative).

> Note: No MTI Algorithms in this Revision. This -00 revision does not define mandatory-to-implement (MTI) primitives. Reference profiles will be published separately to enable experimentation and interoperability testing.

Key Separation (Architecture requirement): Regardless of profile, implementations MUST maintain strict separation between:
- Phase 2 encryption keys (used by the Verifier to release VF to the Attester), and
- Phase 3 identity/signing keys (used by the Attester to sign Evidence/EAT).

Profiles typically achieve separation via domain-separated KDF invocations; however, any mechanism that guarantees computational unlinkability between Phase 2 and Phase 3 key material is acceptable, provided the invariants in [](#protocol-requirements-normative) remain intact.

## Proof-of-Possession (PoP) Construction {#sec-pop}

A profile MUST provide a PoP mechanism that proves joint-possession of both factors used across the ceremony and binds the result to the session context. At minimum, the PoP's authenticated input MUST cover:

- `eca_uuid`,
- the Integrity Hash Beacon (IHB) or an equivalent `BF`+`IF` binding,
- the Attester's Phase-3 signing public key, and
- the Verifier's freshness input (e.g., `vnonce`).

The PoP output MUST be verifiable by the Verifier without additional round trips and MUST be integrity-protected under a key that is infeasible to compute without both factors required by the active profile.

# EAT profiles {#sec-evidence-profiles}

## Evidence Claims {#evidence-claims}

| Claim | EAT Key | Value Type | M/O | Description |
| :----------------- | :------ | :--------- | :-: | :----------------------------------------------------------------------------------------------------------------------- |
| **ECA UUID** | 2 (sub) | tstr | M | The unique `eca_uuid` for the attestation lifecycle. The value of this claim MUST be the `eca_uuid`. |
| **Expiration** | 4 (exp) | int | M | NumericDate (epoch seconds). MUST be encoded as a 64-bit unsigned integer. |
| **Not Before** | 5 (nbf) | int | M | NumericDate (epoch seconds). MUST be encoded as a 64-bit unsigned integer. |
| **Issued At** | 6 (iat) | int | M | NumericDate (epoch seconds). MUST be encoded as a 64-bit unsigned integer. |
| **Verifier Nonce** | 10 (nonce) | tstr | M | Verifier-issued `vnonce` (**base64url**, unpadded) representing exactly 16 bytes of entropy (typically 22 chars). |
| **ECA Identity** | 256 (EUID) | tstr | M | `eca_attester_id` = hex SHA-256 of the Ed25519 public key used to sign this EAT. |
| **EAT Profile** | 265 | tstr | M | Profile identifier (e.g., `urn:ietf:params:eat:profile:eca-v1`). |
| **Measurements** | 273 | tstr | M | Integrity Hash Beacon (IHB) (**lowercase hex**). |
| **PoP** | 274 (PoP) | tstr | M | Final Proof of Possession tag (**base64url**, unpadded) computed as defined by the active profile. |
| **Intended Use** | 275 | tstr | M | The intended use of the EAT (e.g., attestation, enrollment credential binding). |
| **JP Proof** | 276 | tstr | M | Joint Possession proof (**lowercase hex**), binding the final identity to the ceremony. |

Values marked "tstr" that carry binary material (e.g., nonces, tags) MUST specify their encoding. Profile specifications MUST define exact encodings for all binary claims.

## Attestation Results {#attestation-results}

| Claim | Key | Value Type | Description |
| :--------------- | :------ | :--------- | :--------------------------------------------------------------------------------- |
| **Issuer** | 1 | tstr | An identifier for the Verifier that produced the result. |
| **Subject** | 2 | tstr | The `eca_attester_id` identity of the instance that was successfully attested. |
| **Expiration** | 4 (exp) | int | OPTIONAL. NumericDate defining the AR's validity period. |
| **Not Before** | 5 (nbf) | int | OPTIONAL. NumericDate defining the AR's validity period. |
| **Issued At** | 6 | int | NumericDate (epoch seconds) of the successful validation. |
| **JWT ID** | 7 | tstr | The unique `eca_uuid` of the attestation lifecycle to prevent replay. |
| **Key ID** | -1 (kid)| bstr | OPTIONAL. The hash of the Verifier's public key used to sign the AR. |
| **Status** | -262148 | tstr | The outcome of the attestation. MUST be `urn:ietf:params:rats:status:success`. |

For failures, the AR payload SHOULD follow the same structure but with a `status` of `urn:ietf:params:rats:status:failure` and an additional `error_code` claim (e.g., -262149 as a `tstr`) containing the authenticated error. Relying Parties consuming the AR MUST validate the `nbf` and `exp` claims to ensure the AR is within its validity period.

# Transport Considerations {#transport-considerations}

The ECA protocol is transport-agnostic. It requires only that peers have a mechanism to publish and retrieve immutable cryptographic artifacts from a pre-defined Artifact Repository. The Static Artifact Exchange (SAE) protocol [@I-D.ritz-sae] is specified as the recommended pattern to fulfill this requirement. SAE's static, "publish-then-poll" model is intentionally chosen to minimize the attack surface associated with traditional, dynamic APIs. By avoiding direct request processing, it eliminates entire classes of vulnerabilities like injection and parser flaws, ensuring that protocol security is derived from the cryptographic content of the artifacts alone.

# Operational Considerations {#operational-considerations}

**Scalability:** The use of a simple artifact repository allows for high scalability using standard web infrastructure like CDNs and object storage.

**Time Synchronization:** Reasonably synchronized time is REQUIRED for proper validation of the `nbf` and `exp` time windows (Gate 5 skew tolerance: ±60s). The use of a time synchronization protocol like NTP [@?RFC5905] is RECOMMENDED. Polling MUST use exponential backoff with jitter.

**Addressing Complexity:** The multi-phase design of ECA is intentionally confined to the infrastructure layer to provide a simple and secure operational experience. ECA's cryptographic machinery is expected to be abstracted away from the end-user. The prototype implementation demonstrates this, executing a complete, parallel attestation with a single command (e.g. `eca-toolchain attest --manifest ./manifest.yml`), similar to how a sophisticated suite of standards (SMTP, DKIM, etc.) underpins a simple email "send" button.

## Provisioning and Repository Access {#provisioning-and-repository-access}

The ECA protocol requires the Attester to publish artifacts while adhering to the **Privileged Credential Vacuum** design principle (see [](#core-design-principles)). This is achievable using standard cloud primitives that grant ephemeral, narrowly-scoped write capabilities without provisioning long-term secrets. Common patterns include the control plane injecting a time-limited pre-signed URL (e.g., for Amazon S3 or GCS) or a short-lived, scoped OAuth2 token for the instance to use. In this model, the Attester is granted the temporary *capability* to write to its specific repository path, fulfilling the protocol's needs without violating the zero-trust principle of verify-then-trust. Verifiers MUST NOT rely on any CA or key material delivered by the Attester for appraisal trust establishment. This reinforces the requirement in [](#protocol-requirements-normative).

# IANA Considerations {#iana-considerations}

IANA is requested to register:

## EAT Profile {#sec-iana-eat-profile}

* **Profile:** Profile identifiers will be defined by concrete profile specifications.

* **ECA Attestation Result Claims:** IANA is requested to establish a registry for ECA Attestation Result Claims as outlined in [](#attestation-results). This registry defines the claims used within the signed CBOR object that constitutes an Attestation Result.

## Registries {#sec-iana-registries}

### ECA Error Codes Registry {#sec-iana-errors}

This registry defines application-specific error codes that are used in addition to the base error codes defined in [@I-D.ritz-sae]. The Canonical Content string defined here MUST be used as the input to the HMAC-SHA256 function when generating an error signal, as specified by the SAE protocol.

| Code | Canonical Content (UTF-8) | Gate | Description |
| :-------------------- | :------------------------ | :--- | :--------------------------------------------------------------------------- |
| `MAC_INVALID` | `MAC_INVALID` | 1 | Provided MAC was invalid. |
| `ID_MISMATCH` | `ID_MISMATCH` | 2 | Provided instance identity was invalid. |
| `IHB_MISMATCH` | `IHB_MISMATCH` | 3 | Recomputed IHB did not match expected value. |
| `KEM_MISMATCH` | `KEM_MISMATCH` | 4 | Did not get expected KEM key for the session. |
| `TIME_EXPIRED` | `TIME_EXPIRED` | 5 | Evidence timestamp was outside valid time window. |
| `SCHEMA_ERROR` | `SCHEMA_ERROR` | 6 | Attestation token failed schema validation. |
| `SIG_INVALID` | `SIG_INVALID` | 7 | Attestation token signature failed. |
| `NONCE_MISMATCH` | `NONCE_MISMATCH` | 8 | Nonce in the EAT did not match the issued nonce. |
| `KEY_BINDING_INVALID` | `KEY_BINDING_INVALID` | 9 | The key used for validation is not bound to the session's Boot Factor. |
| `POP_INVALID` | `POP_INVALID` | 10 | The PoP tag was invalid. |
| `IDENTITY_REUSE` | `IDENTITY_REUSE` | 11 | Attempt to reassign an existing identity. |
| `PUBLISHER_INVALID` | `PUBLISHER_INVALID` | - | Attester artifacts were observed at a repository not hosted by the Attester. |
| `TIMEOUT_PHASE1` | `TIMEOUT_PHASE1` | - | Attester failed to publish Phase 1 artifacts within timeout |
| `TIMEOUT_PHASE2` | `TIMEOUT_PHASE2` | - | Attester failed to publish Phase 2 artifacts within timeout |
| `TRANSPORT_ERROR` | `TRANSPORT_ERROR` | - | Underlying transport protocol error |

# Implementation Status {#implementation-status}

A working prototype demonstrates end-to-end attestation including:

- Complete three-phase protocol implementation
- EAT-compliant evidence generation
- Concurrent execution capability
- Docker-based orchestration for testing

| Metric | Value | Notes |
|--------|-------|-------|
| Protocol Execution | ~1.3s | Phases 1-3, excluding infra |
| Full Attestation (incl. containers) | ~6s | Parallel runs, randomized mode |
| Scalability | 3 concurrent | No failures observed |

An end-to-end happy-path version of the Prototype is available at [[ECA-SAE-PROTOTYPE](#ext-links)].

Reference profile specifications and test vectors are maintained separately to enable independent updates and experimentation.

# Acknowledgments {#acknowledgments}

The design of this protocol was heavily influenced by the simplicity and security goals of the [[AGE](#ext-links)] file encryption tool. The protocol's core cryptographic mechanisms would not be as simple or robust without the prior work of the IETF community in standardizing modern primitives, particularly Hybrid Public Key Encryption (HPKE) in RFC 9180. The author wishes to thank the contributors of these foundational standards for making this work possible.

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

The protocol's security properties were analyzed using an exploratory formal model in ProVerif [[ECA-FORMAL-MODELS](#ext-links)]. The model assumes a powerful Dolev-Yao network attacker who can intercept, modify, and inject messages. It also correctly models the Boot Factor (`BF`) as public knowledge from the start, as per the protocol's "exposure tolerance" principle ([](#core-design-principles)).

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

A test was conducted modeling a compromised long-term Verifier signing key [[ECA-FORMAL-MODELS](#ext-links)]:

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

A test was conducted modeling a compromised Attester whose ephemeral private decryption key is leaked [[ECA-FORMAL-MODELS](#ext-links)]:.

- **Result:** The model demonstrated that this allows a passive attacker to decrypt the Phase 2 ciphertext and steal the `ValidatorFactor` (`VF`) (`not (event(VFReleased(vf)) && attacker(vf))` was **False**).

- **Interpretation:** This result formally establishes the security boundary discussed in [](#attester-state-compromise)

- **Mitigation:** This analysis provides the formal rationale for hardware-rooted Instance Factor Pattern A when the threat model must assume compromise of the underlying provisioning platform. For pattern specifications, see [](#instance-factor-patterns-ifp).

# Reference Profile: ECA-VM-v1 {#app-reference-profiles}

> Stability note: This profile documents the concrete choices used by the reference prototype to enable experimentation and interop. It is non-normative and may change in future drafts based on feedback.

## Primitives {#primitives}

- Hash / KDF: HKDF-SHA-256 (RFC5869), SHA-256 (RFC6234)
- MAC: HMAC-SHA-256
- Signatures: Ed25519 (RFC8032)
- KEM/HPKE: X25519 + HPKE base mode (RFC9180) for Verifier -> Attester secrecy in Phase 2. The `eca_uuid` is used as the AAD, and the `info` parameter for key derivation is `"ECA/v1/hpke"`.
- Nonces: Verifier freshness `vnonce` is exactly 16 bytes (encoded base64url, unpadded)

## Integrity Hash Beacon (IHB) {#integrity-hash-beacon-ihb}

- `IHB = SHA-256( BF || IF )`, rendered as lowercase hex for transport where necessary.

## Deterministic Key Material {#deterministic-key-material}

All keys are deterministically derived from ceremony inputs via domain-separated HKDF invocations. Notation: `HKDF-Extract(salt, IKM)` then `HKDF-Expand(PRK, info, L)`. The `eca_uuid` is appended to the `salt` in all derivations to ensure session uniqueness.

- **Phase 1 MAC key (Attester artifact MAC)**

  - `IKM = BF || IF`
  - `salt = "ECA:salt:auth:v1" || eca_uuid`
  - `info = "ECA:info:auth:v1"`
  - `K_MAC_Ph1 = HKDF-Expand( HKDF-Extract(salt, IKM), info, 32 )`
  - Usage: HMAC-SHA-256 over the CBOR Phase-1 payload bytes.

- **Phase 2 ECDH/HPKE seed (Attester's ephemeral X25519 keypair)**

  - `IKM = BF || IF`
  - `salt = "ECA:salt:encryption:v1" || eca_uuid`
  - `info = "ECA:info:encryption:v1"`
  - `seed32 = HKDF-Expand( HKDF-Extract(salt, IKM), info, 32 )`
  - The Attester forms an X25519 private key by clamping `seed32` per RFC7748; the public key is derived normally.
  - The Verifier uses HPKE with the Attester's public key to encrypt `{VF, vnonce}`.

- **Phase 3 signing key (Attester's Ed25519 identity keypair)**

  - `IKM = BF || VF`
  - `salt = "ECA:salt:composite-identity:v1" || eca_uuid`
  - `info = "ECA:info:composite-identity:v1"`
  - `sk_seed32 = HKDF-Expand( HKDF-Extract(salt, IKM), info, 32 )`
  - The Attester initializes Ed25519 with `sk_seed32` as the private key seed and derives the corresponding public key.

- **HPKE KDF `info` parameter:** `info = "ECA/v1/hpke"`

## Phase Artifacts {#phase-artifacts}

*This section provides a high-level description of the payloads. For concrete byte-for-byte examples, see Section 7.*

### Phase 1 Payload (Attester→Repo) {#phase-1-payload-attester-repo}

The Phase-1 payload is a CBOR map containing the following claims, which is then protected by an external HMAC tag.

| Claim | Value Type | Description |
| :--- | :--- | :--- |
| `kem_pub` | `bstr` (raw 32 bytes) | Attester's ephemeral X25519 public key. |
| `ihb` | `tstr` (lowercase hex) | Integrity Hash Beacon. |

### Phase 2 Payload (Verifier -> Repo) {#phase-2-payload-verifier---repo}

The Phase-2 payload is a signed CBOR map containing the following claims.

| Claim | Value Type | Description |
| :--- | :--- | :--- |
| `C` | `tstr` (base64url unpadded) | HPKE ciphertext |
| `vnonce` | `tstr` (base64url unpadded) | The Verifier-generated nonce. |

The plaintext for HPKE encryption is the direct concatenation of the raw bytes: `plaintext = VF || vnonce`.

### Phase 3 Payload (Attester -> Repo) {#phase-3-payload-attester---repo}

The Phase-3 payload is a signed EAT as defined in the core protocol Section 11.1. The profile-specific constructions for proofs are as follows:

- **Joint-Possession Proof (concrete for this profile):**
  - `jp_proof = SHA-256( BF || VF )`, rendered as lowercase hex.
- **Proof-of-Possession (concrete for this profile):**
  - First, a bound hash is computed from the session context:
    - `bound_data = eca_uuid || IHB_bytes || eca_attester_id_bytes || vnonce_raw_bytes`
    - `bound_hash = SHA-256( bound_data )`
  - Then, a dedicated MAC key is derived:
    - `IKM = BF || VF`
    - `salt = "ECA:salt:kmac:v1" || eca_uuid`
    - `info = "ECA:info:kmac:v1"`
    - `K_MAC_PoP = HKDF-Expand( HKDF-Extract(salt, IKM), info, 32 )`
  - Finally, the PoP tag is computed over the bound hash:
    - `pop_tag = base64url( HMAC-SHA-256( K_MAC_PoP, bound_hash ) )`
- The `jp_proof` and `pop_tag` are included in the EAT, which is then signed with the Attester's Ed25519 key.

## Verification (Verifier) {#verification-verifier}

- Verify Phase-1 MAC with `K_MAC_Ph1`.
- Verify the signed Phase-2 payload with the Verifier's public key; HPKE-Open with Attester's kem key to recover `{VF, vnonce}`.
- Recompute Attester signing key from `BF||VF` and verify the EAT signature.
- Recompute `jp_proof` and `pop_tag` inputs and compare constant-time.
- Apply local appraisal policy; on success, emit an Attestation Result bound to `eca_uuid`.

## Interop Notes {#interop-notes}

- **Encodings:** All binary fields referenced in EAT must be explicitly encoded (e.g., base64url) and stated as such in the claims table. NumericDate claims (`iat`, `nbf`, `exp`) use 64-bit unsigned integers.
- **Side-Channel Resistance:** To mitigate timing attacks, implementations SHOULD use constant-time cryptographic comparisons. Payloads that are inputs to cryptographic operations (e.g., Evidence) MAY be padded to a fixed size using a length-prefix scheme to ensure unambiguous parsing.


