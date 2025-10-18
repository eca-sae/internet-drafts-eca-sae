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

Heterogenous workloads across multi-cloud, bare-metal, and edge environments often lack verifiable identities, relying instead on pre-shared secrets that enable impersonation if intercepted. Concurrently, Trusted Execution Environments (TEEs) and other high-assurance workloads are limited to single point-in-time attestation when they otherwise require continuous verification of platform trustworthiness throughout long-running sessions.

This document specifies Entity and Compute Attestation (ECA), a protocol that profiles RATS architecture to address both challenges. ECA defines an identity bootstrap procedure where Attester and Verifier collaboratively act as an Identity Supplier to establish an emergent and cryptographically verifiable identity for ephemeral workloads through proof of joint possession without the use of secrets like bearer tokens. The protocol also defines an attestation renewal procedure providing single round-trip verification bound to (D)TLS sessions via TLS Exported Authenticators that directly enables continuous attestation over time. ECA is designed as a supporting component for frameworks like WIMSE and to enhance related projects such as SPIFFE/SPIRE. The security properties of both procedures are being formally analyzed (see Appendix A). 

{mainmatter}

# Introduction

In many modern computing environments, such as bare-metal deployments, multi-cloud instances, or edge devices, workloads often lack a built-in, verifiable identity. This "Identity Vacuum" complicates trust establishment, forcing reliance on less secure methods like injected static secrets that if intercepted or leaked, could enable an attacker can use them to enroll a rogue workload.

Concurrently, high-assurance workloads, particularly those in Trusted Execution Environments (TEEs), require not only initial authentication but also continuous verification of their state. A point-in-time check is insufficient to detect compromises that may occur mid-session, creating a need for ongoing, stateful attestation that is cryptographically bound to the active communication channel.

This document specifies Entity and Compute Attestation (ECA), a protocol that profiles the Remote Attestation Procedures (RATS) architecture [@!RFC9334] to address these challenges. ECA defines two distinct cryptographic attestation procedures:

1.  **Identity Bootstrapping:** For initial "cold start" establishment of verifiable identity in environments not yet provisioned.

2.  **Attestation Renewal:** A lightweight, single round-trip attestation procedure for continuous verification of established identity and state, ideal for long-running workloads and TEEs.

# Motivation and Use Cases

This section describes scenarios where remote attestation enhances trust decisions by replacing static, possession-based secrets with cryptographic proof of a compute instance's identity and state. 

In the RATS model, the compute instance acts as an Attester, generating verifiable Evidence about its software and configuration. This Evidence is appraised by a Verifier, which produces a trusted Attestation Result (AR) for a Relying Party to consume, realizing the RATS Passport Model [@!RFC9334]. This fundamentally shifts the trust model from "who has the secret" to "what can be proven." 

The following use cases illustrate operational challenges that attestation can address.

## Bootstrapping Verifiable Identity in Constrained Environments

In environments without provider-backed identity mechanisms, such as bare-metal servers without TPMs or VMs limited to cloud-init, operators bootstrap trust by injecting static secrets into startup configuration. This creates a race condition where the first entity presenting the secret receives access, regardless of intended role. The resulting trust model depends on secret possession rather than verifiable identity.

Remote attestation can address this gap by enabling cryptographic proof of compute instance identity before credential release.

~~~
+--------------------------------------+
|  Bare-Metal / Alt-Cloud Environments | 
| (No provider-backed identity)        | 
+--------------------------------------+
                   |
                   v
         +--------------------+
         | Attestation        |
         | (Identity Proof)   |
         +--------------------+
                   |
                   v
    +-----------------------------+
    | Identity Consumers          |
    | (IAM, KMS, Access Control)  |
    +-----------------------------+
~~~

## Multi-Cloud Portability

When workloads migrate between cloud providers and on-premise environments, their provider-backed identity mechanisms are lost. Operators must then provision long-lived static credentials like API keys. This creates a risk where credential theft enables persistent workload impersonation.

Attestation can enable portable identity that survives migration across trust domains.

~~~
+--------------------------------------+
|  Workloads Across Environments       | 
| (AWS | Azure | Bare-Metal | Edge)    | 
+--------------------------------------+
                   |
                   v
         +--------------------+
         | Attestation        |
         |(Portable Identity) |
         +--------------------+
                   |
                   v
    +-----------------------------+
    | Identity Systems            |
    | (CA, SPIFFE/SPIRE, IAM) )   |
    +-----------------------------+
~~~


## Continuous TEE Verification

In confidential computing scenarios, clients establish sessions with TEE-based services after verifying initial attestation evidence. This point-in-time verification cannot detect post-handshake compromises. An attacker who compromises the TEE mid-session can exfiltrate sensitive data while the client continues operating under stale trust assumptions.

Continuous attestation can maintain trust throughout long-lived sessions.

~~~
            Verifying Relying Party          Attester
             (Client Application)       (TEE-Based Server)
                     |                           |
                     |<== Established Session ==>|  
                     |                           |
                     |--------- Health check --->| 
                     | (bound to session state)  |
                     |                           |                
                     |<--- Evidence -------------|                       
                     |(HW RoT Quote/Measurements)| 
 Appraise vs. Policy |                           | 
     (e.g., CORiM[1] |                           |
     validation)     |------ Policy Decision --->|                             
                     |(upkeep or destroy session)|                                                     
~~~
[1] [@?I-D.ietf-rats-corim]

# Conventions and Definitions {#conventions-and-definitions}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [@!RFC2119] [@!RFC8174] when, and only when, they appear in all capitals, as shown here.

**Attester**: An entity whose trustworthiness is to be evaluated, typically combining hardware, firmware and trusted software deployed in the cloud.

**Verifier**: Conducts appraisal of Evidence to evaluate trustworthiness of the Attester, enforcing validation gates against reference values.

  - The Verifier's appraisal relies on trust relationships with supply chain roles:
     - **Endorsers** (e.g., hardware manufacturers) provide cryptographic identity
     - **Reference Value Providers** supply expected measurements for appraisal
     - **Identity Suppliers** establish the Attester's cryptographic identity
     
**Relying Party**: Consumes signed Attestation Results to make authorization decisions.

**Verifying Relying Party (VRP):** An entity that fulfills the roles of both Verifier and Relying Party, particularly in attestation renewal procedures. The VRP directly appraises Evidence from an Attester to make an authorization decision without consulting an external Verifier.

**Identity Supplier:** In the context of ECA, this role is collaboratively fulfilled by the Attester and Verifier. The identity is not provisioned by a central authority but **emerges deterministically** from the identity bootstrap procedure, where the Attester generates its identity claims based on its inherent properties (`IF`) and the Verifier cryptographically ratifies them by issuing a signed Attestation Result.

**Evidence:** A set of claims produced by an Attester about its state, cryptographically signed by the Attester itself. In ECA, this typically takes the form of a signed EAT containing claims such as the EUID, IHB, and Proof-of-Possession.

**Attestation Result (AR):** A signed statement from a Verifier asserting the outcome of the appraisal of an Attester's Evidence. In ECA, this is a separate artifact from the Evidence, signed by the Verifier's long-term identity key.

**Entity Attestation Token (EAT):** A standardized token format [@!RFC9711] used to convey attestation evidence in a cryptographically verifiable form.

**Binding Factor (BF):** Attestation scope. A publicly verifiable, high-entropy value (≥128 bits) that cryptographically scopes an attestation procedure to a specific context. The BF does not require confidentiality; protocol security relies on its binding to the Instance Factor, not secrecy. Context-specific semantics:

  - **Bootstrap:** Image digest, signed manifest, or SBOM reference
  - **Re-attestation:** Server's X.509 certificate public key

**Instance Factor (IF):** Platform Evidence. An inherent, measurable property of the instance that is verifiable by the Verifier. The IF value itself is never transmitted directly; instead, the Attester proves possession through cryptographic means (e.g., signature, quote, attestation report).

**Validator Factor (VF):** A confidential, ephemeral challenge generated and released by the Verifier during **identity bootstrap procedures** after successful initial authentication of BF+IF possession. The VF MUST be bound to the IF (e.g., `VF = SHA-256(seed || IF)`) to ensure secrecy against network attackers.

**Renewal Factor (RF):** A cryptographic credential proving identity continuity. Following a full ECA identity lifecycle, RF is the signed **Attestation Result (AR)** issued by a Verifier from a prior bootstrap or renewal procedure. It is presented by an Attester as proof of an established identity.

**Instance Factor Pattern (IFP):** The set of defined methods for sourcing the private value for Instance Factor (`IF`). Three patterns are defined: hardware-rooted (Pattern A), orchestrator-provisioned (Pattern B), and artifact-based (Pattern C). For detailed specifications, see [](#instance-factor-patterns-ifp).

**Joint Factor Possession:** The cryptographic property where security derives from proving knowledge of multiple factors (`BF`+`VF` for bootstrap, `BF`+`RF`+`IF` for attestation renewal) rather than secrecy of individual components.

**Integrity Hash Beacon (IHB):** A SHA-256 binding of `BF` to `IF` that enables exposure-tolerant authentication while preventing pre-computation attacks to mitigate MiTM threats.

**Exchange Identifier (eca_uuid):** A unique identifier for each attestation lifecycle instance, used to construct artifact repository paths.

**Procedure Binding:** The Instance Factor (IF) MUST be bound to the a unique identifier (e.g., the `eca_uuid` for ECA bootstrap) to ensure freshness and prevent replay.

# Conceptual Model (Informational) {#conceptual-model}

The ECA protocol defines a unified pattern for the attestation lifecycle through two distinct but related attestation procedures. A compute instance without a verifiable identity can be bootstrapped on Day 0 to obtain a verifiable identity, and then use that verifiable identity for efficient attestation renewal on an ongoing basis.

~~~
                                 +---------------------------+
                                 |    Attestation Renewal    |
                                 |         Procedure         |
                                 +---------------------------+
                                             ^
              Input: Prior credential (RF)   | 
                     "Renewal Factor"        |
 +------------------>---------------------+-------+
 | (Updated AR becomes RF for next cycle) |  RF   |
 |                                        +-------+
 ^                                            | Output: Updated AR
 |                                            v
 |                                        +----------+
 |    [ Day N: Periodic Health-check ]    |(Updated) |
 +-------------------<--------------------|   AR     |
                                          +----------+
                                              ^
                                              |
                                              | Verifiable Identity
                                              | (Enters the cycle)
                                              |
                                 +--------------------------+
 [ Day 0: On-Ramp ]              |    Identity Bootstrap    |
 (Lacks Verifiable Identity)     |        Procedure         |
                                 +--------------------------+
~~~

## Initial Identity Bootstrap (Bootstrap Procedure)

This three-phase attestation procedure establishes initial identity for instances starting without any verifiable identity (a "cold start").

1.  **Attester proves possession** of a public **Binding Factor (BF)** and a measurable **Instance Factor (IF)**.
2.  **Verifier validates this proof** and releases a secret challenge (**Validator Factor (VF)**).
3.  **Attester proves joint possession** of the factors to receive its initial credential, which can serve as a Renewal Factor (RF) for subsequent attestation procedures.

## Continuous Verification (Attestation Renewal Procedure)

This lightweight, single-phase attestation procedure that enables ongoing verification for instances that already possess a verifiable identity from a prior attestation (the **Renewal Factor, or RF**).

1.  **Attester presents** its existing credential (RF) along with fresh measurements (Instance Factor, IF).
2.  **Verifying Relying Party (VRP) validates** the credential and appraises the new measurements against its policy.

## Credential Lifecycle {#credential-lifecycle}

A successful identity bootstrap procedure concludes with the issuance of an Attestation Result (AR). In the ECA-VM-BOOTSTRAP-V1 profile, this AR is realized as a signed Entity Attestation Token (EAT) (see []{#attestation-results}). This AR subsequently serves as the Renewal Factor (RF) in attestation renewal procedures.

**Typical Lifecycle:**

1.  **Bootstrap:** An instance performs the full identity bootstrap procedure and receives an initial signed AR.
2.  **Transition:** The instance uses the AR to establish a (D)TLS connection to a service.
3.  **Health check:** The service periodically challenges the instance using the attestation renewal pattern to verify its current state.
4.  **Renewal:** Before credential expiration, the instance performs attestation renewal to receive an updated AR with extended validity.

# Integration with Existing Frameworks {#integration-with-existing-frameworks}

## Alignment with Proposed SEAT Working Group {#seal-working-group-alignment}

This specification's **attestation renewal procedure** directly implements the proposed SEAT WG charter requirements for attested (D)TLS:

| SEAT Requirement | How ECA Satisfies |
|------------------|-------------------|
| **Per-connection freshness** | `certificate_request_context` bound into TEE Quote |
| **Leverage (D)TLS 1.3** | Via RFC 9261 Exported Authenticators |
| **Leverage RATS formats** | CMW, CoRIM, AR4SI, EAT |
| **No core (D)TLS modifications** | Only `cmw_attestation` extension |
| **Mutual attestation support** | Symmetric client/server attestation procedures |

## The SPIFFE/SPIRE Framework {\#the-spiffespire-framework}

The ECA protocol is designed to complement and enhance the SPIFFE/SPIRE framework by providing a standardized, interactive protocol for node attestation. SPIFFE/SPIRE's extensible node attestor architecture provides a clear integration path for new attestation methods, and ECA offers a mechanism specifically designed for environments where provider metadata is insufficient or unavailable.

For environments lacking a hardware root of trust, SPIRE's primary software-based bootstrap method is the Join Token. As a bearer token, its security model relies on the confidentiality of the token during delivery; if the token is intercepted or leaked, an attacker can use it to enroll a rogue workload.

The ECA identity bootstrap procedure presents a path for a next-generation, built-in SPIRE node attestor that operates without bearer tokens. By implementing ECA natively, the SPIRE agent could act as the ECA Attester and the SPIRE server as the ECA Verifier. This would evolve the enrollment model by replacing the dependency on "possession of a secret" with a model based on an interactive, challenge-response proof of the compute instance's identity. This approach, which uses measurable properties of the instance itself, is designed to drastically reduce the risk of impersonation.

Beyond initial bootstrapping, the ECA **attestation renewal procedure** offers a standardized mechanism for periodic, stateful health checks. A native ECA attestor could leverage this capability to provide continuous verification of workload integrity throughout its lifecycle, a critical requirement for modern infrastructure.

In this integrated model, a successful ECA bootstrap would conclude with an Attestation Result (AR) containing verifiable claims. The SPIRE server, acting as the Verifier, would validate this AR and use its claims (e.g., `eca_uuid`, EUID, `IHB`) as selectors for a secure registration policy, admitting the node to issue SVIDs as usual.

```
# Example of SPIRE registration entry using selectors from a native ECA attestor
spire-server entry create -spiffeID "spiffe://example.org/my-service"  
\-parentID "spiffe://example.org/spire/agent/eca/\<verifier\_id\>"  
\-selector "eca:euid:a1b2c3d4..."  
\-selector "eca:ihb:e5f6g7h8..."
```

## ECA in a WIMSE Architecture {#eca-in-a-wimse-architecture}

In WIMSE deployments, ECA provides a critical, standardized on-ramp for workloads to securely enter the identity ecosystem. While WIMSE aims to standardize portable identity, it first needs a reliable way to attest the workload before issuing it a credential, especially in environments without a built-in identity mechanism. ECA is designed to be that interoperable attestation protocol.

ECA's primary function can serve as the secure "front door" for the WIMSE workflow. It achieves this by replacing the reliance on static bearer tokens with an interactive, cryptographic protocol. The protocol's design is based on a challenge-response mechanism that establishes **Joint Factor Possession**, where a workload must prove knowledge of both its own measurable properties and a secret challenge from the Verifier. This provides strong cryptographic confidence that the WIMSE Identity Service is issuing a credential to the legitimate workload, not an impersonator.

By providing this standardized attestation mechanism, ECA solves several key challenges for WIMSE:

* **It creates a standardized on-ramp.** Instead of relying on a patchwork of platform-specific or less secure attestation methods, WIMSE can leverage ECA as a single protocol for proving a workload's identity, regardless of whether it's on bare-metal, at the edge, or in a multi-cloud environment.

* **It provides stronger security guarantees.** By using an interactive challenge-response mechanism, ECA offers a more robust security foundation than static credentials, which are vulnerable to interception.

* **It enables the full lifecycle.** Beyond bootstrapping, the ECA **attestation renewal procedure** provides a standard for the continuous verification needed to maintain trust in long-running workloads, a key requirement for any robust identity framework.

### Role Mapping {#role-mapping}

When integrating ECA into a WIMSE-compliant system, the roles map as follows:

| ECA Role | WIMSE Role | Description |
| :--- | :--- | :--- |
| **Attester** | **Workload** | The ephemeral compute instance requiring identity. |
| **Verifier** | **Identity or Attestation Service** | The entity within the trust domain that validates the workload's claims. |
| **Relying Party** | **Service Consumer or Authorization Service** | An entity that consumes the Attestation Result to make an authorization decision. |

## BRSKI (Bootstrapping Remote Secure Key Infrastructure) {#brski-bootstrapping}

BRSKI [@?RFC8995] and ECA are complementary. BRSKI solves manufacturer-anchored onboarding for physical devices based on supply-chain provenance. ECA targets just-in-time software and instance attestation at runtime for ephemeral compute, which typically lacks a manufacturer-provided identity. An operator could use BRSKI to enroll a physical device, and subsequently use ECA for continuous attestation of the software state on that device.

# Identity Bootstrap Specification {#protocol-overview}

This section specifies the **identity bootstrap procedure** in detail. The attestation renewal procedure is specified in [](#attestation-renewal-specification).

The identity bootstrap procedure is the security-critical foundation of ECA. All formal security analysis ([](#app-formal-modelling-informative)) applies to this procedure type. It follows a three-phase process, beginning with the Attester in a Privileged Credential Vacuum and concluding with the Verifier producing a signed Attestation Result (AR) upon successful validation.

## Validation Gates {#sec-validation-gates}

The Verifier enforces a sequence of fail-closed validation gates in a specific order derived from the protocol's formal model. Each gate represents a critical check that must pass before proceeding.

### Phase 1 Appraisal Gates (Bootstrap)

1.  **MAC Verification:** Verifies the integrity of the Phase-1 payload using an HMAC tag derived from `BF` and `IF`.
    -   Failure Action: Immediate termination. Publish error status `MAC_INVALID`.

2.  **Instance Authorization:** Checks if the Attester's identity (e.g., derived from a unique Exchange Identifier or Instance Factor) is authorized to proceed.
    -   Failure Action: Immediate termination. Publish error status `ID_MISMATCH`.

3.  **IHB Validation:** Confirms that the received Integrity Hash Beacon (IHB) matches the expected value for the authorized instance.
    -   Failure Action: Immediate termination. Publish error status `IHB_MISMATCH`.

4.  **KEM Public Key Match:** Ensures the ephemeral encryption public key in the payload matches the expected key for the session.
    -   Failure Action: Immediate termination. Publish error status `KEM_MISMATCH`.

### Phase 3 Appraisal Gates (Bootstrap)

5.  **Evidence Time Window:** Validates that the `iat`, `nbf`, and `exp` claims in the final EAT are within an acceptable time skew (e.g., ±60 seconds).
    -   Failure Action: Immediate termination. Publish error status `TIME_EXPIRED`.

6.  **EAT Schema Compliance:** Checks that the EAT contains all required claims with the correct types and encodings.
    -   Failure Action: Immediate termination. Publish error status `SCHEMA_ERROR`.

7.  **EAT Signature:** Verifies the Ed25519 signature on the EAT using the public key derived from `BF` and `VF`.
    -   Failure Action: Immediate termination. Publish error status `SIG_INVALID`.

8.  **Nonce Match:** Ensures the nonce in the EAT matches the nonce the Verifier issued in Phase 2, proving freshness.
    -   Failure Action: Immediate termination. Publish error status `NONCE_MISMATCH`.

9.  **JP Validation:** Verifies the Joint Possession proof, ensuring the final identity key is bound to the attestation procedure context.
    -   Failure Action: Immediate termination. Publish error status `KEY_BINDING_INVALID`.

10. **PoP Validation:** Verifies the final Proof-of-Possession tag, confirming the Attester's knowledge of both `BF` and `VF`.
    -   Failure Action: Immediate termination. Publish error status `POP_INVALID`.

11. **Identity Uniqueness (Replay):** Persists the terminal state for the unique Exchange Identifier and rejects any future attempts to use it.
    - Failure Action: Immediate termination. Publish error status `IDENTITY_REUSE`.

These gates align with the formal model's events (see [](#core-security-properties-bootstrap-model)):
- Gate 8 Nonce Match (per AttesterUsesNonce event).
- Gate 9 JP Validation (per VerifierValidatesWithKey event).
- Gate 10 PoP Validation (per VerifierAccepts event).

## Phase 1: Authenticated Channel Setup {#phase-1-authenticated-channel-setup}

-   **Attester** generates an ephemeral X25519 keypair deterministically from `BF` + `IF`.
-   Computes the Integrity Hash Beacon (IHB): `IHB = SHA-256(BF || IF)`.
-   Publishes a CBOR payload containing `{kem_pub, ihb}` and an associated HMAC tag to the repository.
-   **Verifier** retrieves the published artifacts and validates them against Gates 1-4.

## Phase 2: Challenge and Validator Factor Release {#phase-2-challenge-and-validator-factor-release}

- **Verifier** generates:
  - A fresh `VF` (≥128 bits) 
  - A 16-byte nonce
  - A fresh ephemeral Ed25519 keypair for this specific bootstrap procedure
- Encrypts `{VF, nonce}` using HPKE to the Attester's ephemeral public key
- Signs the encrypted payload with the ephemeral procedure key (the Verifier's long-term identity key MUST NOT be used)
- Publishes the signed payload and the ephemeral public key to the repository
- **Attester** retrieves the published payload, verifies the signature using the published ephemeral public key, and decrypts the `VF`

## Phase 3: Joint Possession Proof {#phase-3-joint-possession-proof}

-   **Attester** derives a final Ed25519 signing keypair deterministically from `BF`+`VF`.
-   Creates a signed EAT containing identity claims, the Verifier's nonce, and a final Proof-of-Possession HMAC. The Proof-of-Possession (PoP) proves knowledge of the secret VF without revealing it, while the Joint Possession Proof (JP) binds the final identity key to the procedure context.
-   Publishes the signed EAT to the repository.
-   **Verifier** retrieves the final EAT and validates the **Evidence EAT** against Gates 5-11. Upon success, the Verifier generates and signs a separate **Attestation Result (AR)**, which cryptographically confirms the validity of the claims made in the Evidence.

# Protocol States {#sec-states}

These states apply to the identity bootstrap procedure; see []{#attestation-renewal-specification} for renewal.

| State                     | Description                                |
| :------------------------ | :----------------------------------------- |
| `INIT`                    | New attestation lifecycle initiated.       |
| `AWAITING_ATTESTER_PROOF` | Awaiting Phase 1 artifacts.                |
| `PROVING_TO_ATTESTER`     | Publishing Phase 2 artifacts.              |
| `AWAITING_EVIDENCE`       | Awaiting Phase 3 artifacts.                |
| `VALIDATING`              | Appraisal of evidence.                     |
| `SUCCESS`                 | Terminal success state.                    |
| `FAIL`                    | Terminal failure state.                    |

## State Transitions {#sec-state-transitions}

| State                     | Event                                    | Next State                |
| :------------------------ | :--------------------------------------- | :------------------------ |
| `INIT`                    | New attestation lifecycle.               | `AWAITING_ATTESTER_PROOF` |
| `AWAITING_ATTESTER_PROOF` | Phase 1 artifacts retrieved and validated. | `PROVING_TO_ATTESTER`     |
| `PROVING_TO_ATTESTER`     | Sign Phase 2 with ephemeral key.            | `AWAITING_EVIDENCE`       |
| `AWAITING_EVIDENCE`       | Phase 3 artifacts retrieved.             | `VALIDATING`              |
| `VALIDATING`              | Sign final AR with long-term identity key   | `SUCCESS`                 |
| Any                       | Any validation check fails or timeout.   | `FAIL`                    |

# Attestation Renewal Specification {#attestation-renewal-specification}

This section specifies the attestation renewal procedures for instances that possess an existing credential (a Renewal Factor) from a prior attestation.

A preliminary formal model for this procedure and its security properties are provided. See []{#core-security-properties-renewal-model}

## Prerequisites {#Attestation Renewal Procedures-prerequisites}

-   The instance possesses a Renewal Factor (RF).
-   The Verifying Relying Party (VRP) has a record of the expected identity associated with the `RF`.
-   The Binding Factor (BF) remains stable or is updated according to policy.

## Generic Attestation Renewal Pattern {#generic-renewal-pattern}

The attestation renewal procedure is a single-phase exchange.

**Attester actions:**
1.  Collect the current Instance Factor (IF), such as fresh measurements or quotes.
2.  Construct an Evidence payload containing `{BF, RF, IF, attestation_procedure_id, timestamp}`.
3.  Sign the Evidence with a key derived from the RF.
4.  Transmit the signed Evidence to the Verifying Relying Party.

**Verifying Relying Party (VRP) actions:**
1.  Receive the Evidence payload.
2.  Validate the RF signature against the known credential.
3.  Verify that the RF subject matches the expected identity for the BF.
4.  Appraise the IF measurements against policy.
5.  Confirm the `attestation_procedure_id` is unique to prevent replay.
6.  If all checks pass, emit an updated Attestation Result (AR).

### Validation Gates {#attestation-renewal-validation-gates}

These gates align with the formal model's events (see []{#core-security-properties-renewal-model}).

1.  **RF Signature Verification**: Validates credential authenticity
    -   Failure: `CREDENTIAL_INVALID`

2.  **Identity Continuity**: Confirms RF subject matches expected identity
    -   Failure: `IDENTITY_MISMATCH`

3.  **Measurement Appraisal**: Verifies IF against policy (e.g., CoRIM)
    -   Failure: `MEASUREMENT_REJECTED`

4.  **Freshness Binding**: Ensures attestation_procedure_id is unique and properly bound
    -   Failure: `REPLAY_DETECTED` or `BINDING_INVALID`

5.  **Timestamp Validation**: Confirms Evidence timestamp within acceptable window
    -   Failure: `TIME_EXPIRED`
    
### Transport-Specific Implementations {#attestation-renewal-transport-specific}

#### Session-Bound (D)TLS Pattern

When using TLS Exported Authenticators [@?RFC9261]:

-   **Binding Factor**: Server's X.509 certificate public key
-   **Renewal Factor**: Prior EAT from bootstrap
-   **Instance Factor**: Fresh TEE Quote with attestation_procedure_id in REPORTDATA
-   **attestation_procedure_id**: `certificate_request_context` from CertificateRequest

**Freshness**: Cryptographic binding of Quote to session context ensures per-connection freshness.

**Security**: TLS 1.3 forward secrecy + RF validation + Quote appraisal

See [](#concrete-example-continuous-tee-attestation-over-dtls) for a complete example.

#### Custom Transport Pattern

Implementations using other transports MUST ensure:

-   Renewal Factor (RF) signature verification
-   Exchange Identifier uniqueness (replay protection)
-   Instance Factor freshness (e.g., timestamps, nonces, or context binding)
-   Integrity protection of Evidence payload

# Post-Attestation Patterns {#post-attestation-patterns}

Once an attestation procedure concludes, the Attestation Result (AR) can be used to make policy decisions. A Verifier may transmit the AR to the successful Attester, which can then present it to Relying Parties (RPs) that trust the Verifier's signature. The full scope of AR presentation to RPs is outside the scope of this document.

~~~
   Attester                  Verifier               Relying Party
 (Workload)            (Attestation Service)    (CA / IAM System)
      |                           |                       |
      |----- Evidence ----------> |                       |
      | (e.g., configuration)     |..Appraise vs. Policy..|
      |                           | (e.g., platform state |
      |<--- Attestation Result ---|                       |
      |                                                   |
      |--------------------- CSR + Attestation Result---->|
      |                                                   |
      |<--------------------- Certificate / Token --------|
~~~

## Chaining and Hierarchical Trust {#chaining-and-hierarchical-trust}

ECA attestation procedures can be chained to propagate trust across layers by using the signed AR from one attestation procedure as the Renewal Factor (RF) for a subsequent procedure. For example, a physical host can perform a bootstrap to prove hardware integrity, producing `AR_host`. A virtual machine on that host can then perform a attestation renewal procedure using `AR_host` as its RF to prove it is running on an attested physical host. See []{#risks-and-mitigations-for-composable-deployments} for non-normative operational considerations.

**Example (Bare-metal → VM):**

1.  Physical host performs bootstrap with TPM-based IF (Pattern A)
    -   Output: `AR_host` proving hardware integrity

2.  VM on that host performs attestation renewal
    -   **RF:** `AR_host` (proves running on attested hardware)
    -   **IF:** VM-specific measurements
    -   Output: `AR_vm` proving "healthy VM on healthy host"

## Risks and Mitigations for Composable Deployments {#risks-and-mitigations-for-composable-deployments}

While ECA is designed to be composable (e.g., chaining attestations), realizing this benefit requires operational discipline. Operators should be aware of the following risks:

**Risks from Custom Integration:** The security of the overall system depends on the integrity of each link in the chain. Custom scripts or shims used to connect different attestation layers can inadvertently reintroduce vulnerabilities. It is STRONGLY RECOMMENDED to use standardized, well-vetted integrations over bespoke "glue code."

**Organizational Friction:** In multi-team environments, clear ownership of the end-to-end attestation process is critical. Without a shared governance model, configuration drift between what DevOps provisions, what Security expects, and what the application implements can lead to systemic failures.

# Security Considerations {#security-considerations}

This section addresses security properties and considerations for ECA attestation procedures.

## Security Analysis Scope {#security-analysis-scope}

The formal security analysis presented in this document (see [](#app-formal-modelling-informative)) covers both the **identity bootstrap procedure** and the **attestation renewal procedure**. The identity bootstrap procedure assumes no prior relationship between Attester and Verifier and must establish initial trust through cryptographic proof of joint factor possession. Attestation renewals assume an existing credential from prior attestation and operate under different threat models, with security properties that depend on the integrity of the initial bootstrap, the Renewal Factor credential, and transport-specific properties.

## Identity Bootstrap Procedure Security {#identity-bootstrap-procedure-security}

The Verifier's ability to appraise evidence is anchored in a trust model that relies on upstream supply chain roles. An Endorser (e.g., a hardware manufacturer) supplies endorsements for the hardware's authenticity, while a Reference Value Provider supplies the expected 'golden' measurements for the software stack. The Verifier is configured to trust these entities when making its appraisal decision.

**Trust Boundaries:** Without hardware roots of trust, the security scope is limited to passive network observers rather than compromised infrastructure providers. Hardware-rooted Instance Factor Pattern A addresses this limitation. For detailed pattern specifications, see [](#instance-factor-patterns-ifp). This hardware-based protection is critical for mitigating State Reveal attacks, as a preliminary formal analysis confirmed that a compromise of the Attester's software environment can expose ephemeral keys used in the attestation procedure (see [](#attester-state-reveal)).

**Secrets Handling:** Derived keys are sensitive cryptographic material. Implementations MUST handle them securely in memory (e.g., using locked memory pages) and explicitly zeroize them after use.

## Attestation Renewal Security {#attestation-renewal-security}

> Note: Unlike identity bootstrap procedures, attestation renewal does not protect against initial identity forgery. If an attacker compromises the identity bootstrap procedure, they can obtain a valid `RF` and perform subsequent attestation renewals. Therefore, security of the identity bootstrap procedure (including a hardware-rooted `IF` for zero-trust scenarios) remains critical for overall system security.

Re-attestation security derives from:

1.  **Bootstrap foundation**: The initial credential established via a cryptographically verified bootstrap acts as the Renewal Factor (RF).
2.  **Transport security**: Channel properties (e.g., TLS 1.3 forward secrecy).
3.  **Continuous appraisal**: Fresh IF measurements validated against policy.
4.  **Replay protection**: Exchange Identifier uniqueness enforcement.

## Impersonation Risk {#impersonation-risk}

The security properties of the identity bootstrap procedure depend on an adversary being unable to generate a valid cryptographic proof for an Instance Factor (IF) they do not legitimately possess. An impersonation attack would require an adversary to forge a proof (e.g., a TPM quote) corresponding to a known `IF` for a specific attestation procedure's Binding Factor (BF). The protocol's primary defense is that the `IF` itself is never transmitted, only a proof derived from it. Therefore, operational controls MUST protect the integrity of the measurement source (e.g., a vTPM) and the out-of-band channel through which the Verifier learns the expected measurement.

To reduce this risk, operators SHOULD minimize the time window between when an Attester becomes operational with its `BF` and when a Verifier is available to appraise its evidence.

## Threat Models {#threat-models}

ECA is designed to address two key threat models: the **Network Attacker** (a Dolev-Yao-style MiTM who controls communication but not participant state) and the **Malicious Provider** (a privileged insider with control-plane access). Analysis from an exploratory ProVerif model suggests that the protocol, as modelled, defeats the Network Attacker through its cryptographic binding and joint possession proofs.

The choice of Instance Factor Pattern directly maps to the desired security goals:
-   **IFP Patterns B and C** are sufficient for workload portability and standardization. They protect against Network Attackers but assume the underlying infrastructure provider is trusted.
-   **IFP Pattern A** is designed for high-assurance and zero-trust environments. By anchoring the `IF` in a hardware root of trust (HRoT), it is sufficient to mitigate the Malicious Provider threat model.

## Attester State Compromise {#attester-state-compromise}

The preliminary formal model confirms that the protocol cannot maintain secrecy of the Validator Factor (VF) if the Attester's runtime state is compromised and its ephemeral decryption key is extracted. A formal "State Reveal" analysis was conducted where the Attester's ephemeral private key was deliberately leaked to an attacker (see [](#attester-state-reveal)). The model confirmed that this compromise allows a passive network attacker to intercept and decrypt the Phase 2 ciphertext from the Verifier, revealing the `VF`.

This result establishes the protocol's security boundary regarding the Attester's runtime state. The only viable mitigation for this threat is the use of IFP Pattern A (hardware-rooted), where the Instance Factor and all keys derived from it are protected by a hardware root of trust.

## Verifier Key Compromise Impact Analysis {#verifier-key-compromise-impact-analysis}

The Verifier uses two distinct types of keys in the identity bootstrap procedure:

1. **Ephemeral Procedure Key**: Used to sign Phase 2 artifacts (`VF` + `vnonce`)
2. **Long-term Identity Key**: Used to sign final Attestation Results (`AR`)

## Key Management Requirements {#key-management-requirements}

### Ephemeral Procedure Keys

- MUST be generated fresh for each identity bootstrap procedure
- MUST be discarded after procedure completion
- SHOULD use Ed25519 for performance and security

#### Ephemeral Procedure Key Compromise

The Verifier MUST generate a fresh ephemeral keypair for each identity bootstrap procedure to sign Phase 2 artifacts. This key is single-use and discarded after the procedure completes.

If an ephemeral procedure key is compromised during an active bootstrap procedure, an attacker could:
- Inject forged (VF', nonce') pairs for that specific procedure
- Cause the Attester to derive incorrect final identity keys

However, the protocol's cryptographic design ensures this only enables denial of service, not authentication bypass:
- The resulting Evidence will contain wrong nonce (fails Gate 8)
- Wrong JP proof (fails Gate 9)  
- Wrong PoP tag (fails Gate 10)
- No legitimate Verifier should accept this Evidence

### Long-term Identity Keys  

- MUST be protected as high-value assets
- MUST be used only to sign final Attestation Results
- SHOULD be rotated according to organizational policy
- MAY be backed by organizational PKI for trust distribution

#### Long-term Identity Key Compromise

Compromise of the Verifier's long-term identity key used to sign Attestation Results would allow an attacker to forge ARs. This represents a complete compromise of the trust domain and requires immediate revocation and reissuance of the Verifier's identity credentials.

The impact is independent of transport mechanism and affects all relying parties that trust the compromised key.

# Non-Goals {#non-goals}

ECA explicitly does not attempt to address several related but distinct problems:

- **Software-Based Mitigation of Hypervisor Threats:** ECA does not replace the need for HRoTs where the threat model must assume a compromised service provider, hypervisor, or related platform risks.

- **Replacement for Single-Cloud IMDS:** ECA is not intended to replace provider-native IMDS for workloads operating within a single, trusted cloud environment.

- **Infrastructure Trust Bootstrapping:** ECA assumes operational mechanisms exist for manifest distribution, Verifier discovery, and PKI infrastructure. It integrates with existing trust foundations rather than replacing them.

- **Identity Framework Replacement:** ECA is designed to complement systems like SPIFFE/SPIRE, for example by acting as a high-assurance node attestor.

- **Manufacturer Provenance:** ECA handles runtime attestation and does not provide supply-chain attestation or manufacturer-anchored trust.

# Operational Considerations {#operational-considerations}

**Scalability:** The use of a simple artifact repository allows for high scalability using standard web infrastructure like CDNs and object storage.

**Time Synchronization:** Reasonably synchronized time is REQUIRED for proper validation of time-based claims. The use of a time synchronization protocol like NTP [@?RFC5905] is RECOMMENDED.

**Polling:** For repository-based transports, polling MUST use exponential backoff with jitter.

**Provisioning and Repository Access:** The ECA protocol requires the Attester to publish artifacts while adhering to the **Privileged Credential Vacuum** principle. This can be achieved using standard cloud primitives that grant ephemeral, narrowly-scoped write capabilities without provisioning long-term secrets, such as a time-limited pre-signed URL for an object store.

# IANA Considerations {#iana-considerations}

TODO IANA

# Implementation Status {#implementation-status}

An end-to-end implementation of the bootstrap profile is publicly available at [[ECA-SAE-PROTOTYPE](#ext-links)], demonstrating the three-phase attestation procedure, HPKE-based challenge delivery, COSE-based Evidence, and SAE [@?I-D.ritz-sae] transport. The reference implementation achieves protocol execution in approximately 1.3 seconds.

# Acknowledgments {#acknowledgments}

The design of this protocol was heavily influenced by the simplicity and security goals of the age file encryption tool. The protocol's core cryptographic mechanisms would not be as simple or robust without the prior work of the IETF community in standardizing modern primitives, particularly Hybrid Public Key Encryption (HPKE) in [@?RFC9180].

The integration with Exported Authenticators draws from [@?I-D.fossati-tls-exported-attestation].

The SEAT Working Group charter and Confidential Computing Consortium Attestation SIG provided the use case requirements that shaped the attestation renewal model.

The authors wish to thank the contributors of these foundational standards for making this work possible.

# External Links {#ext-links}

**[ECA-FORMAL-MODELS]**

: "ECA ProVerif Formal Models (bootstrap and renewal)", <https://github.com/eca-sae/internet-drafts-eca-sae/blob/pv0.5.0/formal-model/>, October 2025.

**[ECA-SAE-PROTOTYPE]**

: "OSS MTI prototype for the ECA & SAE Internet-Drafts", <https://github.com/eca-sae/prototype-eca-sae/tree/proto-0.1.0>, September 2025.

{backmatter}

# Formal Modelling (Informative) {#app-formal-modelling-informative}

This appendix presents the ongoing formal security analyses of the ECA **identity bootstrap procedure** and the **attestation renewal procedure** using ProVerif [[ECA-FORMAL-MODELS](#ext-links)]. The analysis assumes a Dolev–Yao network attacker and verifies core security properties for each procedure.

The protocol's bootstrap security properties were analyzed using an exploratory formal model in ProVerif. The model assumes a powerful Dolev-Yao network attacker who can intercept, modify, and inject messages. It also correctly models the Binding Factor (`BF`) as public knowledge from the start, as per the protocol's "exposure tolerance" principle ([](#core-design-principles)).

The analysis was conducted in two parts: verification of the core security properties against a network attacker, and an analysis of the protocol's behavior under specific key compromise scenarios to define its security boundaries.

## Core Security Properties (Bootstrap) {#core-security-properties-bootstrap-model}

In the baseline model, all core security goals were successfully shown to hold against a network attacker.

| Property | ProVerif Query | Result | Interpretation |
| :--- | :--- | :--- | :--- |
| **Authentication** | `inj-event(VerifierAccepts(...)) ==> inj-event(AttesterInitiates(...))` | **True** | The Verifier only accepts an attestation if a unique Attester legitimately initiated it. This prevents an attacker from impersonating the Attester. |
| **Freshness** | `event(AttesterUsesNonce(n)) ==> event(VerifierGeneratesNonce(n))` | **True** | The Attester will only use a nonce that was genuinely generated by the Verifier for that attestion procedure. This property is the basis for **Gate 8 (Nonce Match)** and prevents replay attacks. |
| **Key Binding** | `event(VerifierValidatesWithKey(pk)) ==> event(AttesterPresentsKey(pk))` | **True** | The final identity key that the Verifier checks is unambiguously bound to the Attester that participated in the attestation procedure, validating **Gate 9 (JP Validation)**. |
| **Confidentiality** | `not (event(VFReleased(vf)) && attacker(vf))` | **True** | The secret `ValidatorFactor` (`VF`) is never revealed to a network attacker, satisfying a fundamental security goal of the protocol. |

## Core Security Properties (Attestation Renewal) {#core-security-properties-renewal-model}

**Model summary.** The renewal model binds **BF+IF+RF** and uses the TLS `certificate_request_context` as the freshness nonce (`REPORTDATA = hash(context)`), matching the renewal spec and the (D)TLS EA example. 

| Property | ProVerif Query | Result | Interpretation |
| :--- | :--- | :--- | :--- |
| **Authentication**        | `inj-event(VRPAcceptsRenewal(...,ctx)) ==> inj-event(AttesterAnswersChallenge(...,ctx))` | **True** | Verifier accepts only if a unique Attester legitimately initiated this renewal. |
| **Freshness (context)**   | `event(AttesterUsesContext(ctx)) ==> event(VRPGeneratesContext(ctx))` | **True** | Evidence is fresh and bound to the Verifier-generated EA context. |
| **RF integrity**          | `event(ValidRFVerified(rf)) ==> event(AttesterAnswersChallenge(...,rf,ctx))` | **True** | The presented RF corresponds to the ongoing renewal, not replay. |
| **Measurement freshness** | `event(FreshMeasurementsVerified(ifa)) ==> event(AttesterUsesContext(ctx))` | **True** | TEE quote is fresh and correctly bound to the EA context. |

## Boundary Analysis (Advanced Threat Models) {#boundary-analysis-advanced-threat-models}

Additional tests were performed to formally define the protocol's security boundaries under specific compromise scenarios. 

### Key Compromise Impersonation (KCI) {#key-compromise-impersonation-kci}

A test was conducted where an attacker compromises an `InstanceFactor` (`IF`) from one attestation procedure and attempts to impersonate a Verifier in a different procedure. The model indicated this attack is not possible. The KCI security query passed, confirming that compromising a secondary factor (`IF`) does not allow an attacker to forge messages from a primary party (the Verifier), as they still lack the Verifier's private signing key.

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

- **Mitigation:** This analysis provides the formal rationale for ephemeral keys for each unique bootstrapping procedure

### Attester State Reveal {#attester-state-reveal}

A test was conducted modeling a compromised Attester whose ephemeral private decryption key is leaked:

- **Result:** The model demonstrated that this allows a passive attacker to decrypt the Phase 2 ciphertext and steal the `ValidatorFactor` (`VF`) (`not (event(VFReleased(vf)) && attacker(vf))` was **False**).

- **Interpretation:** This result formally establishes the security boundary discussed in [](#attester-state-compromise)

- **Mitigation:** This analysis provides the formal rationale for hardware-rooted Instance Factor Pattern A when the threat model must assume compromise of the underlying provisioning platform. For pattern specifications, see [](#instance-factor-patterns-ifp).


# Normative ECA-V1 Profiles {#normative-eca-v1-profiles}

This document defines the protocol abstractly. Concrete cryptographic mechanisms are supplied by profiles. A conforming implementation MUST implement at least one profile, and any chosen profile MUST preserve all requirements in [](#protocol-requirements-normative).

> Note: No MTI Algorithms in this revision (-01). Reference profiles are published separately to enable experimentation and interoperability testing.

Key Separation (Architecture requirement): Regardless of profile, implementations MUST maintain strict separation between:
- Phase 2 encryption keys (used by the Verifier to release VF to the Attester), and
- Phase 3 identity/signing keys (used by the Attester to sign Evidence/EAT).

Profiles typically achieve separation via domain-separated KDF invocations; however, any mechanism that guarantees computational unlinkability between Phase 2 and Phase 3 key material is acceptable, provided the invariants in [](#protocol-requirements-normative) remain intact.

## Proof-of-Possession Construction (Bootstrap) {#sec-pop}

A profile MUST provide a PoP mechanism that proves joint-possession of both factors used across the ceremony and binds the result to the session context. At minimum, the PoP's authenticated input MUST cover:

- Ceremony identifier (e.g., `eca_uuid` or `certificate_request_context`),
- the Integrity Hash Beacon (IHB) or an equivalent `BF`+`IF` binding,
- the Attester's Phase-3 signing public key, and
- the Verifier's freshness input (e.g., `vnonce`).

The PoP output MUST be verifiable by the Verifier without additional round trips and MUST be integrity-protected under a key that is infeasible to compute without both factors required by the active profile.

# ECA-VM-BOOTSTRAP-V1 Reference Profile {#bootstrap-reference-profile}

> Stability note: This profile documents the concrete choices used by the reference prototype to enable experimentation and interop. It is non-normative and may change in future drafts based on feedback.

## Primitives {#primitives}

- Hash / KDF: HKDF-SHA-256 (RFC5869), SHA-256 (RFC6234)
- MAC: HMAC-SHA-256
- Signatures: Ed25519 (RFC8032)
- KEM/HPKE: X25519 + HPKE base mode (RFC9180) for Verifier -> Attester secrecy in Phase 2. The Exchange Identifier is used as the AAD, and the `info` parameter for key derivation is `"ECA/v1/hpke"`.
- Nonces: Verifier freshness `vnonce` is exactly 16 bytes (encoded base64url, unpadded)

## Integrity Hash Beacon (IHB) {#integrity-hash-beacon-ihb}

- `IHB = SHA-256( BF || IF )`, rendered as lowercase hex for transport where necessary.

## Deterministic Key Material {#deterministic-key-material}

All keys are deterministically derived from attestation procedure inputs via domain-separated HKDF invocations. Notation: `HKDF-Extract(salt, IKM)` then `HKDF-Expand(PRK, info, L)`. The Exchange Identifier is appended to the `salt` in all derivations to ensure session uniqueness.

- **Phase 1 MAC key (Attester artifact MAC)**

  - `IKM = BF || IF`
  - `salt = "ECA:salt:auth:v1" || attestation_procedure_id`
  - `info = "ECA:info:auth:v1"`
  - `K_MAC_Ph1 = HKDF-Expand( HKDF-Extract(salt, IKM), info, 32 )`
  - Usage: HMAC-SHA-256 over the CBOR Phase-1 payload bytes.

- **Phase 2 ECDH/HPKE seed (Attester's ephemeral X25519 keypair)**

  - `IKM = BF || IF`
  - `salt = "ECA:salt:encryption:v1" || attestation_procedure_id`
  - `info = "ECA:info:encryption:v1"`
  - `seed32 = HKDF-Expand( HKDF-Extract(salt, IKM), info, 32 )`
  - The Attester forms an X25519 private key by clamping `seed32` per RFC7748; the public key is derived normally.
  - The Verifier uses HPKE with the Attester's public key to encrypt `{VF, vnonce}`.

- **Phase 3 signing key (Attester's Ed25519 identity keypair)**

  - `IKM = BF || VF`
  - `salt = "ECA:salt:composite-identity:v1" || attestation_procedure_id`
  - `info = "ECA:info:composite-identity:v1"`
  - `sk_seed32 = HKDF-Expand( HKDF-Extract(salt, IKM), info, 32 )`
  - The Attester initializes Ed25519 with `sk_seed32` as the private key seed and derives the corresponding public key.

- **HPKE KDF `info` parameter:** `info = "ECA/v1/hpke"`

## Phase Artifacts {#phase-artifacts-profile}

*This section provides a high-level description of the payloads. For concrete byte-for-byte examples, see the reference implementation.*

### Phase 1 Payload (Attester→Repo) {#phase-1-payload-attester-repo-profile}

The Phase-1 payload is a CBOR map containing the following claims, which is then protected by an external HMAC tag.

| Claim | Value Type | Description |
| :--- | :--- | :--- |
| `kem_pub` | `bstr` (raw 32 bytes) | Attester's ephemeral X25519 public key. |
| `ihb` | `tstr` (lowercase hex) | Integrity Hash Beacon. |

### Phase 2 Payload (Verifier -> Repo) {#phase-2-payload-verifier-repo-profile}

The Phase-2 payload is a signed CBOR map containing the following claims.

| Claim | Value Type | Description |
| :--- | :--- | :--- |
| `C` | `tstr` (base64url unpadded) | HPKE ciphertext |
| `vnonce` | `tstr` (base64url unpadded) | The Verifier-generated nonce. |

The plaintext for HPKE encryption is the direct concatenation of the raw bytes: `plaintext = VF || vnonce`.

### Phase 3 Payload (Attester -> Repo) {#phase-3-payload-attester-repo-profile}

The Phase-3 payload is a signed EAT as defined in [](#evidence-claims). The profile-specific constructions for proofs are as follows:

- **Joint-Possession Proof (concrete for this profile):**
  - `jp_proof = SHA-256( BF || VF )`, rendered as lowercase hex.
- **Proof-of-Possession (concrete for this profile):**
  - First, a bound hash is computed from the session context:
    - `bound_data = attestation_procedure_id || IHB_bytes || eca_attester_id_bytes || vnonce_raw_bytes`
    - `bound_hash = SHA-256( bound_data )`
  - Then, a dedicated MAC key is derived:
    - `IKM = BF || VF`
    - `salt = "ECA:salt:kmac:v1" || attestation_procedure_id`
    - `info = "ECA:info:kmac:v1"`
    - `K_MAC_PoP = HKDF-Expand( HKDF-Extract(salt, IKM), info, 32 )`
  - Finally, the PoP tag is computed over the bound hash:
    - `pop_tag = base64url( HMAC-SHA-256( K_MAC_PoP, bound_hash ) )`
- The `jp_proof` and `pop_tag` are included in the EAT, which is then signed with the Attester's Ed25519 key.

## Verification (Verifier) {#verification-verifier-profile}

- Verify Phase-1 MAC with `K_MAC_Ph1`.
- Verify the signed Phase-2 payload with the Verifier's public key; HPKE-Open with Attester's kem key to recover `{VF, vnonce}`.
- Recompute Attester signing key from `BF||VF` and verify the EAT signature.
- Recompute `jp_proof` and `pop_tag` inputs and compare constant-time.
- Apply local appraisal policy; on success, emit an Attestation Result bound to the Exchange Identifier.

## Interop Notes {#interop-notes}

- **Encodings:** All binary fields referenced in EAT must be explicitly encoded (e.g., base64url) and stated as such in the claims table. NumericDate claims (`iat`, `nbf`, `exp`) use 64-bit unsigned integers.
- **Side-Channel Resistance:** To mitigate timing attacks, implementations SHOULD use constant-time cryptographic comparisons. Payloads that are inputs to cryptographic operations (e.g., Evidence) MAY be padded to a fixed size using a length-prefix scheme to ensure unambiguous parsing.

# Concrete Example: Continuous TEE Attestation over (D)TLS {#concrete-example-continuous-tee-attestation-over-dtls}

This appendix provides a complete example of attestation renewal for a long-running TEE workload using (D)TLS Exported Authenticators, integrating the work established by Fossati et al. [@?I-D.fossati-tls-exported-attestation].

## Scenario {#scenario}

We consider Server as Attester.
- Client establishes initial TLS 1.3 connection to TEE-based service
- Service performed bootstrap via ECA during provisioning
- Client needs to verify TEE health before processing sensitive data
- Service presents current measurements via attestation renewal

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

This concrete flow is the reference for the renewal ProVerif model (`REPORTDATA = SHA-256(certificate_request_context)`), see []{#core-security-properties-renewal-model}.

# SAE Transport Profile {#sae-transport-profile}

> Note: This appendix provides a non-normative summary of SAE integration. For the normative SAE specification, see [@I-D.ritz-sae].

## Repository Requirements {#repository-requirements}

- Strong read-after-write consistency
- Immutable artifact storage
- Access control for write operations
- Support for HEAD/GET operations

## Artifact Lifecycle {#artifact-lifecycle}

### Bootstrap Ceremony {#bootstrap-ceremony-sae}

Full three-phase ceremony as defined in [](#protocol-overview):

**Repository Structure:**
```
/<eca_uuid>/phase1.cbor
/<eca_uuid>/phase1.hmac
/<eca_uuid>/phase2.cbor
/<eca_uuid>/phase2.sig
/<eca_uuid>/phase3.eat
/<eca_uuid>/phase3.sig
/<eca_uuid>/status
```

### Re-attestation Ceremony {#re-attestation-ceremony-sae}

Simplified single-phase exchange:

**Repository Structure:**
```
/<eca_uuid>/evidence.eat
/<eca_uuid>/evidence.sig
/<eca_uuid>/result.ar
/<eca_uuid>/status
```

## Accept-Once Enforcement {#accept-once-enforcement}

Verifiers MUST maintain persistent storage tracking accepted `eca_uuid` values. Recommended minimum retention: AR validity period + clock skew tolerance.

# EAT profiles {#app-evidence-profiles}

## Evidence Claims {#evidence-claims}

| Claim | EAT Key | Value Type | M/O | Description |
| :----------------- | :------ | :--------- | :-: | :----------------------------------------------------------------------------------------------------------------------- |
| **ECA UUID** | 2 (sub) | tstr | M | The unique ceremony identifier. For SAE: `eca_uuid`. For (D)TLS: `certificate_request_context`. |
| **Expiration** | 4 (exp) | int | M | NumericDate (epoch seconds). MUST be encoded as a 64-bit unsigned integer. |
| **Not Before** | 5 (nbf) | int | M | NumericDate (epoch seconds). MUST be encoded as a 64-bit unsigned integer. |
| **Issued At** | 6 (iat) | int | M | NumericDate (epoch seconds). MUST be encoded as a 64-bit unsigned integer. |
| **Verifier Nonce** | 10 (nonce) | tstr | M | Verifier-issued freshness challenge (**base64url**, unpadded) representing exactly 16 bytes of entropy (typically 22 chars). |
| **ECA Identity** | 256 (EUID) | tstr | M | `eca_attester_id` = hex SHA-256 of the Ed25519 public key used to sign this EAT. |
| **EAT Profile** | 265 | tstr | M | Profile identifier (e.g., `urn:ietf:params:eat:profile:eca-v1`). |
| **Measurements** | 273 | tstr | M | Integrity Hash Beacon (IHB) (**lowercase hex**). |
| **PoP** | 274 (PoP) | tstr | M | Final Proof-of-Possession tag (**base64url**, unpadded) computed as defined by the active profile. |
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
| **JWT ID** | 7 | tstr | The unique ceremony identifier to prevent replay. |
| **Key ID** | -1 (kid)| bstr | OPTIONAL. The hash of the Verifier's public key used to sign the AR. |
| **Status** | -262148 | tstr | The outcome of the attestation. MUST be `urn:ietf:params:rats:status:success`. |

For failures, the AR payload SHOULD follow the same structure but with a `status` of `urn:ietf:params:rats:status:failure` and an additional `error_code` claim (e.g., -262149 as a `tstr`) containing the authenticated error. Relying Parties consuming the AR MUST validate the `nbf` and `exp` claims to ensure the AR is within its validity period.

# ECA/SAE Error Codes Registry {#app-errors}

This registry defines application-specific error codes that are used in addition to the base error codes defined in [@I-D.ritz-sae].

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
| `KEY_BINDING_INVALID` | `KEY_BINDING_INVALID` | 9 | The key used for validation is not bound to the session's Binding Factor. |
| `POP_INVALID` | `POP_INVALID` | 10 | The PoP tag was invalid. |
| `IDENTITY_REUSE` | `IDENTITY_REUSE` | 11 | Attempt to reassign an existing identity. |
| `PUBLISHER_INVALID` | `PUBLISHER_INVALID` | - | Attester artifacts were observed at a repository not hosted by the Attester. |
| `TIMEOUT_PHASE1` | `TIMEOUT_PHASE1` | - | Attester failed to publish Phase 1 artifacts within timeout |
| `TIMEOUT_PHASE2` | `TIMEOUT_PHASE2` | - | Attester failed to publish Phase 2 artifacts within timeout |
| `TRANSPORT_ERROR` | `TRANSPORT_ERROR` | - | Underlying transport protocol error |
| `CREDENTIAL_INVALID` | `CREDENTIAL_INVALID` | - | Renewal Factor signature failed verification |
| `MEASUREMENT_REJECTED` | `MEASUREMENT_REJECTED` | - | Instance Factor measurements failed policy appraisal |
| `REPLAY_DETECTED` | `REPLAY_DETECTED` | - | Attestation procedure ID was reused |
| `BINDING_INVALID` | `BINDING_INVALID` | - | Freshness binding check failed |

# Instance Factor Patterns (IFP) {#instance-factor-patterns-ifp}

The Instance Factor (IF) can be sourced through three defined patterns, each addressing different threat models:

## Pattern A: Hardware-Rooted {#ifp-pattern-a}

**Source:** Hardware security module, TPM, TEE, or similar root of trust.

**Properties:**
- IF never exists in plaintext outside hardware boundary
- Provides strongest security against malicious provider threats
- May require specific hardware capabilities

**Example:** TPM-sealed secret, TEE-derived key material

## Pattern B: Orchestrator-Provisioned {#ifp-pattern-b}

**Source:** Control plane or orchestration system provisions IF at instance creation.

**Properties:**
- Suitable for cloud-native deployments
- Assumes trusted orchestration layer
- Can be integrated with existing provisioning workflows

**Example:** Kubernetes secret, cloud-init parameter

## Pattern C: Artifact-Based {#ifp-pattern-c}

**Source:** Derived from deployment artifacts (container images, binaries).

**Properties:**
- Provides workload-specific attestation
- Portable across environments
- Security depends on artifact integrity

**Example:** SHA-256 of container image, signed manifest hash

# Protocol Requirements (Normative) {#protocol-requirements-normative}

Implementations MUST ensure the following invariants are maintained regardless of the specific profile or transport:

1. **Factor Independence:** The Binding Factor (BF) and Instance Factor (IF) MUST be computationally independent
2. **Freshness Binding:** All attestation procedures MUST be bound to a unique, non-reusable identifier
3. **Key Separation:** Keys used for Phase 2 encryption MUST be distinct from Phase 3 signing keys
4. **Evidence Integrity:** All Evidence MUST be cryptographically bound to the attestation context
5. **Replay Prevention:** Each attestation procedure identifier MUST be accepted at most once

# Change log

## Changes since -00

This revision represents a significant architectural evolution of the ECA protocol based on deeper understanding of the existing Attestation landscape. The scope has been expanded from a single identity bootstrap procedure to a comprehensive attestation pattern.

### Major Architectural Changes

* **Dual-Attestation Model:** The protocol is no longer a single three-phase attestation procedure. It now defines two distinct but related attestation procedures:
    1.  **Identity Bootstrapping:** For initial "cold start" establishment of verifiable identity in environments not yet provisioned.
    2.  **Attestation Renewal:** A lightweight, single round-trip attestation procedure for continuous verification of an established identity, ideal for long-running workloads and TEEs.

* **New Session-Bound Deployment Model:** A primary deployment model using **(D)TLS Exported Authenticators** has been introduced. This aligns the protocol with the **SEAT WG charter** and directly supports continuous attestation for Trusted Execution Environments (TEEs).

* **Formal Model of Attestation Renewal:** Exploratory formal modeling and analysis of the attestation renewal model has been completed.

* **Consolidation of Implementation Guide:** Key concepts from the separate implementation guide (`draft-ritz-eca-impl-00`) have been merged into this core specification for clarity and completeness. This includes:
    * **Instance Factor Patterns (IFP):** The Hardware-Rooted (A), Orchestrator-Provisioned (B), and Artifact-Based (C) patterns are now formally part of the core draft.
    * **Reference Profile and Examples:** A concrete reference profile (`ECA-VM-BOOTSTRAP-V1`) and a detailed (D)TLS example have been included as appendices.
    * **Implementation Status:** The section detailing the prototype's status is now included.

* **Removed SAE from RECOMMENDED or normative transport requirements. Preliminary formal modeling and validation demonstrates that SAE is not required to maintain the security properties inherent in the logic of the applied cryptography.

### Scope and Terminology Refinements

* **Protocol Renaming:** The draft is now titled **"Entity and Compute Attestation"** (formerly "Ephemeral Compute Attestation") to reflect its broadened applicability to both ephemeral and long-running entities.
* **New Terminology:** Introduced new core terms to support the Dual-Attestation model, most notably the **Renewal Factor (RF)**, which is the credential used to prove identity continuity in attestation renewal procedures. The roles of **Binding Factor (BF)** and **Instance Factor (IF)** have been clarified for each attestation procedure type. Added **Verifying Relying Party (VRP)** to clarify roles in renewal procedures. Clarified the distinction between **Evidence** (from Attester) and **Attestation Result** (from Verifier).

### Expanded Integration and Use Cases

* **WIMSE and SEAT Alignment:** The document now explicitly maps ECA roles and concepts to the **WIMSE (Workload Identity in Multi-Cloud Secure Environments)** architecture and details its alignment with the **SEAT (Secure Evidence and Attestation Layer)** working group's goals.
* **Post-Attestation Patterns:** Added a new section that describes the credential lifecycle, stateful attestation renewal, and patterns for chaining attestations to build hierarchical trust.

### Editorial Changes

* Added **Muhammad Usama Sardar** as a co-author.
* **FURTHER** restructured the document significantly to introduce the conceptual model and deployment patterns upfront.
* Retained ECA-VM-BOOTSTRAP-V1 profile for interop testing
* Replaced "ceremony" with "attestation procedure" or simply "procedure".
* Replaced "re-attestation" with "attestation renewals"
* Updated the formal model analysis in the appendix to reflect the protocol's evolution and provide clearer interpretations of the security boundary tests.
* Integrated normative profiles from `interop-profiles.md` as new appendices

