# Profiles (Normative) {#app-profiles}

This document defines the protocol abstractly. Concrete cryptographic mechanisms are supplied by profiles. A conforming implementation MUST implement at least one profile, and any chosen profile MUST preserve all requirements in [](#protocol-requirements-normative).

> Note: No MTI Algorithms in this Revision. This revision does not define mandatory-to-implement (MTI) primitives. Reference profiles will be published separately to enable experimentation and interoperability testing.

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
