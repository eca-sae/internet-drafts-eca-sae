# ECA-VM-BOOTSTRAP-V1 Reference Profile {#bootstrap-reference-profile}

> Stability note: This profile documents the concrete choices used by the reference prototype to enable experimentation and interop. It is non-normative and may change in future drafts based on feedback.

## Primitives {#primitives}

- Hash / KDF: HKDF-SHA-256 (RFC5869), SHA-256 (RFC6234)
- MAC: HMAC-SHA-256
- Signatures: Ed25519 (RFC8032)
- KEM/HPKE: X25519 + HPKE base mode (RFC9180) for Verifier -> Attester secrecy in Phase 2. The ceremony identifier is used as the AAD, and the `info` parameter for key derivation is `"ECA/v1/hpke"`.
- Nonces: Verifier freshness `vnonce` is exactly 16 bytes (encoded base64url, unpadded)

## Integrity Hash Beacon (IHB) {#integrity-hash-beacon-ihb}

- `IHB = SHA-256( BF || IF )`, rendered as lowercase hex for transport where necessary.

## Deterministic Key Material {#deterministic-key-material}

All keys are deterministically derived from ceremony inputs via domain-separated HKDF invocations. Notation: `HKDF-Extract(salt, IKM)` then `HKDF-Expand(PRK, info, L)`. The ceremony identifier is appended to the `salt` in all derivations to ensure session uniqueness.

- **Phase 1 MAC key (Attester artifact MAC)**

  - `IKM = BF || IF`
  - `salt = "ECA:salt:auth:v1" || ceremony_id`
  - `info = "ECA:info:auth:v1"`
  - `K_MAC_Ph1 = HKDF-Expand( HKDF-Extract(salt, IKM), info, 32 )`
  - Usage: HMAC-SHA-256 over the CBOR Phase-1 payload bytes.

- **Phase 2 ECDH/HPKE seed (Attester's ephemeral X25519 keypair)**

  - `IKM = BF || IF`
  - `salt = "ECA:salt:encryption:v1" || ceremony_id`
  - `info = "ECA:info:encryption:v1"`
  - `seed32 = HKDF-Expand( HKDF-Extract(salt, IKM), info, 32 )`
  - The Attester forms an X25519 private key by clamping `seed32` per RFC7748; the public key is derived normally.
  - The Verifier uses HPKE with the Attester's public key to encrypt `{VF, vnonce}`.

- **Phase 3 signing key (Attester's Ed25519 identity keypair)**

  - `IKM = BF || VF`
  - `salt = "ECA:salt:composite-identity:v1" || ceremony_id`
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
    - `bound_data = ceremony_id || IHB_bytes || eca_attester_id_bytes || vnonce_raw_bytes`
    - `bound_hash = SHA-256( bound_data )`
  - Then, a dedicated MAC key is derived:
    - `IKM = BF || VF`
    - `salt = "ECA:salt:kmac:v1" || ceremony_id`
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
- Apply local appraisal policy; on success, emit an Attestation Result bound to ceremony identifier.

## Interop Notes {#interop-notes}

- **Encodings:** All binary fields referenced in EAT must be explicitly encoded (e.g., base64url) and stated as such in the claims table. NumericDate claims (`iat`, `nbf`, `exp`) use 64-bit unsigned integers.
- **Side-Channel Resistance:** To mitigate timing attacks, implementations SHOULD use constant-time cryptographic comparisons. Payloads that are inputs to cryptographic operations (e.g., Evidence) MAY be padded to a fixed size using a length-prefix scheme to ensure unambiguous parsing.
