%%%
title = "Static Artifact Exchange (SAE) Protocol"
abbrev = "SAE"
category = "exp"
docname = "draft-ritz-sae-00"
date = "2025-09-28T00:00:00Z"
ipr = "trust200902"
area = "SEC"
pi = ["toc", "sortrefs", "symrefs", "strict"]
stand_alone = true

[[author]]
fullname = "Nathanael Ritz"
organization = "Independent"
  [author.address]
  email = "nathanritz@gmail.com"

[seriesInfo]
name = "Internet-Draft"
value = "draft-ritz-sae-00"
stream = "IETF"
status = "experimental"
%%%

.# Abstract {#sec-abstract}

This document specifies the Static Artifact Exchange (SAE) protocol, an asynchronous protocol for exchanging cryptographic artifacts between two parties via a shared, stateless repository. SAE uses a pull-only communication model where peers poll for the presence of immutable, pre-computed artifacts to coordinate a sequenced exchange. By design, this static artifact model avoids dynamic request processing, reducing common attack surfaces like injection and parser vulnerabilities. The protocol is transport-agnostic, allowing each party to access the repository using different underlying mechanisms (e.g., cloud APIs or standard HTTPS). SAE is intended as a foundational transport pattern for protocols like Ephemeral Compute Attestation (ECA), which require a secure, minimal channel where trust is derived from the cryptographic content of the artifacts, not from the channel itself.

{mainmatter}

# Introduction {#sec-intro}

Many cryptographic protocols require a coordinated, multi-phase exchange of artifacts like proofs, challenges, or attestation evidence. Traditional request-response patterns often introduce security risks at the transport layer, including complex state management, parser vulnerabilities, and injection attacks.

This document specifies the Static Artifact Exchange (SAE) protocol, an alternative model designed for security and simplicity. In SAE, parties do not communicate directly. Instead, they interact asynchronously through a simple, stateless repository. One party publishes a set of immutable, pre-computed artifacts for a given phase and then publishes a status indicator to signal its completion. The other party polls for this status indicator and, upon observing it, retrieves the corresponding artifacts.

This "publish-then-poll" pattern reduces the need for active listeners or dynamic request processing, limiting the attack surfaces associated with traditional models. The security of the exchange relies entirely on the cryptographic validity of the artifacts themselves, not on any feature of the transport mechanism beyond providing durable storage and reliable retrieval. The transport is treated as a content-agnostic, key-value store.

SAE is intended as a reusable transport pattern for higher-level protocols. It is motivated by the requirements of Ephemeral Compute Attestation (ECA) [I-D.eca-protocol], where a compute instance must prove its identity before it has been provisioned with any operational credentials.

# Terminology and Core Concepts {#sec-terms}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [@RFC2119] [@RFC8174] when, and only when, they appear in all capitals, as shown here.

Peer

: An entity participating in the SAE protocol that can both publish artifacts to its own repository and retrieve artifacts from its counterpart's repository.

Artifact

: An immutable blob of data published by a peer, identified by a predetermined path or address and having a size attribute.

Status Indicator

: A signal published by a peer indicating the completion of a phase. A zero-byte artifact indicates success, while a non-zero-byte artifact contains an **HMAC tag** identifying a specific error (see [§ 4.4](#sec-error-signaling)).

Phase

: A distinct stage in a protocol where specific artifacts are exchanged. Phase transitions are atomic and explicitly signaled (see [§ 4.2](#sec-phase-coordination)).

Repository

: A durable, addressable, and immutable store for artifacts. It provides a means to publish and retrieve artifacts but does not provide any protocol-level intelligence.

Exchange Identifier

: A unique identifier (e.g., a UUID) for a specific exchange instance, used to construct artifact paths. The generation and out-of-band communication of the Exchange Identifier is the responsibility of the higher-layer protocol utilizing SAE. *In the ECA profile, this corresponds to the `eca_uuid`* (ECA Terms [§ 2.1](https://datatracker.ietf.org/doc/draft-ritz-eca-00/)).

Inhomogeneous Transport Fabric

: A design pattern enabled by SAE where peers operate over different transport mechanisms (e.g., one peer uses a cloud API, the other uses HTTPS) to access the same repository. This decoupling allows each peer to maintain its own network topology and security posture without constraining its counterpart.

# Protocol Requirements (Normative) {#sec-invariants}

SAE implementations MUST satisfy the following invariants:

{type="%d."}
1. **Static Artifact Model**: All communication MUST conform to a strict artifact exchange model where both peers operate as passive repositories of pre-computed, immutable artifacts.

2. **Pull-Only Communication**: Peers MUST NOT push data. All artifact retrieval MUST be initiated by the consuming peer through polling predetermined paths.

3. **Phased Atomic Progression**: The protocol MUST progress through distinct phases. All artifacts for a phase MUST be published before its corresponding status indicator is published.

4. **Immutability**: Once a status indicator for a phase is published, all associated artifacts for that phase MUST NOT be changed or removed.

5. **Prohibited Processing**: The protocol's state transitions and security decisions MUST be based on the presence and size of artifacts, not their content. A non-zero Content-Length for a status indicator MUST be treated as a terminal failure, ending the exchange. Implementations MUST NOT parse or interpret arbitrary or variable-length content to determine the protocol's outcome. The inspection of a status indicator's content to diagnose a failure is an operational concern that MUST only occur after the exchange has already been terminated based on the artifact's size.

6. **Bounded Polling**: Polling for status indicators MUST use exponential backoff.

7. **Transport Simplicity**: The protocol logic MUST remain independent of transport-level features beyond basic artifact retrieval (e.g., HTTP GET/HEAD) and presence signaling (e.g., HTTP 200/404 status codes). Implementations MUST treat the transport layer as a stateless key-value store and MUST NOT derive protocol behavior from any other transport metadata, such as HTTP headers or TLS session details.

8. **Repository Consistency**: Any repository used to host artifacts MUST provide strong read-after-write consistency for all operations. Eventually consistent systems MUST NOT be used unless specifically configured to provide strong consistency guarantees for the relevant objects.

9. **Resilient Artifact Retrieval**: After a peer successfully observes the presence of a status indicator, it proceeds to retrieve the corresponding phase artifacts. The peer's retrieval logic MUST be resilient to transient transport- or storage-layer delays. It is RECOMMENDED that implementations employ a bounded retry mechanism with exponential backoff when fetching artifacts. The initial observation of the status indicator is sufficient to proceed with the retrieval attempts; re-verification of the status indicator during a retry loop is NOT RECOMMENDED as it adds unnecessary complexity.

> NOTE: SAE's model enables an *"inhomogeneous transport fabric"*, where peers need not share a common protocol beyond basic retrieval semantics. For example, one peer might access the repository via a cloud provider's SDK for low-latency internal operations, while another uses HTTPS over a bastion host. This decouples endpoint security postures, supporting hardened, outbound-only configurations without sacrificing usability.

# Protocol Mechanics {#sec-mechanics}

## Artifact Repository Structure {#sec-repo-structure}

Each peer MUST organize its repository using a consistent path structure based on the Exchange Identifier.

**Recommended Structure**:

/<exchange_id>/<artifact_name>
/<exchange_id>/<phase_name>.status

Where `exchange_id` uniquely identifies the exchange, `artifact_name` identifies a specific artifact, and `phase_name` identifies the status indicator for a phase.

## Phase Coordination {#sec-phase-coordination}

The protocol progresses using the following pattern:

{type="%d."}
1. **Publication**: A peer publishes all required artifacts for the current phase to its repository.

2. **Signaling**: After all artifacts are published, the peer publishes the status indicator for that phase.

      * **Success**: The status indicator MUST be a zero-byte artifact (e.g., an empty file) whose presence alone signals successful completion of the phase.
      * **Failure**: The status indicator MUST be a non-zero-byte artifact containing an **HMAC tag** as defined in [§ 4.4](#sec-error-signaling).

3. **Polling**: The counterpart peer polls for the status indicator using transport-appropriate presence checks (e.g., HTTP `HEAD` requests) with bounded retry logic (see [§ 3](#sec-invariants)).

4. **Retrieval and Interpretation**: Upon receiving a response to the presence check:

      * If the artifact is absent (e.g., HTTP 404 Not Found), the phase is not complete; continue polling.

      * If the artifact is present:

          * If the size is zero, the phase was successful; proceed to retrieve the associated phase artifacts.
          * If the size is greater than zero, the phase has failed. The peer MUST immediately consider the exchange to be in a terminal failure state. Identifying the specific cause of the failure by inspecting the artifact's content, as described in [§ 4.5](#sec-error-diagnosis), is an OPTIONAL step that may be performed for diagnostic purposes after termination.

The publication of a phase's status indicator MUST be an atomic operation from an observer's perspective. After all other artifacts for that phase are durable and fully written, the status indicator MUST appear instantly and completely. Implementations MUST NOT allow an observer to view a status indicator in a partially written or otherwise inconsistent state.

## Transport Abstraction {#sec-transport}

While SAE is transport-agnostic in principle, HTTPS **MUST** be implemented as the mandatory-to-implement transport. The transport layer MUST provide:

{type="%d."}
1. Retrieval operations (e.g., HTTP `GET`, `HEAD`)
2. Presence/absence signaling (e.g., HTTP `200`/`404` status codes)
3. Confidentiality and integrity (e.g., TLS 1.2 or later)

Transport-level metadata (e.g., custom headers) **MUST NOT** influence protocol behavior. The method used to publish artifacts to a repository is considered an implementation detail; SAE does not constrain publisher semantics (e.g., HTTP `PUT`, `rsync`, or object-store APIs are all acceptable).

## Error Signaling {#sec-error-signaling}

When a peer encounters an application-level error, it MUST publish a status indicator artifact containing a Keyed-Hash Message Authentication Code (`HMAC-SHA256`). The HMAC tag MUST be computed over the concatenation of the Exchange Identifier and the canonical error string (e.g., `exchange_id || ":" || error`). The key used for the HMAC MUST be derived from a secret shared between the peers out-of-band or established by the higher-layer protocol. This binds the error signal to a specific exchange context, preventing replay attacks across different exchanges and ensuring an unauthorized party cannot forge a valid error signal. *(In ECA, these canonical error strings are defined in the ECA Error Codes registry; see ECA [§ 12.2.1](https://datatracker.ietf.org/doc/draft-ritz-eca-00/).)*

## Error Cause Diagnosis (Optional) {#sec-error-diagnosis}

The presence of any non-zero-byte content in a status indicator signifies a terminal failure of the exchange. For operational hardening, consuming peers **MUST** first check the `Content-Length` header.

## Artifact Lifecycle Management (Informative) {#sec-artifact-lifecycle}

In large-scale deployments, operators SHOULD implement a garbage collection strategy to remove artifacts from completed or timed-out exchanges to prevent storage sprawl. A common approach is to apply a time-to-live (TTL) policy to all artifacts associated with an `exchange_id`, deleting them after a defined period (e.g., 24 hours) has passed since the exchange was initiated.

# Security Considerations {#sec-security}

## Elimination of Processing Vulnerabilities {#sec-security-processing}

The static artifact model makes implementations inherently immune to injection attacks, parser vulnerabilities, and other flaws common in request-processing systems. Since peers never process arbitrary client-supplied data, these attack vectors are eliminated by design. The use of fixed-size **HMAC tag verification** further reduces risk by avoiding the parsing of arbitrary error messages.

## Prevention of Race Conditions {#sec-security-race}

The atomic "publish-then-signal" model prevents Time-of-Check-to-Time-of-Use (TOCTOU) vulnerabilities. A peer that detects a status indicator is guaranteed that all associated artifacts are already published and immutable.

## Resilience Against Denial of Service {#sec-security-dos}

The stateless nature of the repository model provides resilience against DoS attacks that target session state. The bounded polling requirement (see [§ 3](#sec-invariants)) further mitigates resource exhaustion from misbehaving peers.

## Transport Security {#sec-security-transport}

Implementations **MUST** use transport-layer encryption to protect artifacts in transit.

## Error Signaling {#sec-security-error-signaling}

The use of authenticated, fixed-size error codes within status indicators upholds the **Prohibited Processing** invariant by avoiding the need to parse arbitrary or variable-length error messages. A peer makes its terminal failure decision based on size alone. This approach contrasts with protocols that rely on variable-length messages, which can introduce parsing overhead and potential vulnerabilities in resource-constrained environments.

## Information Leakage via Error Hashes {#sec-info-leak}

Using predictable, public hashes for error signaling supports interoperability and debugging but allows a passive repository observer to gain real-time intelligence on failures. The primary mitigation is strict repository access control. In high-security environments, repositories SHOULD NOT be publicly observable.

## Resilience to Replay Attacks {#sec-replay}

Replay protection across exchanges MUST be provided by the higher-layer protocol (e.g., ECA’s accept-once semantics for `eca_uuid`; see ECA [I-D.eca-protocol] §4.1 (*Validation Gates*) {#sec-validation-gates}). Operators SHOULD implement repository controls (path-based write permissions, audit logging) to mitigate local replay by a writer.

# IANA Considerations {#sec-iana}

## SAE Error Codes Registry {#sae-error-codes-registry}

IANA is requested to establish a registry for SAE Error Codes. This registry defines the error code identifier and the canonical string that, when concatenated with the Exchange Identifier, is used as input to the HMAC function for error signaling. Implementations MUST compute the HMAC tag over the exact bytes of the canonical content with no trailing newline.

| Code | Canonical Content (UTF-8) | Description (Analogy) |
| :--- | :--- | :--- |
| `BAD_REQUEST` | `BAD_REQUEST` | A client-side error due to a malformed or invalid artifact (HTTP 400). |
| `UNAUTHORIZED` | `UNAUTHORIZED` | Authentication is required and has failed or has not yet been provided (HTTP 401). |
| `FORBIDDEN` | `FORBIDDEN` | The server understood the request but refuses to authorize it (HTTP 403). |
| `CONFLICT` | `CONFLICT` | The request could not be completed due to a conflict with the current state (HTTP 409). |
| `GATEWAY_TIMEOUT` | `GATEWAY_TIMEOUT` | A peer did not receive a timely response from its counterpart (HTTP 504). |

# Normative References {#sec-refs-norm}

[I-D.eca-protocol]
: Ritz, N., "Ephemeral Compute Attestation (ECA) Protocol", Work in Progress, draft-ritz-eca-00, 16 September 2025.

[@RFC2119]
: Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119.

[@RFC6234]
: Eastlake 3rd, D. and T. Hansen, "US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)", RFC 6234, DOI 10.17487/RFC6234, May 2011, <https://www.rfc-editor.org/info/rfc6234>.

[@RFC8174]
: Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174.

[@RFC8446]
: Rescorla, E., "The Transport Layer Security (TLS) Protocol Version 1.3", RFC 8446, DOI 10.17487/RFC8446, August 2018.

[@RFC9110]
: Fielding, R., Ed., Nottingham, M., Ed., and J. Reschke, Ed., "HTTP Semantics", STD 97, RFC 9110, DOI 10.17487/RFC9110, June 2022.

{backmatter}

# HTTPS Profile (Normative) {#appendix-a}

This section provides a normative example of how the abstract SAE protocol can be implemented using standard HTTPS over a repository (e.g., a file system or an object store).

## Artifact Transport {#appendix-a-transport}

* **Retrieval**: Use HTTP `GET` to retrieve artifacts and HTTP `HEAD` to check for their presence and size.
* **Presence/Absence Signaling**: A successful HTTP `200` response indicates presence, while a `404` indicates absence.
* **Success/Failure Signaling**: A zero-byte artifact's `Content-Length: 0` header indicates success. Any `Content-Length` greater than zero indicates a terminal failure.

## Example Exchange {#appendix-a-example}

This example illustrates a simple two-phase SAE exchange between peers A and B using the exchange identifier `exchange-12345`.

**Phase 1: A publishes an initial proof artifact**

```
A: PUT /exchange-12345/proof.json
A: PUT /exchange-12345/proof.status (0 bytes)
B: HEAD /exchange-12345/proof.status (polling until 200 OK)
B: Observes Content-Length: 0 → success
B: GET /exchange-12345/proof.json
```

**Error example:** If B encounters a timeout while waiting for A, it publishes an authenticated error signal.

```
# B derives the HMAC key from a shared secret
# B computes the HMAC tag for the "GATEWAY_TIMEOUT" string
# B hex-encodes the 32-byte tag into a 64-character string
B: PUT /exchange-12345/response.status (content: <64-char-hex-hmac-tag>)
A: HEAD /exchange-12345/response.status (polling until 200 OK)
A: Observes Content-Length > 0 // Exchange is dead
A: GET /exchange-12345/response.status (reads 64 bytes) // OPTIONAL
A: Verifies received tag against its own computed HMACs for known errors
A: Finds match for GATEWAY_TIMEOUT -> aborts exchange
```

## Implementation with Standard Web Servers {#appendix-a-impl}

```nginx
server {
    listen 443 ssl;
    root /var/sae/repository;
    location / {
        try_files $uri =404;
        add_header Cache-Control "private, max-age=0, immutable";
    }
}
```

```bash
#!/bin/bash
EXCHANGE_ID="$1"
PHASE_NAME="$2" # Name of the phase (e.g., "proof")
ERROR_CODE="${3:-}" # If set, indicates failure and specifies error code

# The HMAC key MUST be securely provided (e.g., via env var or file)
# This is an example and not a secure way to handle keys.
HMAC_KEY="${SAE_HMAC_KEY}"

REPO_ROOT="/var/sae/repository"
PHASE_DIR="$REPO_ROOT/$EXCHANGE_ID"
mkdir -p "$PHASE_DIR"

# ... (script logic to publish main artifacts for the phase) ...

# For the status indicator, creation is the signal.
if [[ -z "$ERROR_CODE" ]]; then
    # Success: create an empty status file
    touch "$PHASE_DIR/$PHASE_NAME.status"
else
    # Failure: create a status file with the HMAC of the error code
    TMPSTATUS=$(mktemp -p "$PHASE_DIR")
    # Calculate the HMAC tag of the error string and hex-encode it
    printf "%s" "${EXCHANGE_ID}":"${ERROR_CODE}" | openssl dgst -sha256 -hmac "$HMAC_KEY" -r | awk '{print $1}' > "$TMPSTATUS"
    mv -f "$TMPSTATUS" "$PHASE_DIR/$PHASE_NAME.status"
fi
```

# Verifying Error Signals (Informative) {#appendix-b}

This appendix provides a helper script that can be used to diagnose a failed exchange by verifying a received HMAC tag against the set of known canonical error strings.

```bash
#!/usr/bin/env bash
# verify-sae-error.sh: Verifies a received HMAC tag to identify an error.

RECEIVED_TAG="$1"

if [[ -z "$RECEIVED_TAG" ]]; then
  echo "Usage: $0 <received-hmac-tag>"
  exit 1
fi

# The HMAC key MUST be the same one used by the publishing peer.
HMAC_KEY="${SAE_HMAC_KEY}"

if [[ -z "$HMAC_KEY" ]]; then
  echo "Error: SAE_HMAC_KEY environment variable not set."
  exit 1
fi

# Array of known canonical error strings from the IANA registry
declare -a KNOWN_ERRORS=(
  "BAD_REQUEST"
  "UNAUTHORIZED"
  "FORBIDDEN"
  "CONFLICT"
  "GATEWAY_TIMEOUT"
  # ... Higher-layer protocol errors would be added here
)

for ERROR_STRING in "${KNOWN_ERRORS[@]}"; do
  # Recompute the expected HMAC tag for this error string
  EXPECTED_TAG=$(printf "%s" "$EXCHANGE_ID" "$ERROR_STRING" | openssl dgst -sha256 -hmac "$HMAC_KEY" -r | awk '{print $1}')

  if [[ "$RECEIVED_TAG" == "$EXPECTED_TAG" ]]; then
    echo "VERIFIED: The error code is '$ERROR_STRING'."
    exit 0
  fi
done

echo "UNKNOWN_ERROR: The received tag does not match any known error code."
exit 1
```
