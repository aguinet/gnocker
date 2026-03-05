# Gnocker protocol

## Overview

The protocol allows a client to authenticate to a server using a signed
message, after which the server forwards the TCP session to an upstream service.
The handshake is self-contained in a single TCP packet (plus the signature).

## Message Format

The knock packet consists of the following fields:

| Field          | Size      | Description                                              |
|----------------|-----------|----------------------------------------------------------|
| Version        | 1 byte    | Protocol version (currently 1)                           |
| Timestamp      | 8 bytes   | GMT Unix timestamp in seconds (big-endian)               |
| Rand           | 32 bytes  | Cryptographically random nonce                           |
| HashedPubKeyID | 32 bytes  | <code>SHA256(0x00 \|\| rand \|\| Public key ID)</code>   |
| SignLen        | 3 bytes   | Length of the signature (big-endian)                     |
| Signature      | Variable  | Signature following the SSH signature format (see below) |

`Public Key ID` is the SSH public key fingerprint in binary form, as described
in [RFC 4716](https://www.rfc-editor.org/rfc/rfc4716.html#page-6).

The signature signs everything from `Version` through `HashedPubKeyID` (included) concatenated.

The signature uses the [SSH RFC 4253 signature
format](https://datatracker.ietf.org/doc/html/rfc4253#section-6.6) and the
following [RFC
4253](https://datatracker.ietf.org/doc/html/rfc8709#name-signature-format) for
elliptic curves signatures. It's only using the "blob" part, the type being
already known thanks to the public key itself.

## Authentication Flow

### Client-Side

1. Generate a cryptographically random nonce
2. Construct the header containing version, timestamp, nonce, and hashed public key identifier of the client's SSH private key
3. Sign the entire header with the client's SSH private key
4. Send the header followed by the signature to the server

### Server-Side

1. Parse the version field and validate it
2. Validate the timestamp is within the accepted window (see below)
3. Extract and hash the public key identifier to find if it's an accepted publcic key
4. Verify the signature using the found public key
5. If successful, forward the TCP session to the configured upstream service

## Anti-Replay Mechanism

The anti replay mechanism is based on two principles. A server implementation of **gnocker** must:

* ignore every knock packet whose timestamp isn't within a time window of plus or minus 5 seconds of the server's timestamp in GMT
* ignore every knock packet that has a `(timestamp, nonce)` tuple that it has accepted before

It should do so by also limiting the amount of maximum "nonces-per-timestamp"
it is going to keep in memory, to avoid infinite memory consumption by an
authenticated attacker.


## Hashed Public Key ID

The protocol is designed to never transmit public key fingerprints in clear text over the network.

### Design

1. **Client-Side Hashing**: The client does not send the raw public key or its fingerprint. Instead, it sends a hashed identifier computed as:

   `hashed_pubkey_id = SHA256(0x00 || rand || pubkey_fingerprint)`

2. **Server-Side Lookup**: The server computes the same hash for each of its known public keys and checks if the received hash matches. An implementation should compute all hashes first (without early exit) to prevent timing side-channels (see below).

3. **Signature Verification**: Once the correct public key is identified through hash matching, the signature is verified.

### Constant-time key lookup

To prevent timing attacks that could leak if the server accepts a public key, a
protocol implementation should ensure that:

1. **All authorized public key hashes are computed** before any comparisons are made
2. **All comparisons are performed in constant time** and before returning a result
3. **No early return occurs** based on whether a match was found
4. **A signature verification always happens** even when the provided public key is unknown. This prevents timing leakage that could indicate that a public key is authorized or not by the server.

### Performance drawbacks

This current *hashed* public key identification approach has a significant
performance drawback. Indeed, for each incoming connection, the server must:

1. Compute hashes for all known public keys
2. Compare each computed hash with the received `hashed_pubkey_id`

The worst-case time complexity for public key identification is thus `O(n)`
where `n` is the number of authorized public keys.

This linear scanning approach trades performance for:

- **Security**: Prevents timing attacks that could reveal which keys are authorized
- **Privacy**: Doesn't leak the public key identifiers used by clients

This is a trade-off decision that may change in some future version of this protocol.
