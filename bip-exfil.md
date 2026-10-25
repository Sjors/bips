```
  BIP: XXX
  Layer: Applications
  Title: Interactive Anti-Exfiltration for BIP340 Signatures
  Authors: Sjors Provoost <sjors@sprovoost.nl>
  Status: Draft
  Type: Specification
  License: BSD-2-Clause
  Requires: 174, 340, 341, 370, 371
```

## Introduction

### Abstract

This document specifies a two-round protocol in which a host contributes randomness
to a single signer's BIP340 nonce and checks its use before releasing a signature.
It also specifies provisional per-input PSBT fields for the exchange. The resulting
signature and transaction use existing consensus rules and carry no extra on-chain
data.

### Copyright

This BIP is licensed under the BSD 2-Clause License.

### Motivation

A signing device can produce valid signatures whose nonces leak its private key or
wallet seed to an outside observer. Checking the transaction's outputs and checking
signature validity do not detect such an attack. Deterministic signing can be spot
checked by a party holding the private key; it does not let a watch-only host verify
every nonce.[^overview]

The host and signer jointly determine the nonce, with the host revealing its random
contribution only after the signer commits to its original public nonce. A host
commitment also binds deterministic nonce generation to the contribution and avoids
related-nonce attacks by a malicious host. This is the additive, stateless construction
described as Scheme 6 in the anti-covert-channel overview.[^overview] Stepan
Snigirev's earlier nonce-blinding proposal also described additive host contributions,
stateless signers, and per-input PSBT fields.[^nonce-blinding] This draft specializes
that work to BIP340 and Taproot, including nonce derivation, parity, exceptional
cases, transcript validation, and reproducible interoperability vectors.

Related ECDSA anti-exfil protocols have been deployed by BitBox02 and Jade. Their
existing transports and sign-to-contract constructions are prior art, rather than
byte-compatible implementations of this Taproot profile.[^deployed]

The scope is single-signer Taproot key-path signing. ECDSA, Taproot script-path
signing, MuSig2, FROST, and general-purpose sign-to-contract are outside this draft.
Unlike a one-round construction, the signer cannot grind its initial nonce after
learning the host's contribution.[^delving] A general sign-to-contract API is not
required.[^secp-choice]

## Specification

The words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY express normative requirements.

### Notation

The curve, group order `n`, generator `G`, point operations, `has_even_y`, `lift_x`,
and 32-byte big-endian integer encodings `bytes` and `int` are those of BIP340.
`tagged_hash(tag, data)` is its tagged SHA256 construction. `||` concatenates byte
strings and `XOR` is bitwise exclusive-or.

`compress(P)` encodes a finite curve point in 33 bytes: `0x02 || bytes(x(P))` when
its y coordinate is even, and `0x03 || bytes(x(P))` otherwise. Parsing rejects other
lengths, invalid prefixes, x coordinates at least the field prime, and points not
on the curve. The parity bit MUST be preserved.

The message `m` is exactly 32 bytes. For the PSBT profile it is the BIP341 Taproot
key-path signature hash, computed independently by the host and signer. The secret
key `sk` is the actual Taproot-tweaked signing key, not the internal key. `P` is its
even-y public point, whose x coordinate is the spent output's 32-byte witness
program. The device MUST reject `sk` unless it is 32 bytes and
`1 <= int(sk) < n`. Normalize the secret as in BIP340: with `P0 = int(sk) * G`,
set `d = int(sk)` if `P0` has even y, otherwise `d = n - int(sk)`; then
`P = d * G`.

Two new hash tags are used:

* `BIP-EXFIL/host`
* `BIP-EXFIL/nonce`

These are placeholder domains for this unnumbered draft. Assignment of a BIP
number may change the domains and MUST be followed by regeneration of all test
vectors and coordinated implementation updates. Existing `BIP0340/aux` and
`BIP0340/challenge` tags remain unchanged.

### Host commitment

1. Draw a uniformly random 32-byte string `rho` from a cryptographically secure
   generator. Repeat until `1 <= int(rho) < n`.
2. Compute `h = tagged_hash("BIP-EXFIL/host", rho)`.
3. Send `h`, the requested signing key, and the immutable signing request to the
   device. Keep `rho` secret until its nonce commitment has been received and
   recorded.

Use fresh, independently sampled `rho` for each new signature session, including
each input of a transaction. The host MUST generate this contribution itself;
entropy or commitments prefilled in an untrusted PSBT are not evidence of honest
host randomness. A bridge transporting a caller's transcript does not thereby
establish its provenance. Recovery of an interrupted session is defined below.

### Signer nonce commitment

The device validates its key, the signing request, and `m`. It computes:

```
masked = bytes(d) XOR tagged_hash("BIP0340/aux", h)
k0 = int(tagged_hash("BIP-EXFIL/nonce", masked || bytes(x(P)) || m)) mod n
```

Abort if `k0 = 0`. Return `compress(R0)`, where `R0 = k0 * G`. Do not return a
signature in this round. The device MUST NOT normalize `R0` to even y: its full
point, including parity, is the commitment.

The separate nonce tag is mandatory. Reusing ordinary BIP340 nonce derivation
would permit a caller able to request ordinary signing with auxiliary randomness
`h` to obtain signatures with related nonces `k0` and `k0 + int(rho)`. Those
relations can reveal the signing key. Domain separation prevents this cross-API
reuse.

### Host reveal and signing

The host validates and records `compress(R0)` before sending `rho`. It MUST NOT
replace that recorded point using a value supplied with the final signature.

On receipt of `rho`, the device:

1. Rejects unless `rho` is 32 bytes and `1 <= int(rho) < n`.
2. Recomputes `h` and derives `k0` using the same signing key and message.
3. Where the transport supplies the previous `h` and `R0`, checks that they equal
   the recomputed values. An API receiving only `(key, m, rho)` MAY rederive its
   nonce without storing the first-round transcript: the host's verification
   against its originally recorded `R0` binds that response to round one. The
   PSBT transport below supplies both fields, so its implementations MUST check
   them against the recomputed values.
4. Sets `k_raw = (k0 + int(rho)) mod n`. Aborts if it is zero.
5. Sets `R_raw = k_raw * G`, and `k = k_raw` if its y coordinate is even, otherwise
   `k = n - k_raw`. Set `R = k * G`.
6. Sets `e = int(tagged_hash("BIP0340/challenge", bytes(x(R)) || bytes(x(P)) || m)) mod n`.
7. Sets `s = (k + e * d) mod n` and `sig = bytes(x(R)) || bytes(s)`.
8. Verifies `sig` using BIP340 and aborts if verification fails; otherwise returns it.

The device can rederive its nonce without persisting secret nonce state. It MUST
still perform ordinary transaction authorization and key/path checks. Anti-exfil
does not replace those checks.

### Host verification

The host rejects unless all of the following hold:

* The received signature is exactly 64 bytes and is valid under BIP340 for its
  independently selected public key and original message.
* The originally recorded `R0` is a valid full curve point.
* `R_raw = R0 + int(rho) * G` is not infinity.
* The signature's first 32 bytes equal `bytes(x(R_raw))`.

The BIP340 signature check handles the required even-y normalization of the final
nonce. Its x coordinate alone suffices for the last comparison, but the original
`R0` MUST retain its parity. Only after these checks may the host release the
signature to another party outside the private host/bridge exchange, finalize a
PSBT, or broadcast a transaction. For a protected invocation with multiple targets,
all requested signatures and proofs MUST pass before any are released outside that
exchange. An error MUST NOT return a subset as a successfully protected result.

### Interruptions and selective aborts

After committing to `R0`, a malicious device can still refuse to finish sessions
whose resulting signatures do not encode its preferred signal. Silently retrying
with new host randomness would restore a grinding channel.[^abort]

An automatic retry MUST reuse the exact same `(key, m, rho, h, R0)` and MUST reject
a different `R0`. An implementation unable to recover this tuple MUST stop and
report the interruption, rather than silently create a new session. This applies
to reconnects and process restarts as well as in-process retries. Applications
SHOULD make repeated failures visible to the user. No universal bound on safe
manual retries is claimed.

The nonce transcript is host-local signing data. Applications MUST NOT broadcast
it or include it in routine diagnostic logs. Raw signer nonce points can
themselves carry the information this protocol is intended to keep off-chain.

### PSBT transport

The following new per-input fields use BIP174's proprietary-key mechanism while
this draft is experimental.[^nonce-blinding] Their identifier is the two ASCII bytes `ae`; the
subtype is CompactSize-encoded; remaining key data is the actual 32-byte x-only
Taproot output signing key `Q`. No standard PSBT field numbers are assigned.

The complete serialized key is:

```
0xfc || 0x02 || 0x61 0x65 || subtype || Q
```

For the subtypes below its total length is 37 bytes. All values are raw bytes,
without an inner length prefix. The normal PSBT key/value length prefixes still
apply. These fields are allowed only in input maps of PSBT versions 0 and 2.
Implementations MUST reject `ae` fields in global or output maps, noncanonical
key encodings, unknown subtypes, invalid key or value lengths, and more than one
`Q` for an input. Recognizing the `ae` identifier and then ignoring a malformed
encoding MUST NOT cause fallback to ordinary signing.

| Name | Subtype | Key data | Value | Meaning |
|------|---------|----------|-------|---------|
| `PSBT_IN_AE_HOST_COMMITMENT` | `0x00` | `Q` (32 bytes) | `h` (32 bytes) | Request anti-exfil; binds the host contribution. |
| `PSBT_IN_AE_SIGNER_NONCE` | `0x01` | `Q` (32 bytes) | `compress(R0)` (33 bytes) | Device's original nonce commitment. |
| `PSBT_IN_AE_HOST_ENTROPY` | `0x02` | `Q` (32 bytes) | `rho` (32 bytes) | Opens the host commitment in round two. |

`Q` MUST equal the Taproot output key of this input's UTXO. The input MUST be a
Taproot key-path spend, without an annex. An explicitly present
`PSBT_IN_SIGHASH_TYPE` MUST be `SIGHASH_DEFAULT` (0) or `SIGHASH_ALL` (1); absence
means DEFAULT. The final PSBT signature is 64 bytes for DEFAULT, or 65 bytes
ending in `0x01` for ALL. The signature hash, key, outputs, input outpoints,
sequences, ordering, transaction version, effective locktime, and UTXO data used
to compute the signature hash MUST remain fixed throughout the exchange.

In particular, a BIP370 unique-identifier comparison is insufficient for freezing
the request because that identifier deliberately ignores input sequences.[^sequence]

All targets in one invocation MUST be in the same round. Fields for a target
pass through these states:

| Message | Host commitment | Signer nonce | Host entropy | Target signature |
|---------|-----------------|--------------|--------------|------------------|
| Host request, round 1 | Required | Absent | Absent | Absent |
| Signer response, round 1 | Unchanged | Required | Absent | Absent |
| Host request, round 2 | Unchanged | Unchanged | Required | Absent |
| Signer response, round 2 | Unchanged | Unchanged | Unchanged | Required |

A request carrying these fields requires anti-exfil protection. A signer or
bridge unable to provide it MUST return an error and MUST NOT fall back to
ordinary signing. A host MUST reject signatures returned in the first round,
missing commitments or signatures, malformed fields, changed commitments, early
entropy disclosure, and incomplete or inconsistent field sets. Each target input
has its own independent transcript. Inputs not targeted MUST NOT acquire new
signatures through this exchange. A signer unable to skip untargeted signing keys
MUST reject an unsupported subset before producing any signatures. A target MUST
NOT already contain a key-path signature, script-path signatures, or finalized
script fields. Existing signatures on untargeted inputs are not retroactively
protected by this exchange.

The PSBT MAY remain unfinished because inputs outside the target set still need
signatures. This does not waive verification of any requested target. An
implementation MUST NOT present the operation as protected and complete until all
requested proofs have been verified. The trusted host MAY delegate these checks
to a trusted component providing a checked command boundary; duplicate verification
by each host component is not required. A lower-level transport API MAY return
unchecked protocol data, but MUST identify that boundary and MUST NOT claim its
result has been verified. Merely returning a boolean claiming protection is not a
substitute for the host's verification.

The final response retains the transcript until the trusted host has verified
it. The host MUST compare against its retained state; accepting a signer-substituted
commitment or entropy from a returned PSBT defeats the protection.[^host-state]
A PSBT Combiner MUST NOT replace an immutable transcript
value on a conflict or fill a missing response field before the raw response is
validated.

The trusted host MUST base verified PSBT results on its retained request, copying
only validated target nonce commitments in round one or verified target signatures
in round two. It MAY perform this reconstruction at a trusted bridge's checked
boundary. It MUST preserve the original caller's metadata and transcript, and MUST
NOT forward other signer-added or signer-modified PSBT metadata. This prevents an
independent leakage channel through exported PSBTs; checking the nonce relation
does not sanitize unrelated fields. The host removes all `ae` fields before
exporting or retaining a completed PSBT. Private round responses retain the fields
needed for session continuation or additional verification by another trusted host
component.

The `ae` prefix and field allocation remain provisional and may be moved into a
separate PSBT BIP.

## Rationale and security considerations

### Scope and assumptions

There are two asymmetric threat models. With a malicious signing device and an
honest host, the goal is to constrain the published signature's nonce channel.
The host does not know the signing key. It includes the wallet software,
coordinators, bridges, drivers, and their dependencies. Independent checks within
the host provide defense in depth, without establishing isolation from a
compromised host process.

With a malicious host and an honest device, the device must preserve signing-key
security, ordinary transaction authorization, and key/path checks. Its trusted
display remains responsible for reviewing the transaction. Host commitments,
nonce domain separation, and transcript binding address protocol misuse; they do
not force a malicious host to request anti-exfil protection. Conversely, a
malicious device cannot be trusted to enforce its own preflight checks: the
honest host must perform the checks specified here.

If both host and device collude, the host can publish the key or transcript
directly; this protocol cannot prevent that. It also cannot repair a seed chosen
by an attacker, protect a device that leaks over a separate radio or physical
channel, or prevent leakage through permitted changes to the transaction. Hosts
must separately enforce transaction integrity and allowed sighash types.

The intended property concerns the bytes of verified signatures for the fixed
signing request, observed without the private protocol transcript. It assumes
that an outside observer cannot directly query the device or observe its host
traffic. Nonce points, error strings, unrelated PSBT metadata, and other device
output can carry secrets independently of the final signature. Timing and the
occurrence of failures are also outside this narrow property; the interruption
rules reduce retry-based bias but do not promise availability or eliminate every
observable channel.[^true2f]

These requirements complement existing external-signer PSBT hardening.[^core]
There is no consensus or mempool-policy change.

### Why two commitments?

The device must commit to `R0` before learning `rho` to prevent searching over
nonces after learning the host contribution. Conversely, binding nonce derivation
to the host's initial hash commitment prevents a malicious host obtaining two
signatures with the same original nonce and different known tweaks. The signing
key, public key, message, host commitment, and dedicated protocol tag all
participate in nonce derivation. No API may omit those bindings.

The host contribution is a valid scalar sampled uniformly rather than a hash
reduced modulo the order. That makes its distribution and boundary rules
explicit. Rejecting zero, the order, larger values, and an infinite resulting
nonce also makes independent implementations agree on exceptional cases.

This deterministic derivation prioritizes stateless nonce recovery and retrying
the same transcript. Unlike a construction incorporating fresh signer randomness,
it does not itself provide synthetic nonces against physical side-channel
attacks.[^overview] Signature self-verification is a fault-detection measure, not
a guarantee against arbitrary fault injection or physical leakage. Implementations
may blind their arithmetic without changing the prescribed nonce.

### MuSig2 and collaborative nonce generation

MuSig2 already combines nonce contributions from multiple signers. Its first round
exchanges pairs of public nonce points, from which the final public nonce can be
computed once the message and aggregate key are known. A malicious signer that
learns all other contributions before choosing its own can search for nonce pairs
that encode information in the final signature. BIP327's unforgeability guarantee
and partial-signature verification do not detect such valid contributions.[^musig2]

An honest coordinator can block this adaptive search by collecting contributions
privately: it withholds other signers' public nonces from each device during round
one, records every returned pair, and reveals the complete set only after the
contributions are fixed. This reasoning assumes at least one honest signer supplies
fresh, independent, unpredictable nonces that remain unknown to the entire
colluding malicious subset until all its contributions are fixed. Ledger's
two-phase PSBT signing flow
already provides a way to withhold the other public nonces during phase one;
this staging alone is not a general anti-exfil guarantee.[^ledger-musig2]

For this argument to apply, the coordinator also needs to retain the original full
nonce pairs, bind them to the intended signing session and parameters, reject
replacement contributions, and verify partial signatures against those original
values. The message, participant keys, tweaks, and remaining session parameters
also need to be fixed before the hidden honest contributions are revealed.
Checking against a replacement supplied in round two would allow the adaptive
search again. Selective aborts remain possible after the complete set is
revealed. Automatic retries with fresh nonces can bias which signatures succeed;
reusing secret nonces to sign again is unsafe under MuSig2. Publicly exposing the
individual nonce or partial-signature transcripts also provides a separate channel,
even if the final aggregate signature hides each signer's contribution.

An application that establishes these properties may not need an additional host
nonce contribution solely to block adaptive nonce grinding in the final on-chain
signature. This is a conditional argument about that channel, not an anti-exfil
property established by BIP327's security proof. If all signing devices collude,
there is no honest cosigner contribution on which to base this argument. The
single-signer construction specified here instead obtains fresh randomness from
the honest host and requires no honest cosigner. Extending it to MuSig2, including
its nonce-pair processing and concurrent sessions, is outside this specification.

### Prior work

Schnorr anti-covert-channel implementations were proposed for libsecp256k1 in
2019, before BIP340 was finalized; later work supplied an ECDSA implementation in
secp256k1-zkp and a new BIP340 proposal.[^secp-history] Collaborative nonce
generation and firewalled signing also appear in the True2F literature.[^true2f]
These precedents motivate this specification; their security results do not by
themselves establish security of this particular construction and API.

### API scope

An implementation may expose just commitment, signing, and verification functions
for this protocol. There is no need to expose arbitrary data commitments or a
general sign-to-contract signing interface. Existing work on Schnorr anti-exfil
identified complete specifications, security arguments, independent vectors, and
adversarial protocol tests as prerequisites to deployment.[^secp-review]

The arguments above explain the intended defenses; this draft does not claim a
new formal security proof. Cryptographic review is required before production
deployment, including malicious-host concurrency and cross-protocol interactions.
Security against a malicious host running concurrent sessions under the same key
is a separate requirement from preventing malicious nonce selection.[^concurrency]

## Test vectors and reference implementations

The accompanying `bip-exfil/vectors.json` contains reproducible positive vectors
covering both public-key parities, both final nonce parities, and scalar boundaries.
The reference generator is `bip-exfil/reference.py`. Implementations MUST also
reject changed messages, keys, host entropy, nonce commitments, invalid scalars,
invalid points, infinity, noncanonical encodings, early signatures, and reordered
or mixed transcripts. Transport tests MUST cover untargeted-signature rejection,
transcript provenance, raw-response validation before merging, and preservation of
original host metadata without relaying unrelated signer output. Ordinary BIP340
signature validation remains mandatory even when the nonce relation holds.

### Implementations

Experimental implementation proposals are available for:

- [libsecp256k1 signing and verification API](https://github.com/Sjors/secp256k1/pull/1)
- [Bitcoin Core external-signer coordinator](https://github.com/Sjors/bitcoin/pull/129)
- [HWI bridge and device tests](https://github.com/Sjors/HWI/pull/2)
- [Ledger Bitcoin app](https://github.com/Sjors/ledger-bitcoin-app/pull/1)
- [Trezor firmware](https://github.com/Sjors/trezor-firmware/pull/1)
- [Jade firmware](https://github.com/Sjors/Jade/pull/1)
- [BitBox02 firmware](https://github.com/Sjors/bitbox02-firmware/pull/1)
- [libngu cryptographic helpers](https://github.com/Sjors/libngu/pull/1)
- [Coldcard Edge firmware](https://github.com/Sjors/firmware/pull/1)

## Backward compatibility

Signatures remain ordinary BIP340 signatures, with the normal BIP341 sighash byte
where applicable. Transactions are accepted by existing nodes. PSBT readers that
do not implement this protocol preserve its proprietary fields. Such readers do
not provide anti-exfil verification and MUST NOT be treated as supporting it merely
because they preserve the fields. Applications not requesting protection continue
to use their existing signing flow.

## References

[^overview]: Pieter Wuille, [Overview of anti-covert-channel signing techniques](https://gnusha.org/pi/bitcoindev/VZTbLR9RlkkyNg6mOOIxedh7H0g8NGlaCmgBfCVXZ4RNfW3axefgoTqZGXjAQZFEuekujVGjRMv8SifDIodZ6tRGaaXQ_R63rFa03SGS6rg=@wuille.net/), bitcoin-dev, 3 March 2020. Scheme 6 supplies the additive stateless protocol and discusses its threat models.

[^delving]: Moonsettler, [Non interactive anti-exfil (airgap compatible)](https://delvingbitcoin.org/t/non-interactive-anti-exfil-airgap-compatible/1081), 20 August 2024; Pieter Wuille's replies explain the residual grinding channel of a one-round construction.

[^secp-choice]: Tim Ruffing's [question about S2C versus simple addition](https://github.com/bitcoin-core/secp256k1/pull/1140#issuecomment-1245316220) and Benma's [response](https://github.com/bitcoin-core/secp256k1/pull/1140#issuecomment-1245322066), 13 September 2022.

[^abort]: The [Schnorr anti-exfil implementation proposal](https://github.com/bitcoin-core/secp256k1/pull/1140) documents selective-abort and retry considerations. See also Andrew Poelstra and Jonas Nick, [Anti-Exfil: Stopping Key Exfiltration](https://blog.blockstream.com/anti-exfil-stopping-key-exfiltration/), 9 February 2021.

[^sequence]: [BIP370, Unique Identification](bip-0370.mediawiki#unique-identification) requires setting sequence numbers to zero when computing the PSBT identifier.

[^core]: [Bitcoin Core external-signer PSBT hardening](https://github.com/bitcoin/bitcoin/pull/36114), including transaction merging, unsafe-sighash rejection, and rejection of finalized inputs.

[^secp-review]: Jonas Nick's [specification, security, vector, and failure-test review](https://github.com/bitcoin-core/secp256k1/pull/1140#pullrequestreview-2587222129), 31 January 2025. Related deployed ECDSA experience is described in BitBox's [Anti-klepto explanation](https://blog.bitbox.swiss/en/anti-klepto-explained-protection-against-leaking-private-keys/).

[^nonce-blinding]: Stepan Snigirev, [Nonce blinding protocol for hardware wallets and airgapped signers](https://gnusha.org/pi/bitcoindev/CACL8y1vNEOfATJvkYTOV3pZQA5uac3hbTe9Onfz-38zJUzL_Ug@mail.gmail.com/), bitcoin-dev, 27 February 2020. The proposal includes host entropy hashes, full signer nonce commitments, optional signer metadata, and entropy preimages indexed by signing public key in each PSBT input.

[^host-state]: Marko Bencun's [reply in the nonce-blinding thread](https://gnusha.org/pi/bitcoindev/c6709c19-a6b2-37a8-0d58-4800126f145f@gmail.com/) warns against trusting signer-provided or prefilled host entropy and commitment fields.

[^deployed]: Benma, [Anti-klepto explained](https://blog.bitbox.swiss/en/anti-klepto-explained-protection-against-leaking-private-keys/), 11 February 2021; Andrew Poelstra and Jonas Nick, [Anti-Exfil: Stopping Key Exfiltration](https://blog.blockstream.com/anti-exfil-stopping-key-exfiltration/), 9 February 2021. Jade maintainers discuss the additional PSBT and Schnorr work in [Jade issue 332](https://github.com/Blockstream/Jade/issues/332#issuecomment-5390108061).

[^secp-history]: Jonas Nick's [Schnorr anti-covert-channel implementation](https://github.com/bitcoin-core/secp256k1/pull/590), 2019, and its [closure directing future work to secp256k1-zkp](https://github.com/bitcoin-core/secp256k1/pull/590#issuecomment-1077668520), 24 March 2022; Benma's [BIP340 sign-to-contract and anti-exfil proposal](https://github.com/bitcoin-core/secp256k1/pull/1140), 2022 onward.

[^true2f]: Emma Dauterman, Henry Corrigan-Gibbs, David Mazières, Dan Boneh, and Dominic Rizzo, [True2F: Backdoor-resistant authentication tokens](https://www.scs.stanford.edu/~dm/home/papers/dauterman%3Atrue2f.pdf), IEEE Symposium on Security and Privacy, 2019. Its firewalled ECDSA construction has a different application and signature scheme.

[^musig2]: [BIP327, General Signing Flow and Nonce Generation](bip-0327.mediawiki#general-signing-flow) describes the two-round exchange and permits a stateless last signer to receive the other public nonces before generating its own. Its security guarantee concerns unforgeability; this section's discussion of hidden contributions and nonce bias is additional protocol reasoning.

[^ledger-musig2]: Ledger, [MuSig2 signing flow](https://github.com/LedgerHQ/app-bitcoin/blob/develop/doc/musig.md#signing-flow-in-detail): phase one receives a PSBT without public nonces, while phase two receives the complete set. The document describes device state management and nonce-reuse avoidance, not a general anti-exfil guarantee.

[^concurrency]: Tim Ruffing's [reply to the anti-covert-channel overview](https://gnusha.org/pi/bitcoindev/de7bd393327015a5b97ffff0d15a7c90d2d2196a.camel@timruffing.de/), 21 March 2020, discusses concurrent-session attacks on adaptive host tweaks, key-generation assumptions, and the tradeoff between statelessness and synthetic nonces. These are review considerations, not a proof of this draft.
