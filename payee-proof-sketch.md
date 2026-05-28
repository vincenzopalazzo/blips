```
Title: BOLT 12 Payee Proofs — Design Sketch
Status: Pre-draft (discussion)
Author: Vincenzo Palazzo <vincenzopalazzodev@gmail.com>
Created: 2026-05-28
License: CC0
Related: lightning/bolts#1295 (payer proofs), bLIP-0056 (PoS notifications)
```

## Purpose

This is a pre-bLIP sketch, not a final proposal. It lays out a standard, machine-verifiable format for a *payee* to prove to a third party that they received a specific Lightning payment, mirroring the machinery introduced for payer proofs in [bolts#1295](https://github.com/lightning/bolts/pull/1295) but applied to the other side of the payment.

The goal is to capture the design space and, in particular, the open question of whether a payee signature is needed at all. The next step after this sketch is to pick a direction and write a numbered bLIP.

## Today: invoice + preimage

The de-facto payee proof today is "show the invoice and the preimage". For BOLT 12 this is already cryptographically meaningful: the invoice signature commits `invoice_node_id` to `invoice_payment_hash` and `invoice_amount`, and the preimage hashes to `invoice_payment_hash`. Anyone given the pair can verify "the node behind `invoice_node_id` committed to be paid X for hash H, and someone unlocked H".

Three problems remain:

1. **No verifier binding.** The proof is fully replayable. Anyone who sees `(invoice, preimage)` can re-show it to any other verifier. There is no way for a verifier to challenge the payee for a *fresh* proof of an *old* payment.
2. **No selective disclosure.** The invoice contains fields the payee may not want to leak (blinded paths, `invoice_payer_note`, internal description, fallback addresses). Today it is all-or-nothing.
3. **No envelope.** There is no standard wire/text encoding that says "this blob is a payee proof". Wallets, accounting tools, auditors and tax software all roll their own.

bLIP-0056 explicitly flagged this as Open Question #1 ("Proof of payment") and noted that LDK's stateless inbound payment model makes the naive `(invoice, preimage)` answer harder to produce. A standardized format would unblock that and similar use cases.

## Goal

Define a self-contained payee-proof message that:

- Is produced by the payee after a payment has settled.
- Is bound to a verifier-chosen challenge so it cannot be replayed.
- Supports selective disclosure of invoice fields, reusing the BOLT 12 merkle commitment.
- Has a canonical text encoding (bech32 with an `lnp` / `lnpp` HRP, mirroring #1295).
- Composes with the rest of BOLT 12 — verifier needs only the invoice signing rules and BIP340 verification it already implements.

Non-goals: proving identity of the *payer*, proving the routing path, attesting to time of payment beyond what the invoice already contains.

## Design space

### Does the payee need to sign at all?

This is the core question and it is not obvious. The invoice already carries a payee signature over the merkle root. So the temptation is:

> Payee proof = invoice (selectively disclosed) + preimage + verifier_nonce.

The verifier checks the invoice signature against `invoice_node_id`, checks `sha256(preimage) == invoice_payment_hash`, and is done. **No new payee signature.**

This works for the "did this node get paid for hash H?" question, but it fails the verifier-binding goal: the verifier's `nonce` is never committed to anything, so the proof is still replayable. The nonce is decorative.

To make the verifier nonce *matter*, something fresh has to cover it. Three ways to do that:

**Option A — no new signature, only the preimage covers the nonce.** Have the verifier challenge be a *commitment* the payee includes when first publishing the invoice (e.g. `verifier_commitment` in the invoice TLVs), and the payee reveals it post-payment. This is awkward: the verifier must be known *before* the payment, so it does not fit auditor/tax-software flows.

**Option B — payee schnorr-signs (merkle_root || preimage || verifier_nonce || statement) with `invoice_node_id`.** Symmetric to #1295's payer signature with `invreq_payer_id`. Minimal new state, no new key, no new invoice TLV. Verifier reuses BIP340 verification it already implements for BOLT 12. The verifier nonce now *means* something: the signature is fresh, not replayable.

**Option C — payee signs with an ephemeral `invoice_payee_proof_id` committed in the invoice.** Allows delegation (a custodian or accounting service can produce proofs without holding the node key) and rotation. Costs a new invoice TLV and the key-management surface that comes with it. Probably the right *long-term* answer, but heavier.

### Chosen direction: Option B

Reasons:

- Zero new fields in the BOLT 12 invoice; the proof message is the only new artefact.
- The signing key is already the key the verifier trusts from the invoice signature.
- Matches PR #1295 structurally: payer proofs sign with `invreq_payer_id`, payee proofs sign with `invoice_node_id`. The two specs end up symmetric and easy to teach and verify with a single library.

Option C can be layered on later as an optional `invoice_payee_proof_id` TLV without breaking Option B verifiers.

### What `invoice_node_id` actually is, and why it matters here

`invoice_node_id` is TLV type 176 in the BOLT 12 invoice — a 33-byte compressed pubkey. Per the spec, the payee sets it to one of two values:

- if the invoice request came from an offer with `offer_issuer_id` → `invoice_node_id == offer_issuer_id` (the merchant's persistent node pubkey).
- if it came from an offer using `offer_paths` (no `offer_issuer_id`) → `invoice_node_id == ` the final `blinded_node_id` on the path the invoice request arrived on (a per-path blinded pubkey).

Both cases sign the invoice the same way and verifiers don't care about the distinction. The payee-proof inherits the same property, with two useful consequences:

1. **Privacy comes for free in the blinded-path case.** A merchant who already chose `offer_paths` for privacy does not retroactively de-anonymise themselves by producing a payee proof — the proof is signed by the blinded per-path key, not by the persistent node id. Verifiers can still verify, but they learn no more than they already learned from the invoice. The wording in this spec should therefore say "the pubkey in `invoice_node_id`" rather than "the node's pubkey".
2. **Key retention burden is real.** In the blinded-path case the payee must keep the blinded private key alive long enough to re-sign proofs on demand. Persistent merchants can do this trivially; stateless-inbound setups (LDK) need a deterministic-derivation rule. This is exactly the wrinkle flagged in Open Question #2 below.

### Verifier challenge

Required, not optional. The challenge has two parts:

- `proof_verifier_nonce` (32 bytes, verifier-chosen, MUST be unpredictable to the payee until the proof is requested).
- `proof_statement` (variable, verifier-chosen UTF-8, optional in practice but always part of the signed payload — empty if absent).

The signed payload is:

```
tagged_hash("lightning/payee_proof/v1",
            invoice_merkle_root
         || invoice_payment_hash
         || proof_verifier_nonce
         || sha256(proof_statement))
```

Signature is BIP340 schnorr by `invoice_node_id`. Reusing a tagged hash (BIP340-style) prevents cross-protocol signature reuse.

### Selective disclosure

Reuse PR #1295's machinery wholesale. The invoice's merkle tree is already in BOLT 12; the proof message carries:

- `proof_invoice_tlvs` — the TLVs the payee chooses to reveal.
- `proof_omitted_tlvs` — sorted list of TLV type numbers omitted.
- `proof_missing_hashes` and `proof_leaf_hashes` — exactly as in #1295, so the verifier can reconstruct the merkle root.
- `proof_preimage`.
- `proof_verifier_nonce`, `proof_statement`.
- `proof_signature` (payee).

The TLV envelope reuses the 240–1000 signator range convention from #1295.

### Wire / text encoding

`lnpp1...` bech32 of the TLV stream, mirroring `lnp1...` for payer proofs. Long proofs (typical with many merkle hashes) imply bech32m without the 90-char limit — i.e. the same accommodation BOLT 12 already makes.

## Compatibility

- **With existing `(invoice, preimage)` flow.** A "no-challenge" mode can be defined trivially (verifier nonce = 32 zero bytes, statement = empty, no signature required), which is byte-equivalent in information content to today's `invoice + preimage`. Recommendation: do *not* define this mode in v1 — it brings back the replayability problem. Wallets that want today's behaviour can keep doing it; this proof is opt-in.
- **With PR #1295.** Both proofs sign over the invoice merkle root, so a single verifier library can handle either by switching the verifying key (`invreq_payer_id` vs `invoice_node_id`) and the tagged hash.
- **With bLIP-0056.** Solves Open Question #1 of that bLIP. The PoS, after receiving the merchant's notification, can produce a payee proof on the merchant's behalf if it holds the relevant signing key, or relay the merchant-produced proof.
- **With LDK stateless inbound payments.** The payee must remember enough state to re-sign on demand. For LDK this means either (a) the merchant signs eagerly at payment time and stores the signature, or (b) deterministic re-derivation from a per-payment seed. Option (b) is more LDK-flavoured but needs spec'ing.

## Open questions

1. **Statelessness for LDK and similar.** v1 chose Option B (sign with `invoice_node_id`). In the `offer_paths` case this is a blinded per-path key, so the payee must retain that private key, or re-derive it deterministically, in order to sign proofs after the payment has settled. Should the spec mandate a deterministic-derivation rule for the blinded-path private key? If yes, what is it? (This is the LDK-statelessness blocker for bLIP-0056 Open Question #1.)
2. **MPP / AMP.** Preimage is per-payment, not per-part. Probably nothing to do, but worth a paragraph confirming.
3. **Multiple proofs over the same invoice.** A payee may need to produce N proofs over time to N verifiers. Each verifier_nonce makes them distinct; no replay protection needed on the payee side. Confirm.
4. **Delegation (Option C).** Should v1 punt on the ephemeral `invoice_payee_proof_id` TLV, or include it as optional from day one? Punting is cheaper and forward-compatible. Recommendation: punt.
5. **Naming.** `lnpp` vs `lnpz` vs reusing `lnp` with a discriminator byte. Coordinate with #1295.

## Next steps

1. Get a second opinion from `t-bast` / `rustyrussell` / `jkczyz` on whether this should live as a sibling section in BOLT 12 (next to #1295) or as a standalone bLIP.
2. If bLIP, reserve number 0057 and promote this sketch into the full `blip-0057.md` template structure (Abstract / Motivation / Specification / Rationale / Backwards Compat / Reference Implementation / Open Questions).
3. Build a PoC on top of `vincenzopalazzo/rust-lightning` payer-proof branch, since the merkle/selective-disclosure code is mostly reusable.
