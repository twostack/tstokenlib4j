# tstokenlib4j

A Java library for building complete Bitcoin token transactions per the [TSL1 (Twostack Layer 1) specification](https://github.com/twostack/tsl1). Provides high-level transaction assembly for six token archetypes — NFT, fungible, restricted, appendable, and state machine tokens — with full support for issuance, transfer, witness proofs, and burns.

## Installation

tstokenlib4j requires `bitcoin4j` to be installed in your local Maven repository.

```groovy
repositories {
    mavenCentral()
    mavenLocal()
}

dependencies {
    implementation 'org.twostack:tstokenlib4j:0.1.0'
}
```

## Quick Start

### Issuing an NFT

```java
TokenTool tool = new TokenTool(NetworkAddressType.TEST_PKH);

SigningCallback signingCallback = sighash -> privateKey.sign(sighash);

Transaction issuanceTx = tool.createTokenIssuanceTxn(
        fundingTx,              // transaction providing satoshis
        signingCallback,        // signs sighash digests externally
        publicKey,              // public key for the funding input
        recipientAddress,       // Address of the token recipient
        witnessFundingTxId,     // 32-byte txid of the first witness funder
        rabinPubKeyHash,        // 20-byte HASH160 of Rabin oracle key
        metadataBytes           // optional OP_RETURN payload (or null)
);
```

### Creating a Witness Proof

Every token action requires a corresponding witness transaction that proves
the token owner authorised the state change.

```java
Transaction witnessTx = tool.createWitnessTxn(
        signingCallback, publicKey, fundingTx, tokenTx,
        parentTokenTxBytes, ownerPubkey, changePKH,
        TokenAction.ISSUANCE,
        rabinN, rabinS, rabinPadding, identityTxId, ed25519PubKey
);
```

### Transferring an NFT

```java
Transaction transferTx = tool.createTokenTransferTxn(
        prevWitnessTx, prevTokenTx,
        currentOwnerPubkey, recipientAddress,
        fundingTx, signingCallback, publicKey,
        recipientWitnessFundingTxId, tokenId, rabinPubKeyHash
);
```

### Minting Fungible Tokens

```java
FungibleTokenTool ftTool = new FungibleTokenTool(NetworkAddressType.TEST_PKH);

SigningCallback signingCallback = sighash -> privateKey.sign(sighash);

Transaction mintTx = ftTool.createFungibleMintTxn(
        fundingTx, signingCallback, publicKey, recipientAddress,
        witnessFundingTxId, 1_000_000L, metadataBytes
);
```

### Splitting Fungible Tokens

```java
Transaction splitTx = ftTool.createFungibleSplitTxn(
        prevWitnessTx, prevTokenTx,
        currentOwnerPubkey, recipientAddress,
        300_000L,                           // amount to send
        fundingTx, signingCallback, publicKey,
        recipientWitnessFundingTxId,
        changeWitnessFundingTxId,
        tokenId, 1_000_000L,                // total balance
        1                                   // prevTripletBaseIndex
);
```

## Signing

All Tool methods accept a `SigningCallback` and `PublicKey` instead of a bitcoin4j `TransactionSigner`. This decouples transaction building from private key management.

`SigningCallback` is a `@FunctionalInterface` with a single method:

```java
@FunctionalInterface
public interface SigningCallback {
    byte[] sign(byte[] sighash);
}
```

The callback receives a 32-byte sighash digest and returns a DER-encoded ECDSA signature. This makes it compatible with any signing backend:

```java
// Local key:
SigningCallback signer = sighash -> privateKey.sign(sighash);

// KMS or HSM:
SigningCallback signer = sighash -> kms.sign(merchantId, sighash);

// libspiffy4j's CallbackTransactionSigner:
CallbackTransactionSigner spiffySigner = ...;
SigningCallback signer = sighash -> spiffySigner.sign(sighash, 0);
```

Internally, `SignerAdapter.fromCallback(callback, publicKey)` bridges a `SigningCallback` to bitcoin4j's `TransactionSigner` so the underlying `TransactionBuilder` workflow is unchanged. Application code never needs to call `SignerAdapter` directly — the Tool classes handle the adaptation.

## Plugin Integration

tstokenlib4j provides a plugin for [libspiffy4j](https://github.com/AgenticGroup/libspiffy4j)'s wallet plugin system. The plugin delegates to the existing parser (`PP1TemplateRegistrar`) for script identification and to Tool classes for transaction building.

libspiffy4j is a `compileOnly` dependency — the host application provides it at runtime. To register the plugin:

```java
var plugin = new Tsl1TransactionBuilderPlugin(NetworkAddressType.MAIN_PKH);
pluginRegistry.register(plugin);
```

`Tsl1TransactionBuilderPlugin` implements both `ScriptPlugin` and `TransactionBuilderPlugin`, supporting all six token archetypes with:

- `identifyScript()` — Matches output scripts against PP1 templates to detect token type
- `extractMetadata()` — Extracts ownerAddress, tokenId, amount, and other fields for UTXO enrichment
- `createLockingScript()` — Builds PP1 locking scripts for new token outputs
- `buildTransaction()` — Delegates to the appropriate Tool class for complete transaction assembly
- `validateTransactionStructure()` — Checks output counts and layout per action type

## Token Archetypes

Each archetype has a dedicated **Tool** class that assembles complete multi-output transactions:

| Tool Class | Archetype | Operations |
|---|---|---|
| `TokenTool` | Non-Fungible Token (NFT) | issue, transfer, witness, burn |
| `FungibleTokenTool` | Fungible Token (FT) | mint, transfer, split, merge, witness, burn |
| `RestrictedTokenTool` | Restricted NFT (RNFT) | issue, transfer, witness, redeem, burn |
| `RestrictedFungibleTokenTool` | Restricted FT (RFT) | mint, transfer, split, merge, witness, redeem, burn |
| `AppendableTokenTool` | Appendable Token (AT) | issue, stamp, transfer, witness, redeem, burn |
| `StateMachineTool` | State Machine (SM) | create, enroll, confirm, convert, settle, timeout, witness, dual-witness, burn |

All Tool constructors take a `NetworkAddressType` and an optional `BigInteger` fee
(defaults to 135 satoshis):

```java
TokenTool tool = new TokenTool(NetworkAddressType.TEST_PKH);
TokenTool mainnet = new TokenTool(NetworkAddressType.MAIN_PKH, BigInteger.valueOf(200));
```

## Transaction Layouts

TSL1 transactions follow a structured multi-output layout. The Tool classes
handle all wiring automatically.

### Standard 5-Output Layout

Used by issuance, transfer, and most state transitions:

```
Output 0: Change        — P2PKH back to the signer
Output 1: PP1 (token)   — Inductive proof locking script (1 satoshi)
Output 2: PP2 (witness) — Outpoint-anchored witness bridge (1 satoshi)
Output 3: PP3 (partial) — SHA256 partial witness verifier (1 satoshi)
Output 4: Metadata      — OP_RETURN payload (0 satoshis)
```

### Split Layout (8 Outputs)

Used by `createFungibleSplitTxn` and `createRftSplitTxn`:

```
Output 0:   Change
Output 1–3: Recipient triplet (PP1_FT, PP2-FT, PP3-FT)
Output 4–6: Sender change triplet (PP1_FT, PP2-FT, PP3-FT)
Output 7:   Metadata
```

### Settle Layout (7 Outputs)

Used by `StateMachineTool.createSettleTxn`:

```
Output 0: Change
Output 1: Customer reward (P2PKH)
Output 2: Merchant payment (P2PKH)
Output 3–5: PP1_SM, PP2, PP3
Output 6: Metadata
```

### Timeout Layout (6 Outputs)

Used by `StateMachineTool.createTimeoutTxn` (with `nLockTime`):

```
Output 0: Change
Output 1: Merchant refund (P2PKH)
Output 2–4: PP1_SM, PP2, PP3
Output 5: Metadata
```

### Witness Layout (1 Output)

Used by all `createWitnessTxn` methods:

```
Output 0: ModP2PKH locked to current token owner (1 satoshi)
```

## Witness Proof Lifecycle

Every token operation follows a two-transaction pattern:

1. **Token Transaction** — Creates or updates the token outputs (5+ outputs).
2. **Witness Transaction** — Proves ownership by spending PP1 + PP2 from the token
   transaction and producing a single witness output.

The witness transaction uses a **two-pass build**: the first pass computes the
sighash preimage, and the second pass recalculates SHA256 block-alignment padding
to ensure the partial hash proof is valid.

```
           ┌──────────────────┐     ┌──────────────────┐
           │  Token Tx        │     │  Witness Tx       │
           │                  │     │                   │
Funding ──►│  PP1 (token)  ──────►──│  PP1 (unlock)     │
           │  PP2 (witness)──────►──│  PP2 (unlock)     │
           │  PP3 (partial)   │     │                   │
           │  Metadata        │     │  Witness output   │
           │  Change          │     └──────────────────┘
           └──────────────────┘
```

Transfers then spend the witness output + PP3 from the token transaction to
produce the next token transaction in the chain.

## Transaction Sizes and Fees

Approximate on-chain sizes for core token operations. The PP3 witness verifier
(~49KB, containing two rounds of hand-optimized partial SHA-256) dominates the
transaction size. The transfer witness carries the full serialized parent token
transaction (`parentRawTx`) as required by the inductive proof — this is constant-size
and does not grow with successive transfers.

### NFT

| Transaction | Size | Fee @ 1 sat/KB | Fee @ 100 sat/KB |
|-------------|-----:|---------------:|-----------------:|
| Issuance Tx | ~55 KB | 55 sats | 5,500 sats |
| Issuance Witness | ~1 KB | 1 sat | 100 sats |
| **Issuance pair** | **~56 KB** | **56 sats** | **5,600 sats** |
| Transfer Tx | ~55 KB | 55 sats | 5,500 sats |
| Transfer Witness | ~56 KB | 56 sats | 5,600 sats |
| **Transfer pair** | **~111 KB** | **111 sats** | **11,100 sats** |

### Fungible Token

| Transaction | Size | Fee @ 1 sat/KB | Fee @ 100 sat/KB |
|-------------|-----:|---------------:|-----------------:|
| Mint Tx | ~61 KB | 61 sats | 6,100 sats |
| Mint Witness | ~1 KB | 1 sat | 100 sats |
| **Mint pair** | **~62 KB** | **62 sats** | **6,200 sats** |
| Transfer Tx | ~61 KB | 61 sats | 6,100 sats |
| Transfer Witness | ~62 KB | 62 sats | 6,200 sats |
| **Transfer pair** | **~123 KB** | **123 sats** | **12,300 sats** |

Sizes are approximate and vary slightly with key sizes, padding, and metadata.
Split transactions (8 outputs with two triplets) are roughly 1.5x the transfer size.

## TSL1 Terminology

| Term | Description |
|------|-------------|
| **PP1 (Plugpoint 1)** | Primary token locking script containing the inductive proof logic. Encodes ownership, token identity, and archetype-specific parameters. |
| **PP2 (Plugpoint 2)** | Witness locking script that "plugs into" the token transaction, anchoring it to a specific UTXO outpoint. |
| **PP3 (Plugpoint 3)** | Lightweight partial witness script used for witness funding inputs. |
| **ownerPKH** | 20-byte HASH160 of the token owner's public key. |
| **tokenId** | 32-byte unique token identifier — the genesis transaction ID. |
| **preImage** | Sighash preimage of the transaction, required by OP_PUSH_TX for self-referential script validation. |
| **witnessPadding** | Padding bytes that align the witness transaction to SHA256 block boundaries. |
| **tokenLHS** | Left-hand side of the serialized token transaction (version + inputs), used for output structure verification. |

## Architecture

The library has four layers:

### Plugin Layer (libspiffy4j integration)

The `plugin` package bridges tstokenlib4j to libspiffy4j's wallet plugin system:

- `Tsl1TransactionBuilderPlugin` — Implements `ScriptPlugin` + `TransactionBuilderPlugin` for all six archetypes
- `ScriptInfoMetadataMapper` — Converts `ScriptInfo` into metadata maps for UTXO enrichment

### Tool Layer (developer-facing)

The `transaction` package provides the six Tool classes that developers use
directly. Each Tool assembles complete transactions by composing the lower
layers:

- Transaction output wiring (correct indices, satoshi amounts)
- Sighash preimage computation
- Two-pass witness padding calculation
- Metadata forwarding across transfers
- Balance conservation (splits/merges)

### Script Layer (internal)

The `lock` and `unlock` packages contain the individual script builders.
These are used internally by the Tool classes but can also be used directly
for advanced or custom transaction assembly:

- **Lock builders** load JSON templates and substitute parameters
- **Unlock builders** use static factory methods (`forMint()`, `forTransfer()`, etc.)

### Encoding Layer (internal)

The `encoding` package provides Bitcoin-specific value encoding:

- `AmountEncoder` — 7-byte LE encoding for FT amounts
- `PushdataEncoder` — Bitcoin pushdata framing
- `ScriptNumberEncoder` — Bitcoin script number encoding

See [docs/architecture.md](docs/architecture.md) for detailed internals.

## Cross-Language Compatibility

Script outputs are validated byte-identical against the canonical Dart
implementation via `CrossLanguageVectorTest`. Test vectors are loaded from
`src/test/resources/cross_language_vectors.json`.

## Building from Source

```bash
# Requires bitcoin4j 1.7.0 in mavenLocal
./gradlew build        # compile + test
./gradlew test         # tests only
./gradlew javadoc      # generate Javadoc
```

Java 21 or later is required.

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
