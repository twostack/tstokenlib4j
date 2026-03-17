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

Transaction issuanceTx = tool.createTokenIssuanceTxn(
        fundingTx,              // transaction providing satoshis
        signer,                 // TransactionSigner for the funding input
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
        signer, fundingTx, tokenTx,
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
        fundingTx, fundingSigner,
        recipientWitnessFundingTxId, tokenId, rabinPubKeyHash
);
```

### Minting Fungible Tokens

```java
FungibleTokenTool ftTool = new FungibleTokenTool(NetworkAddressType.TEST_PKH);

Transaction mintTx = ftTool.createFungibleMintTxn(
        fundingTx, signer, recipientAddress,
        witnessFundingTxId, 1_000_000L, metadataBytes
);
```

### Splitting Fungible Tokens

```java
Transaction splitTx = ftTool.createFungibleSplitTxn(
        prevWitnessTx, prevTokenTx,
        currentOwnerPubkey, recipientAddress,
        300_000L,                           // amount to send
        fundingTx, fundingSigner,
        recipientWitnessFundingTxId,
        changeWitnessFundingTxId,
        tokenId, 1_000_000L,                // total balance
        1                                   // prevTripletBaseIndex
);
```

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

The library has three layers:

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

Java 17 or later is required.

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
