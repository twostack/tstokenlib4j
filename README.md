# tstokenlib4j

A Java library for building and unlocking Bitcoin token scripts per the [TSL1 (Two Stack Language) token specification](https://github.com/twostack/tsl1). Provides template-driven locking script (scriptPubKey) generation and action-driven unlocking script (scriptSig) generation for six token archetypes.

## Token Types

| Archetype | Lock Builder | Unlock Builder | Actions |
|-----------|-------------|----------------|---------|
| Fungible Token (FT) | `PP1FtLockBuilder` | `PP1FtUnlockBuilder` | Mint, Transfer, Split Transfer, Merge, Burn |
| Non-Fungible Token (NFT) | `PP1NftLockBuilder` | `PP1NftUnlockBuilder` | Issuance, Transfer, Burn |
| Restricted FT (RFT) | `PP1RftLockBuilder` | `PP1RftUnlockBuilder` | Mint, Transfer, Split Transfer, Merge, Redeem, Burn |
| Restricted NFT (RNFT) | `PP1RnftLockBuilder` | `PP1RnftUnlockBuilder` | Issuance, Transfer, Redeem, Burn |
| State Machine (SM) | `PP1SmLockBuilder` | `PP1SmUnlockBuilder` | Create, Enroll, Confirm, Convert, Settle, Timeout, Burn |
| Appendable Token (AT) | `PP1AtLockBuilder` | `PP1AtUnlockBuilder` | Issuance, Stamp, Transfer, Redeem, Burn |

Each token transaction also uses **PP2** (witness) and **PP3/PartialWitness** (funding) scripts, plus an optional **Metadata** output.

## TSL1 Terminology

| Term | Description |
|------|-------------|
| **PP1 (Proof Part 1)** | Primary token locking script containing the inductive proof logic. Encodes ownership, token identity, and archetype-specific parameters. |
| **PP2 (Proof Part 2)** | Witness locking script that anchors a token transaction to a specific UTXO outpoint and handles witness change. |
| **PP3 / Partial Witness** | Lightweight witness script for the witness funding input. |
| **ownerPKH** | 20-byte HASH160 of the token owner's public key. |
| **tokenId** | 32-byte unique token identifier, typically the genesis transaction ID. |
| **rabinPubKeyHash** | 20-byte HASH160 of a Rabin signature public key, used for identity anchoring in NFTs and restricted tokens. |
| **preImage** | Sighash preimage of the transaction, required by OP_PUSH_TX for self-referential script validation. |
| **witnessPadding** | Padding bytes for the witness funding transaction to ensure correct script alignment. |
| **tokenLHS** | Left-hand side of the serialized token output, used to verify output structure during transfers. |
| **prevTokenTx** | Raw bytes of the previous token transaction, used for inductive proof verification. |

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

### Creating an NFT Locking Script

```java
byte[] ownerPKH = ...;       // 20-byte HASH160 of owner's public key
byte[] tokenId = ...;         // 32-byte token identifier
byte[] rabinPubKeyHash = ...; // 20-byte HASH160 of Rabin public key

PP1NftLockBuilder lockBuilder = new PP1NftLockBuilder(ownerPKH, tokenId, rabinPubKeyHash);
Script lockingScript = lockBuilder.getLockingScript();
```

### Creating a Fungible Token Locking Script

```java
byte[] ownerPKH = ...;  // 20-byte HASH160 of owner's public key
byte[] tokenId = ...;    // 32-byte token identifier
long amount = 1000;       // token amount (max 2^55 - 1)

PP1FtLockBuilder lockBuilder = new PP1FtLockBuilder(ownerPKH, tokenId, amount);
Script lockingScript = lockBuilder.getLockingScript();
```

### Unlocking an NFT for Transfer

```java
PP1NftUnlockBuilder unlockBuilder = PP1NftUnlockBuilder.forTransfer(
    preImage, pp2Output, ownerPubKey,
    changePKH, changeAmount,
    tokenLHS, prevTokenTx, witnessPadding
);

// Add signature (required for transfer)
unlockBuilder.addSignature(signature);

Script unlockingScript = unlockBuilder.getUnlockingScript();
```

### Parsing a PP1 Script

```java
Script lockingScript = ...; // any PP1* locking script

Optional<PP1TokenScriptParser.TokenScriptInfo> info =
    PP1TokenScriptParser.parse(lockingScript);

info.ifPresent(i -> {
    byte[] ownerPKH = i.ownerPKH();
    byte[] tokenId = i.tokenId();
});
```

## Architecture

The library uses a three-layer script architecture:

1. **PP1 (Token Logic)** — Contains the full inductive proof script. Validates token integrity, ownership signatures, and output structure. Each archetype has its own PP1 script.
2. **PP2 (Witness)** — Anchors the token transaction to a specific UTXO outpoint. Handles witness change for transaction fees.
3. **PP3 / Partial Witness (Funding)** — Modified P2PKH script for the witness funding input.
4. **Metadata** — Optional OP_FALSE OP_RETURN output for off-chain metadata.

Lock scripts are generated via **template substitution** — JSON templates at `src/main/resources/templates/` contain hex script patterns with `{{placeholder}}` markers that are replaced with encoded parameter values.

Unlock scripts are built via **action-specific factory methods** (e.g., `forMint()`, `forTransfer()`) that push data items onto the stack in the exact order expected by the corresponding lock script.

See [docs/architecture.md](docs/architecture.md) for detailed architecture documentation.

## Cross-Language Compatibility

Script outputs are validated byte-identical against the canonical Dart implementation via `CrossLanguageVectorTest`. Test vectors are loaded from `src/test/resources/cross_language_vectors.json`.

## Building from Source

```bash
# Requires bitcoin4j 1.7.0 in mavenLocal
./gradlew build
```

Java 17 or later is required.

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
