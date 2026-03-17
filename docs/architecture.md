# tstokenlib4j Architecture

This document describes the internal architecture of tstokenlib4j for contributors and integrators who need to understand how the library works, extend it with new token archetypes, or maintain cross-language compatibility.

For the TSL1 specification itself, see [https://github.com/twostack/tsl1](https://github.com/twostack/tsl1).

## Library Layers

The library is organized into four layers. Developers interact with the **Tool layer** directly or via the **Plugin layer** when using libspiffy4j; the other two layers are internal.

```
┌─────────────────────────────────────────────────────────────┐
│  Plugin Layer  (plugin package)                             │  ◄── libspiffy4j integration
│  Tsl1TransactionBuilderPlugin, ScriptInfoMetadataMapper     │
├─────────────────────────────────────────────────────────────┤
│  Tool Layer  (transaction package)                          │  ◄── Developer API
│  TokenTool, FungibleTokenTool, StateMachineTool...          │
├─────────────────────────────────────────────────────────────┤
│  Script Layer  (lock + unlock packages)                     │  ◄── Internal
│  PP1NftLockBuilder, PP1FtUnlockBuilder...                   │
├─────────────────────────────────────────────────────────────┤
│  Encoding Layer  (encoding + template packages)             │  ◄── Internal
│  AmountEncoder, TemplateLoader, PartialSha256...            │
└─────────────────────────────────────────────────────────────┘
```

### Tool Layer

The `transaction` package contains six Tool classes, one per token archetype, plus two supporting utilities. Each Tool class orchestrates complete multi-output transaction assembly by composing lock builders, unlock builders, and bitcoin4j's `TransactionBuilder`.

**What the Tools handle:**

- **Output wiring** — Correct output indices, satoshi amounts, and script types for each transaction topology (5/6/7/8-output layouts).
- **Sighash preimage computation** — Builds a first-pass transaction with an empty PP1 unlocker, then computes the sighash preimage over the PP1 spending input.
- **Two-pass witness building** — Computes SHA256 block-alignment padding by building the witness transaction twice: once to measure its size, then again with corrected padding.
- **Metadata forwarding** — Issuance creates metadata via `MetadataLockBuilder`; all subsequent operations carry the metadata forward via `DefaultLockBuilder`.
- **Balance conservation** — Split transactions ensure `sendAmount + changeAmount = totalAmount`; merge transactions sum two parent balances.
- **State management** — The appendable token and state machine tools compute rolling commitment hashes and track milestone counts.

**Supporting utilities:**

- `TransactionUtils` — Serializes the left-hand side of a transaction (`getTxLHS`), computes SHA256 block-alignment padding (`calculatePaddingBytes`), and performs partial SHA256 hashing (`computePartialHash`).
- `PartialSha256` — Block-at-a-time SHA256 implementation that exposes intermediate hash state for partial hash proofs.

### Script Layer

The `lock` and `unlock` packages contain the individual script builders that the Tool classes compose internally. These can also be used directly for advanced or custom transaction assembly.

### Encoding Layer

The `encoding`, `template`, and `crypto` packages provide Bitcoin-specific encoding, script template loading, and Rabin signature utilities.

## The TSL1 Token Model

TSL1 tokens are Bitcoin UTXO-based tokens that use Bitcoin Script's two-stack execution model for on-chain validation. Each token transaction produces a structured set of outputs that encode an **inductive proof** of valid token lineage — the spending transaction must prove that the previous transaction was also valid, forming an unbroken chain back to the genesis (issuance) transaction.

Token state is encoded directly in the locking script parameters (ownerPKH, tokenId, amount, etc.), not in a separate data structure. This makes tokens fully validated by Bitcoin Script without requiring any off-chain indexer for correctness.

## Three-Layer Script Architecture

Every token transaction produces outputs across three script layers:

### PP1 — Token Logic Layer

The PP1 (Plugpoint 1) script contains the full inductive proof logic. It is the core of the token system. When spent, it validates:

- **Ownership**: The spender provides a valid signature matching the `ownerPKH` embedded in the script.
- **Token identity**: The `tokenId` is preserved across transactions.
- **Output structure**: The spending transaction produces correctly formatted token outputs (verified via `tokenLHS` and `preImage`).
- **Inductive proof**: The previous token transaction (`prevTokenTx`) was itself a valid token transaction.
- **Archetype-specific rules**: Amount conservation (FT), Rabin identity anchoring (NFT/RNFT), state transitions (SM), stamp thresholds (AT), etc.

Each token archetype has its own PP1 script template:

| Archetype | Template | Key Parameters |
|-----------|----------|---------------|
| Fungible Token | `templates/ft/pp1_ft.json` | ownerPKH, tokenId, amount |
| Non-Fungible Token | `templates/nft/pp1_nft.json` | ownerPKH, tokenId, rabinPubKeyHash |
| Restricted FT | `templates/ft/pp1_rft.json` | ownerPKH, tokenId, rabinPubKeyHash, flags, amount |
| Restricted NFT | `templates/nft/pp1_rnft.json` | ownerPKH, tokenId, rabinPubKeyHash, flags |
| State Machine | `templates/sm/pp1_sm.json` | ownerPKH, tokenId, merchantPKH, customerPKH, currentState, milestoneCount, commitmentHash, transitionBitmask, timeoutDelta |
| Appendable Token | `templates/nft/pp1_at.json` | ownerPKH, tokenId, issuerPKH, stampCount, threshold, stampsHash |

### PP2 — Witness Layer

The PP2 (Plugpoint 2) script is a secondary locking script that "plugs into" the token transaction, anchoring it to a specific UTXO outpoint. It serves two purposes:

1. **Outpoint binding**: Ensures the token UTXO can only be spent in a transaction that also spends a specific witness UTXO, preventing replay attacks.
2. **Witness change**: Handles change from the witness funding, allowing transaction fees to be paid from the witness UTXO.

| Variant | Template | Key Parameters |
|---------|----------|---------------|
| NFT PP2 | `templates/nft/pp2.json` | outpoint (36 bytes), witnessChangePKH, witnessChangeAmount, ownerPKH |
| FT PP2 | `templates/ft/pp2_ft.json` | outpoint, witnessChangePKH, witnessChangeAmount, ownerPKH, pp1FtOutputIndex, pp2OutputIndex |

### PP3 / Partial Witness — Funding Layer

The PP3 (Plugpoint 3 / Partial Witness) script is the simplest layer — a modified P2PKH script for the witness funding input.

| Variant | Template |
|---------|----------|
| NFT Witness | `templates/nft/pp3_witness.json` |
| FT Witness | `templates/ft/pp3_ft_witness.json` |

### Metadata Output

The `MetadataLockBuilder` produces an `OP_FALSE OP_RETURN` output for attaching off-chain metadata to token transactions. This is the only lock builder that does **not** use the template system — it builds the script directly via `ScriptBuilder`.

### Utility: ModP2PKH

The `ModP2PKHLockBuilder` produces a modified Pay-to-Public-Key-Hash script used for witness outputs and change. Template: `templates/utility/mod_p2pkh.json`.

## Two-Pass Witness Building

The witness transaction uses a two-pass build to ensure correct SHA256 block-alignment padding:

```
Pass 1: Build with empty PP1 unlocker
   └─► Compute sighash preimage over PP1 input

   Build PP1 unlocker with preimage + 1-byte placeholder padding
   └─► Build witness transaction
   └─► Calculate actual padding bytes from tx size

Pass 2: Rebuild PP1 unlocker with correct padding
   └─► Rebuild witness transaction (final)
```

The padding ensures that the last input of the witness transaction starts on a 64-byte (SHA256 block) boundary, enabling the partial SHA256 witness proof mechanism. `TransactionUtils.calculatePaddingBytes()` computes this alignment.

## Template System

### Template JSON Format

Each template is a JSON file at `src/main/resources/templates/` with this structure:

```json
{
  "name": "PP1_NFT",
  "version": "1.3.0",
  "description": "NFT inductive proof locking script...",
  "category": "nft",
  "parameters": [
    {
      "name": "ownerPKH",
      "size": 20,
      "encoding": "hex",
      "description": "20-byte pubkey hash of the token owner"
    }
  ],
  "hex": "14{{ownerPKH}}20{{tokenId}}14{{rabinPubKeyHash}}6b6b6b...",
  "metadata": {
    "generatedBy": "PP1NftScriptGen",
    "sourceFile": "lib/src/script_gen/pp1_nft_script_gen.dart"
  }
}
```

### Placeholder Substitution

**PP1 templates** use **raw hex substitution** — pushdata prefixes are baked into the template hex. Parameters are substituted as raw hex-encoded bytes:

```java
hex = hex.replace("{{ownerPKH}}", Utils.HEX.encode(ownerPKH));
```

**PP2 templates** use **dynamic-length encoding** via `PushdataEncoder` or `ScriptNumberEncoder`:

```java
hex = hex.replace("{{outpoint}}", PushdataEncoder.encode(outpoint));
hex = hex.replace("{{witnessChangeAmount}}", ScriptNumberEncoder.encode(witnessChangeAmount));
```

### Template Loading and Caching

`TemplateLoader.load(String resourcePath)` loads templates from the classpath and caches them in a `ConcurrentHashMap` for thread-safe reuse.

### Template Generation

Templates are **generated by the canonical Dart implementation**. They should **never be hand-edited**. To update a template:

1. Modify the Dart script generator
2. Re-run the generator to produce updated JSON
3. Copy the JSON to `src/main/resources/templates/`
4. Run `CrossLanguageVectorTest` to verify byte-identical output

## Lock/Unlock Pattern

### Lock Builders (scriptPubKey)

All lock builders extend `LockingScriptBuilder` from bitcoin4j and override `getLockingScript()`:

1. Load the template JSON via `TemplateLoader.load()`
2. Get the hex string from `TemplateDescriptor.getHex()`
3. Replace `{{placeholder}}` markers with encoded parameter values
4. Decode the final hex string to a `Script` object

Constructor conventions:
- Validate all byte array parameters for null and correct length
- Throw `IllegalArgumentException` on validation failure
- Defensively clone all byte array inputs and on getter access

### Unlock Builders (scriptSig)

All unlock builders extend `UnlockingScriptBuilder` from bitcoin4j and override `getUnlockingScript()`:

1. Dispatch to a private `buildAction()` method based on the action enum
2. Use `ScriptBuilder` to push data items onto the stack in the exact order expected by the lock script
3. Push the action's `opValue` as the **last item** — the lock script uses this as a dispatch selector

Factory method conventions:
- Private constructor, public static factory methods named `forAction()` (e.g., `forMint()`, `forTransfer()`, `forBurn()`)
- Each factory method enforces the correct set of parameters for that action at compile time
- **ISSUANCE / MINT / CREATE** actions typically do **not** require a signature
- **TRANSFER**, **BURN**, **REDEEM**, and most other actions require `addSignature()` before `getUnlockingScript()` produces output

## Encoding Utilities

### AmountEncoder

`encodeLeUint56(long value)` encodes a fungible token amount as an 8-byte little-endian value with bit 63 clear. Maximum value: 2^55 - 1.

### PushdataEncoder

`encode(byte[] data)` encodes a byte array as a Bitcoin pushdata operation. Returns a hex string of the complete script fragment (length prefix + data).

### ScriptNumberEncoder

`encode(long value)` encodes a long value as a Bitcoin script number. Returns a hex string of the complete script fragment.

## Rabin Cryptography

The `crypto` package provides Rabin signature utilities used by restricted token archetypes (RNFT, RFT) for identity anchoring:

- `Rabin.generateKeyPair(int bitLength)` — Generate Blum prime keypairs
- `Rabin.sign(BigInteger messageHash, BigInteger p, BigInteger q)` — Sign a message hash
- `Rabin.verify(BigInteger messageHash, RabinSignature sig, BigInteger n)` — Verify a signature
- `Rabin.rabinPubKeyHash(BigInteger n)` — HASH160 of the Rabin public key
- `Rabin.bigIntToScriptNum(BigInteger value)` — Encode for Bitcoin Script

## Cross-Language Compatibility

The Dart `tstokenlib` library is the **canonical/reference implementation**. This Java library must produce **byte-identical** script output for the same inputs.

`CrossLanguageVectorTest` loads test vectors from `src/test/resources/cross_language_vectors.json`, generated by `dart run tool/export_test_vectors.dart` in the Dart project.

## Plugin Layer

The `plugin` package bridges tstokenlib4j to libspiffy4j's wallet plugin system, allowing the wallet coordinator to identify, enrich, build, and validate TSL1 token transactions without coupling directly to the Tool or Script layers.

### Tsl1TransactionBuilderPlugin

`Tsl1TransactionBuilderPlugin` implements both `ScriptPlugin` and `TransactionBuilderPlugin` from libspiffy4j. It supports all six token archetypes (NFT, FT, RNFT, RFT, AT, SM) and exposes the following capabilities to the wallet:

- **`identifyScript(Script)`** — Delegates to `PP1TemplateRegistrar` to match output scripts against PP1 templates and return the token type identifier (e.g., `pp1_nft`, `pp1_ft`).
- **`extractMetadata(Script)`** — Parses embedded parameters (ownerPKH, tokenId, amount, etc.) and returns them as a `Map<String, Object>` for UTXO enrichment.
- **`createLockingScript(String scriptType, Map params)`** — Builds a PP1 locking script for the given archetype using the appropriate lock builder.
- **`buildTransaction(String action, Map params)`** — Delegates to the appropriate Tool class to assemble a complete multi-output transaction.
- **`validateTransactionStructure(Transaction, String action)`** — Checks output counts and layout constraints per action type.

### ScriptInfoMetadataMapper

`ScriptInfoMetadataMapper` converts bitcoin4j's `ScriptInfo` objects into `Map<String, Object>` metadata suitable for the wallet's UTXO enrichment pipeline. This mapper handles the type-safe extraction of byte arrays, addresses, and numeric fields from parsed script parameters.

### PluginParamExtractor

`PluginParamExtractor` provides safe typed extraction from the `Map<String, Object>` parameter maps that flow through the plugin interface. It handles type coercion, null checks, and hex decoding for common parameter types (byte arrays, `PublicKey`, `Address`, `BigInteger`, etc.).

### compileOnly Dependency Pattern

libspiffy4j is declared as a `compileOnly` dependency in the build. This means:

- tstokenlib4j compiles against libspiffy4j's plugin interfaces but does not bundle them in its JAR.
- The host application (e.g., a Jmix-based wallet) provides libspiffy4j at runtime.
- Applications that do not use libspiffy4j can use the Tool layer directly with no extra dependencies.

## Adding a New Token Archetype

To add a new token archetype (e.g., a hypothetical "Composable Token"):

### 1. Create the Template

Generate the template JSON using the Dart script generator and place it in `src/main/resources/templates/`.

### 2. Create the Action Enum

Add a new enum in `org.twostack.tstokenlib4j.unlock`:

```java
public enum ComposableTokenAction {
    COMPOSE(0), TRANSFER(1), DECOMPOSE(2), BURN(3);
    public final int opValue;
    // constructor and getter
}
```

### 3. Create Lock and Unlock Builders

Follow the existing patterns in the `lock` and `unlock` packages.

### 4. Create the Tool Class

Add a new Tool class in `org.twostack.tstokenlib4j.transaction` following the
existing Tool patterns:

- Constructor takes `NetworkAddressType` and optional `BigInteger defaultFee`
- Public methods return `Transaction` and throw the standard exception set
- Implement two-pass witness building
- Handle metadata forwarding

### 5. Add Tests

- Unit tests for lock/unlock builders
- Cross-language test vectors from the Dart implementation
- Tool-level integration tests

### 6. Update Documentation

- Javadoc on all new classes
- Update the token type table in README.md
- Update this architecture document
