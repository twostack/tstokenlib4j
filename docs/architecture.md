# tstokenlib4j Architecture

This document describes the internal architecture of tstokenlib4j for contributors and integrators who need to understand how the library works, extend it with new token archetypes, or maintain cross-language compatibility.

For the TSL1 specification itself, see [https://github.com/twostack/tsl1](https://github.com/twostack/tsl1).

## The TSL1 Token Model

TSL1 tokens are Bitcoin UTXO-based tokens that use Bitcoin Script's two-stack execution model for on-chain validation. Each token transaction produces a structured set of outputs that encode an **inductive proof** of valid token lineage — the spending transaction must prove that the previous transaction was also valid, forming an unbroken chain back to the genesis (issuance) transaction.

Token state is encoded directly in the locking script parameters (ownerPKH, tokenId, amount, etc.), not in a separate data structure. This makes tokens fully validated by Bitcoin Script without requiring any off-chain indexer for correctness.

## Three-Layer Script Architecture

Every token transaction produces outputs across three layers:

### PP1 — Token Logic Layer

The PP1 (Proof Part 1) script contains the full inductive proof logic. It is the core of the token system. When spent, it validates:

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

The PP2 (Proof Part 2) script is a secondary locking script that anchors the token transaction to a specific UTXO outpoint. It serves two purposes:

1. **Outpoint binding**: Ensures the token UTXO can only be spent in a transaction that also spends a specific witness UTXO, preventing replay attacks.
2. **Witness change**: Handles change from the witness funding, allowing transaction fees to be paid from the witness UTXO.

PP2 scripts are simpler than PP1 and have fewer parameters:

| Variant | Template | Key Parameters |
|---------|----------|---------------|
| NFT PP2 | `templates/nft/pp2.json` | outpoint (36 bytes), witnessChangePKH, witnessChangeAmount, ownerPKH |
| FT PP2 | `templates/ft/pp2_ft.json` | outpoint, witnessChangePKH, witnessChangeAmount, ownerPKH, pp1FtOutputIndex, pp2OutputIndex |

### PP3 / Partial Witness — Funding Layer

The PP3 (Partial Witness) script is the simplest layer — a modified P2PKH script for the witness funding input. It provides the satoshis that pay for the transaction while the token UTXOs carry the token value.

| Variant | Template |
|---------|----------|
| NFT Witness | `templates/nft/pp3_witness.json` |
| FT Witness | `templates/ft/pp3_ft_witness.json` |

### Metadata Output

The `MetadataLockBuilder` produces an `OP_FALSE OP_RETURN` output for attaching off-chain metadata to token transactions. This is the only lock builder that does **not** use the template system — it builds the script directly via `ScriptBuilder`.

### Utility: ModP2PKH

The `ModP2PKHLockBuilder` produces a modified Pay-to-Public-Key-Hash script used for various utility purposes in the token ecosystem. Template: `templates/utility/mod_p2pkh.json`.

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
    "sourceFile": "lib/src/script_gen/pp1_nft_script_gen.dart",
    "note": "Pushdata prefixes (0x14, 0x20) are part of the static hex..."
  }
}
```

**Fields:**
- `name` — Template identifier (e.g., `PP1_NFT`)
- `version` — Template version, tracks script logic changes
- `description` — Human-readable description
- `category` — Grouping: `ft`, `nft`, `sm`, `utility`
- `parameters` — Array of parameter descriptors with name, byte size, encoding type, and description
- `hex` — The script hex with `{{placeholder}}` markers for parameter substitution
- `metadata` — Generation source info (Dart script gen class, source file)

### Placeholder Substitution

Lock builders load templates via `TemplateLoader.load(resourcePath)` and replace `{{placeholder}}` markers with encoded parameter values.

**PP1 templates** use **raw hex substitution**. Pushdata prefixes (like `0x14` for 20 bytes, `0x20` for 32 bytes) are baked into the template hex itself. Parameters are substituted as raw hex-encoded bytes:

```java
// PP1NftLockBuilder — raw hex substitution
hex = hex.replace("{{ownerPKH}}", Utils.HEX.encode(ownerPKH));
```

In the template: `14{{ownerPKH}}` → `0x14` is the pushdata prefix, `{{ownerPKH}}` becomes 40 hex chars (20 bytes).

**PP2 templates** use **dynamic-length encoding**. Parameters go through `PushdataEncoder` or `ScriptNumberEncoder` to get proper Bitcoin pushdata framing:

```java
// PP2LockBuilder — dynamic-length encoding
hex = hex.replace("{{outpoint}}", PushdataEncoder.encode(outpoint));
hex = hex.replace("{{witnessChangeAmount}}", ScriptNumberEncoder.encode(witnessChangeAmount));
```

This distinction exists because PP1 script parameters have fixed sizes (baked prefixes are safe), while PP2 parameters may vary in encoded length.

### Template Loading and Caching

`TemplateLoader.load(String resourcePath)` loads templates from the classpath and caches them in a `ConcurrentHashMap` for thread-safe reuse. Templates are loaded lazily on first access and cached indefinitely.

The `TemplateDescriptor` POJO is deserialized from JSON using Jackson. It uses `@JsonIgnoreProperties(ignoreUnknown = true)` to remain forward-compatible with template fields not used by the Java library (like `parameters`, `description`, `category`, `metadata`).

### Template Generation

Templates are **generated by the canonical Dart implementation** (e.g., `PP1NftScriptGen` in `lib/src/script_gen/pp1_nft_script_gen.dart`). They should **never be hand-edited**. To update a template:

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
- Defensively clone all byte array inputs
- Defensively clone byte arrays on getter access

### Unlock Builders (scriptSig)

All unlock builders extend `UnlockingScriptBuilder` from bitcoin4j and override `getUnlockingScript()`:

1. Dispatch to a private `buildAction()` method based on the action enum
2. Use `ScriptBuilder` to push data items onto the stack in the exact order expected by the lock script
3. Push the action's `opValue` as the **last item** — the lock script uses this as a dispatch selector

Factory method conventions:
- Private constructor, public static factory methods named `forAction()` (e.g., `forMint()`, `forTransfer()`, `forBurn()`)
- Each factory method enforces the correct set of parameters for that action at compile time
- Parameters not needed for an action are passed as `null`/`0` to the private constructor

Signature requirements:
- **ISSUANCE / MINT / CREATE** actions typically do **not** require a signature
- **TRANSFER**, **BURN**, **REDEEM**, and most other actions require `addSignature()` to be called before `getUnlockingScript()` — the method returns an empty script if no signature is present

## Encoding Utilities

### AmountEncoder

`encodeLeUint56(long value)` encodes a fungible token amount as an 8-byte little-endian value with bit 63 clear. Maximum value: 2^55 - 1. Layout: bytes[0..6] = 7 LE value bytes, bytes[7] = (value >> 56) & 0x7F.

Used by `PP1FtLockBuilder` and `PP1RftLockBuilder` for the `{{amount}}` placeholder.

### PushdataEncoder

`encode(byte[] data)` encodes a byte array as a Bitcoin pushdata operation. Returns a hex string of the complete script fragment (length prefix + data). Delegates to bitcoin4j's `ScriptBuilder.data()` for correct Bitcoin pushdata framing.

Used by PP2 lock builders for dynamic-length parameters.

### ScriptNumberEncoder

`encode(long value)` encodes a long value as a Bitcoin script number. Returns a hex string of the complete script fragment (opcode for small numbers, pushdata + LE bytes for larger values). Delegates to bitcoin4j's `ScriptBuilder.number()`.

Used by PP2 lock builders for numeric parameters like `witnessChangeAmount`.

## Cross-Language Compatibility

The Dart `tstokenlib` library is the **canonical/reference implementation**. This Java library must produce **byte-identical** script output for the same inputs.

### Test Vector Validation

`CrossLanguageVectorTest` loads test vectors from `src/test/resources/cross_language_vectors.json`. These vectors are generated by running `dart run tool/export_test_vectors.dart` in the Dart project.

The test class validates:
- All lock builders (MOD_P2PKH, PP1_NFT, PP1_FT, PP2, PP2_FT)
- All unlock builder actions (MOD_P2PKH, PP2 normal/burn, PP2_FT normal/burn, PP1_NFT issuance/transfer/burn, PP1_FT mint/transfer/split/merge/burn)

Any change to template hex or encoding logic must maintain byte-identity with the Dart output.

## Adding a New Token Archetype

To add a new token archetype (e.g., a hypothetical "Composable Token"):

### 1. Create the Template

Generate the template JSON using the Dart script generator and place it in the appropriate subdirectory under `src/main/resources/templates/`.

### 2. Create the Action Enum

Add a new enum in `org.twostack.tstokenlib4j.unlock` listing all supported actions with their `opValue` integers:

```java
public enum ComposableTokenAction {
    COMPOSE(0), TRANSFER(1), DECOMPOSE(2), BURN(3);

    private final int opValue;
    // constructor and getter
}
```

### 3. Create the Lock Builder

Add a new class in `org.twostack.tstokenlib4j.lock` extending `LockingScriptBuilder`:
- Constructor validates and clones all byte array parameters
- `getLockingScript()` loads the template and substitutes parameters
- Use raw hex substitution for PP1-style templates

### 4. Create the Unlock Builder

Add a new class in `org.twostack.tstokenlib4j.unlock` extending `UnlockingScriptBuilder`:
- Private constructor with all possible parameters
- Public static factory methods for each action
- `getUnlockingScript()` dispatches to private build methods
- Push action `opValue` as the last item

### 5. Add Tests

- Add a unit test for the lock builder
- Add a unit test for the unlock builder
- Generate cross-language test vectors from the Dart implementation
- Add entries to `CrossLanguageVectorTest`

### 6. Update Documentation

- Add Javadoc to all new classes
- Update the token type table in README.md
- Update this architecture document
