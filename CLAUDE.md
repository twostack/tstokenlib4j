# tstokenlib4j

Java library for building complete TSL1 token transactions per the [TSL1 specification](https://github.com/twostack/tsl1).

## Build & Test

```bash
./gradlew build        # compile + test
./gradlew test         # tests only
./gradlew javadoc      # generate Javadoc
./gradlew publishToMavenLocal  # install to ~/.m2
```

Requires `org.twostack:bitcoin4j:1.7.0` in mavenLocal.

## Usage

The primary API consists of six **Tool** classes in the `transaction` package. Each Tool
assembles complete multi-output token transactions for a specific token archetype:

```java
// Example: Issue an NFT
TokenTool tool = new TokenTool(NetworkAddressType.TEST_PKH);
Transaction issuanceTx = tool.createTokenIssuanceTxn(
        fundingTx, signer, recipientAddress,
        witnessFundingTxId, rabinPubKeyHash, metadataBytes);

// Example: Mint a fungible token
FungibleTokenTool ftTool = new FungibleTokenTool(NetworkAddressType.TEST_PKH);
Transaction mintTx = ftTool.createFungibleMintTxn(
        fundingTx, signer, recipientAddress,
        witnessFundingTxId, 1000, metadataBytes);

// Example: Create a witness proof
Transaction witnessTx = tool.createWitnessTxn(
        signer, fundingTx, tokenTx, parentTxBytes,
        ownerPubkey, changePKH, TokenAction.ISSUANCE,
        rabinN, rabinS, rabinPadding, identityTxId, ed25519PubKey);
```

### Tool Classes

| Tool Class | Archetype | Operations |
|---|---|---|
| `TokenTool` | NFT | issue, transfer, witness, burn |
| `FungibleTokenTool` | FT | mint, transfer, split, merge, witness, burn |
| `RestrictedTokenTool` | RNFT | issue, transfer, witness, redeem, burn |
| `RestrictedFungibleTokenTool` | RFT | mint, transfer, split, merge, witness, redeem, burn |
| `AppendableTokenTool` | AT | issue, stamp, transfer, witness, redeem, burn |
| `StateMachineTool` | SM | create, enroll, transition, settle, timeout, witness, dual-witness, burn |

Each Tool handles:
- Multi-output transaction assembly (5-output standard, 7–8 for settle/split)
- Sighash preimage computation for each proof output
- Two-pass witness transaction building (padding recalculation)
- Metadata forwarding across transfers
- Balance conservation for splits/merges

### Transaction Output Layouts

**Standard (5 outputs)** — issuance, transfer, enroll, transition:
```
Output[0]: Change (P2PKH to owner)
Output[1]: PP1 variant (token state lock, 1 sat)
Output[2]: PP2 variant (witness bridge, 1 sat)
Output[3]: PP3/PartialWitness (SHA256 verifier, 1 sat)
Output[4]: Metadata (OP_RETURN, 0 sats)
```

**FT Split (8 outputs)**:
```
Output[0]: Change
Output[1–3]: Recipient triplet (PP1_FT, PP2-FT, PP3-FT)
Output[4–6]: Change triplet (PP1_FT, PP2-FT, PP3-FT)
Output[7]: Metadata
```

**SM Settle (7 outputs)**: Change, CustomerReward, MerchantPayment, PP1_SM, PP2, PP3, Metadata

**SM Timeout (6 outputs)**: Change, MerchantRefund, PP1_SM, PP2, PP3, Metadata

**Witness (1 output)**: ModP2PKH locked to current owner

## Project Structure

```
src/main/java/org/twostack/tstokenlib4j/
├── transaction/  # Tool classes — primary API for transaction assembly
│   ├── TokenTool, FungibleTokenTool, RestrictedTokenTool
│   ├── RestrictedFungibleTokenTool, AppendableTokenTool, StateMachineTool
│   ├── TransactionUtils          — TX serialization helpers (getTxLHS, calculatePaddingBytes)
│   └── PartialSha256             — block-at-a-time SHA256 for partial hash proofs
├── encoding/     # AmountEncoder, PushdataEncoder, ScriptNumberEncoder
├── lock/         # 12 locking script (scriptPubKey) builders
├── unlock/       # 11 unlocking script (scriptSig) builders + 6 action enums
├── parser/       # PP1TokenScriptParser — extracts ownerPKH/tokenId from PP1* scripts
├── crypto/       # Rabin signature utilities (sign, verify, key generation)
└── template/     # TemplateLoader + TemplateDescriptor — JSON template loading/caching

src/main/resources/templates/
├── ft/           # Fungible token templates (pp1_ft, pp1_rft, pp2_ft, pp3_ft_witness)
├── nft/          # NFT templates (pp1_nft, pp1_rnft, pp1_at, pp2, pp3_witness)
├── sm/           # State machine template (pp1_sm)
└── utility/      # Modified P2PKH template (mod_p2pkh)
```

## Naming Conventions

- **PP1*** — Plugpoint 1: token logic scripts with inductive proof validation. Contains ownership, tokenId, and archetype-specific validation.
- **PP2*** — Plugpoint 2: witness scripts that "plug into" token transactions. Anchors to a specific UTXO outpoint.
- **PP3** / **PartialWitness*** — Plugpoint 3: partial witness scripts for witness funding inputs.
- **\*Ft** — Fungible token variant
- **\*Nft** — Non-fungible token variant
- **\*Rft** — Restricted fungible token variant
- **\*Rnft** — Restricted non-fungible token variant
- **\*Sm** — State machine variant
- **\*At** — Appendable token variant

## Key Patterns

### Tool Classes (transaction package)
- Constructor takes `NetworkAddressType` and optional `BigInteger defaultFee` (defaults to 135 satoshis)
- All transaction-building methods return `Transaction` and throw `TransactionException, IOException, SigHashException, SignatureDecodeException`
- Two-pass witness building: first pass computes sighash preimage, second pass recalculates SHA256 block-alignment padding
- `getOutpoint(byte[] txId, int outputIndex)` produces 36-byte outpoints (txid + LE index)
- Metadata forwarding: issuance creates via `MetadataLockBuilder`, transfers carry forward via `DefaultLockBuilder`

### Lock Builders
- All extend `org.twostack.bitcoin4j.transaction.LockingScriptBuilder`
- Override `getLockingScript()` → loads a JSON template via `TemplateLoader.load()`, substitutes `{{placeholder}}` values, returns `Script`
- PP1 templates use **raw hex substitution** — pushdata prefixes are baked into the template hex
- PP2 templates use **PushdataEncoder/ScriptNumberEncoder** for dynamic-length fields
- Exception: `MetadataLockBuilder` builds script directly via `ScriptBuilder` (no template)
- All byte array fields are defensively cloned on input and output
- Constructors validate byte array lengths and throw `IllegalArgumentException`

### Unlock Builders
- All extend `org.twostack.bitcoin4j.transaction.UnlockingScriptBuilder`
- **Private constructors** with **static factory methods** named `forAction()` (e.g., `forMint()`, `forTransfer()`, `forBurn()`)
- Override `getUnlockingScript()` → dispatches to private `buildAction()` method based on the action enum
- The **last item pushed** in every unlock script is the action's `opValue` integer, used by the lock script as a dispatch selector
- Most actions (except MINT/CREATE/ISSUANCE) require `addSignature()` to be called before `getUnlockingScript()` produces output

### Action Enums
- Each token archetype has a corresponding enum: `TokenAction`, `FungibleTokenAction`, `RestrictedTokenAction`, `RestrictedFungibleTokenAction`, `StateMachineAction`, `AppendableTokenAction`
- Each enum value carries an `opValue` (or `value`) integer matching the script dispatch number

## Testing

- JUnit 4.13.1 + AssertJ
- `CrossLanguageVectorTest` validates **byte-identical** output against the canonical Dart implementation
- Test vectors loaded from `src/test/resources/cross_language_vectors.json`
- Individual unit tests for encoding, lock builders, and unlock builders

## Dependencies

- **API**: `org.twostack:bitcoin4j:1.7.0` (via mavenLocal)
- **Implementation**: `com.fasterxml.jackson.core:jackson-databind:2.15.3`
- **Test**: `junit:junit:4.13.1`, `org.assertj:assertj-core:3.19.0`
