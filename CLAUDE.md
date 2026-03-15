# tstokenlib4j

Java library for building and unlocking Bitcoin token scripts per the [TSL1 specification](https://github.com/twostack/tsl1).

## Build & Test

```bash
./gradlew build        # compile + test
./gradlew test         # tests only
./gradlew javadoc      # generate Javadoc
./gradlew publishToMavenLocal  # install to ~/.m2
```

Requires `org.twostack:bitcoin4j:1.7.0` in mavenLocal.

## Project Structure

```
src/main/java/org/twostack/tstokenlib4j/
├── encoding/     # AmountEncoder, PushdataEncoder, ScriptNumberEncoder
├── lock/         # 12 locking script (scriptPubKey) builders
├── unlock/       # 11 unlocking script (scriptSig) builders + 6 action enums
├── parser/       # PP1TokenScriptParser — extracts ownerPKH/tokenId from PP1* scripts
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
