package org.twostack.tstokenlib4j.plugin;

import org.twostack.bitcoin4j.Address;
import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.params.NetworkAddressType;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptInfo;
import org.twostack.bitcoin4j.script.ScriptTemplateRegistry;
import org.twostack.bitcoin4j.transaction.Transaction;
import org.twostack.libspiffy4j.plugin.*;

import org.twostack.tstokenlib4j.lock.*;
import org.twostack.tstokenlib4j.parser.*;
import org.twostack.tstokenlib4j.transaction.*;
import org.twostack.tstokenlib4j.unlock.TokenAction;

import java.util.List;
import java.util.Map;

import static org.twostack.tstokenlib4j.plugin.PluginParamExtractor.*;

/**
 * TSL1 token protocol plugin for libspiffy4j.
 *
 * <p>Implements {@link TransactionBuilderPlugin} (which extends {@link ScriptPlugin}),
 * bridging libspiffy4j's wallet plugin system to tstokenlib4j's parser and Tool
 * infrastructure. Enables the wallet coordinator to:
 * <ul>
 *   <li>Identify PP1 token scripts in transaction outputs</li>
 *   <li>Extract token metadata (ownerAddress, tokenId, amount, etc.) for UTXO enrichment</li>
 *   <li>Build complete TSL1 transactions via the Tool classes</li>
 *   <li>Validate transaction structure (output counts per action)</li>
 * </ul>
 *
 * <p>This class uses libspiffy4j as a {@code compileOnly} dependency. At runtime,
 * the host application provides libspiffy4j and registers this plugin:
 * <pre>{@code
 * var plugin = new Tsl1TransactionBuilderPlugin(NetworkAddressType.MAIN_PKH);
 * pluginRegistry.register(plugin);
 * }</pre>
 */
public class Tsl1TransactionBuilderPlugin implements TransactionBuilderPlugin {

    private static final String PLUGIN_ID = "tsl1";
    private static final String DISPLAY_NAME = "TSL1 Token Protocol";

    private static final List<String> SCRIPT_TYPES = List.of(
            "pp1_nft", "pp1_ft", "pp1_at", "pp1_sm", "pp1_rnft", "pp1_rft");

    private static final List<String> SUPPORTED_ACTIONS = List.of(
            "nft.issue", "nft.transfer", "nft.witness", "nft.burn",
            "ft.mint", "ft.transfer", "ft.split", "ft.merge", "ft.witness", "ft.burn",
            "at.issue", "at.transfer", "at.stamp", "at.witness", "at.burn", "at.redeem",
            "sm.create", "sm.enroll", "sm.transition", "sm.settle", "sm.timeout", "sm.witness", "sm.burn",
            "rnft.issue", "rnft.transfer", "rnft.witness", "rnft.burn", "rnft.redeem",
            "rft.mint", "rft.transfer", "rft.split", "rft.merge", "rft.witness", "rft.burn", "rft.redeem");

    private final NetworkAddressType networkAddressType;

    public Tsl1TransactionBuilderPlugin(NetworkAddressType networkAddressType) {
        this.networkAddressType = networkAddressType;
        PP1TemplateRegistrar.registerAll();
    }

    // ── ScriptPlugin ──

    @Override
    public String pluginId() {
        return PLUGIN_ID;
    }

    @Override
    public String displayName() {
        return DISPLAY_NAME;
    }

    @Override
    public List<String> scriptTypes() {
        return SCRIPT_TYPES;
    }

    @Override
    public String identifyScript(byte[] scriptPubKey) {
        try {
            ScriptInfo info = ScriptTemplateRegistry.getInstance()
                    .extractScriptInfo(new Script(scriptPubKey));
            if (info == null) return null;
            return scriptTypeFromInfo(info);
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public Map<String, Object> extractMetadata(byte[] scriptPubKey) {
        try {
            ScriptInfo info = ScriptTemplateRegistry.getInstance()
                    .extractScriptInfo(new Script(scriptPubKey));
            if (info == null) return Map.of();
            return ScriptInfoMetadataMapper.toMetadata(info, networkAddressType);
        } catch (Exception e) {
            return Map.of();
        }
    }

    @Override
    public byte[] createLockingScript(PluginLockSpec spec) {
        Map<String, Object> p = spec.params();
        return switch (spec.scriptType()) {
            case "pp1_nft" -> new PP1NftLockBuilder(
                    hexBytes(p, "ownerPKH"), hexBytes(p, "tokenId"), hexBytes(p, "rabinPKH")
            ).getLockingScript().getProgram();
            case "pp1_ft" -> new PP1FtLockBuilder(
                    hexBytes(p, "ownerPKH"), hexBytes(p, "tokenId"), toLong(p, "amount")
            ).getLockingScript().getProgram();
            case "pp1_at" -> new PP1AtLockBuilder(
                    hexBytes(p, "ownerPKH"), hexBytes(p, "tokenId"), hexBytes(p, "issuerPKH"),
                    toInt(p, "stampCount"), toInt(p, "threshold"), hexBytes(p, "stampsHash")
            ).getLockingScript().getProgram();
            case "pp1_sm" -> new PP1SmLockBuilder(
                    hexBytes(p, "ownerPKH"), hexBytes(p, "tokenId"),
                    hexBytes(p, "merchantPKH"), hexBytes(p, "customerPKH"),
                    toInt(p, "currentState"), toInt(p, "milestoneCount"),
                    hexBytes(p, "commitmentHash"), toInt(p, "transitionBitmask"),
                    toInt(p, "timeoutDelta")
            ).getLockingScript().getProgram();
            case "pp1_rnft" -> new PP1RnftLockBuilder(
                    hexBytes(p, "ownerPKH"), hexBytes(p, "tokenId"),
                    hexBytes(p, "rabinPKH"), toInt(p, "flags")
            ).getLockingScript().getProgram();
            case "pp1_rft" -> new PP1RftLockBuilder(
                    hexBytes(p, "ownerPKH"), hexBytes(p, "tokenId"),
                    hexBytes(p, "rabinPKH"), toInt(p, "flags"), toLong(p, "amount")
            ).getLockingScript().getProgram();
            default -> throw new IllegalArgumentException("Unknown script type: " + spec.scriptType());
        };
    }

    @Override
    public byte[] createUnlockingScript(PluginUnlockSpec spec) {
        throw new UnsupportedOperationException(
                "TSL1 unlock scripts are built by the Tool classes during transaction construction, "
                + "not standalone. Use buildTransaction() instead.");
    }

    // ── TransactionBuilderPlugin ──

    @Override
    public List<String> supportedActions() {
        return SUPPORTED_ACTIONS;
    }

    @Override
    public TransactionBuilderResult buildTransaction(PluginTransactionRequest request) {
        Map<String, Object> params = request.params();
        String action = requireString(params, "action");

        if (!SUPPORTED_ACTIONS.contains(action)) {
            throw new IllegalArgumentException(
                    "Unsupported action '" + action + "'. Supported: " + SUPPORTED_ACTIONS);
        }

        // Adapt CallbackTransactionSigner → SigningCallback
        SigningCallback signingCallback = sighash -> request.signer().sign(sighash, 0);
        PublicKey pubKey = PublicKey.fromHex(request.publicKeyHexes().get(0));

        try {
            Transaction tx = dispatchBuild(action, params, request, signingCallback, pubKey);
            String txid = tx.getTransactionId();
            String rawHex = Utils.HEX.encode(tx.serialize());
            long feeSats = computeFee(tx, params, request);
            return new TransactionBuilderResult(txid, rawHex, feeSats);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Failed to build transaction for action '" + action + "': " + e.getMessage(), e);
        }
    }

    @Override
    public boolean validateTransactionStructure(byte[] rawTx, String action) {
        try {
            Transaction tx = Transaction.fromHex(Utils.HEX.encode(rawTx));
            int outputCount = tx.getOutputs().size();
            int expected = expectedOutputCount(action);
            return expected == -1 || outputCount == expected;
        } catch (Exception e) {
            return false;
        }
    }

    // ── Dispatch ──

    private Transaction dispatchBuild(String action, Map<String, Object> params,
                                       PluginTransactionRequest request,
                                       SigningCallback signer, PublicKey pubKey) throws Exception {
        TransactionLookup lookup = request.transactionLookup();

        return switch (action) {
            case "nft.issue" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                yield new TokenTool(networkAddressType).createTokenIssuanceTxn(
                        fundingTx, signer, pubKey,
                        requireAddress(params, "recipientAddress", networkAddressType),
                        requireHexBytes(params, "witnessFundingTxId"),
                        requireHexBytes(params, "rabinPKH"),
                        requireHexBytes(params, "metadataBytes"));
            }
            case "nft.transfer" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction prevWitnessTx = resolveTransaction(lookup, requireString(params, "prevWitnessTxId"));
                Transaction prevTokenTx = resolveTransaction(lookup, requireString(params, "prevTokenTxId"));
                yield new TokenTool(networkAddressType).createTokenTransferTxn(
                        prevWitnessTx, prevTokenTx, pubKey,
                        requireAddress(params, "recipientAddress", networkAddressType),
                        fundingTx, signer, pubKey,
                        requireHexBytes(params, "recipientWitnessFundingTxId"),
                        requireHexBytes(params, "tokenId"),
                        requireHexBytes(params, "rabinPKH"));
            }
            case "nft.witness" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction tokenTx = resolveTransaction(lookup, requireString(params, "tokenTxId"));
                String parentTokenTxId = requireString(params, "parentTokenTxId");
                byte[] parentTokenTxBytes = Utils.HEX.decode(
                        resolveRawHex(lookup, parentTokenTxId));
                String actionType = optionalString(params, "witnessAction");
                TokenAction tokenAction = "ISSUANCE".equals(actionType)
                        ? TokenAction.ISSUANCE : TokenAction.TRANSFER;
                yield new TokenTool(networkAddressType).createWitnessTxn(
                        signer, pubKey, fundingTx, tokenTx, parentTokenTxBytes, pubKey,
                        requireHexBytes(params, "tokenChangePKH"), tokenAction,
                        optionalHexBytes(params, "rabinN"),
                        optionalHexBytes(params, "rabinS"),
                        optionalLong(params, "rabinPadding", 0),
                        optionalHexBytes(params, "identityTxId"),
                        optionalHexBytes(params, "ed25519PubKey"));
            }
            case "nft.burn" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction tokenTx = resolveTransaction(lookup, requireString(params, "tokenTxId"));
                yield new TokenTool(networkAddressType).createBurnTokenTxn(
                        tokenTx, signer, pubKey, fundingTx, signer, pubKey);
            }
            // TODO: ft.*, at.*, sm.*, rnft.*, rft.* actions follow the same pattern.
            // Each dispatches to the corresponding Tool class method with params resolved
            // from the map and transactions resolved via lookup.
            default -> throw new IllegalArgumentException("Action '" + action + "' not yet implemented");
        };
    }

    // ── Helpers ──

    /**
     * Resolve a funding transaction. First tries the params map for a txid,
     * then falls back to the first available funding UTXO.
     */
    private Transaction lookupTransaction(TransactionLookup lookup, Map<String, Object> params,
                                           String paramKey, PluginTransactionRequest request) {
        String txid = optionalString(params, paramKey);
        if (txid != null) {
            return resolveTransaction(lookup, txid);
        }
        // Fall back to first funding UTXO
        if (request.fundingUtxos().isEmpty()) {
            throw new IllegalArgumentException("No funding UTXOs available and no '" + paramKey + "' in params");
        }
        return resolveTransaction(lookup, request.fundingUtxos().get(0).txid());
    }

    private Transaction resolveTransaction(TransactionLookup lookup, String txid) {
        if (lookup == null) {
            throw new IllegalStateException(
                    "TransactionLookup not available — cannot resolve txid: " + txid);
        }
        String rawHex = lookup.lookupRawHex(txid);
        if (rawHex == null) {
            throw new IllegalArgumentException("Transaction not found in wallet: " + txid);
        }
        return Transaction.fromHex(rawHex);
    }

    private String resolveRawHex(TransactionLookup lookup, String txid) {
        if (lookup == null) {
            throw new IllegalStateException("TransactionLookup not available");
        }
        String rawHex = lookup.lookupRawHex(txid);
        if (rawHex == null) {
            throw new IllegalArgumentException("Transaction not found in wallet: " + txid);
        }
        return rawHex;
    }

    private long computeFee(Transaction tx, Map<String, Object> params,
                             PluginTransactionRequest request) {
        // Fee = sum(input values) - sum(output values)
        // For now, return 0 as a placeholder — the coordinator can compute this
        // from the UTXO values if needed
        return 0;
    }

    private int expectedOutputCount(String action) {
        if (action.endsWith(".witness") || action.endsWith(".burn") || action.endsWith(".redeem")) {
            return 1;
        }
        if (action.equals("ft.split") || action.equals("rft.split")) {
            return 8;
        }
        if (action.equals("sm.settle")) {
            return 7;
        }
        if (action.equals("sm.timeout")) {
            return 6;
        }
        // Standard 5-output: issue, transfer, mint, enroll, transition, stamp
        return 5;
    }

    private static String scriptTypeFromInfo(ScriptInfo info) {
        return switch (info) {
            case PP1NftScriptInfo ignored -> "pp1_nft";
            case PP1FtScriptInfo ignored -> "pp1_ft";
            case PP1AtScriptInfo ignored -> "pp1_at";
            case PP1SmScriptInfo ignored -> "pp1_sm";
            case PP1RnftScriptInfo ignored -> "pp1_rnft";
            case PP1RftScriptInfo ignored -> "pp1_rft";
            default -> null;
        };
    }

    private static byte[] hexBytes(Map<String, Object> p, String key) {
        Object val = p.get(key);
        if (val == null) throw new IllegalArgumentException("Missing param: " + key);
        return Utils.HEX.decode(val.toString());
    }

    private static long toLong(Map<String, Object> p, String key) {
        Object val = p.get(key);
        if (val == null) throw new IllegalArgumentException("Missing param: " + key);
        return val instanceof Number n ? n.longValue() : Long.parseLong(val.toString());
    }

    private static int toInt(Map<String, Object> p, String key) {
        Object val = p.get(key);
        if (val == null) throw new IllegalArgumentException("Missing param: " + key);
        return val instanceof Number n ? n.intValue() : Integer.parseInt(val.toString());
    }
}
