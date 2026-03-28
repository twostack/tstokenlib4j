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
import org.twostack.tstokenlib4j.unlock.*;

import java.math.BigInteger;
import java.util.HashMap;
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
            "at.issue", "at.issueWithWitness", "at.transfer", "at.stamp", "at.stampWithWitness",
            "at.witness", "at.burn", "at.redeem",
            "sm.create", "sm.enroll", "sm.transition", "sm.settle", "sm.timeout", "sm.witness", "sm.burn",
            "rnft.issue", "rnft.transfer", "rnft.witness", "rnft.burn", "rnft.redeem",
            "rft.mint", "rft.transfer", "rft.split", "rft.merge", "rft.witness", "rft.burn", "rft.redeem",
            "funding.provision");

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
                    hexBytes(p, "ownerPKH"), hexBytes(p, "tokenId"),
                    hexBytes(p, "rabinPKH"), toLong(p, "amount")
            ).getLockingScript().getProgram();
            case "pp1_at" -> new PP1AtLockBuilder(
                    hexBytes(p, "ownerPKH"), hexBytes(p, "tokenId"), hexBytes(p, "issuerPKH"),
                    hexBytes(p, "rabinPKH"),
                    toInt(p, "stampCount"), toInt(p, "threshold"), hexBytes(p, "stampsHash")
            ).getLockingScript().getProgram();
            case "pp1_sm" -> new PP1SmLockBuilder(
                    hexBytes(p, "ownerPKH"), hexBytes(p, "tokenId"),
                    hexBytes(p, "merchantPKH"), hexBytes(p, "customerPKH"),
                    hexBytes(p, "rabinPKH"),
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
                    hexBytes(p, "rabinPKH"), toInt(p, "flags"), toLong(p, "amount"),
                    toInt(p, "tokenSupply"), hexBytes(p, "merkleRoot")
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

        // Adapt CallbackTransactionSigner → SigningCallback.
        // The 3-arg overload receives the locking script of the output being spent,
        // resolves the owner address, and forwards it to the signing actor which
        // uses addressToDerivationIndex to derive the correct key.
        SigningCallback signingCallback = new SigningCallback() {
            @Override public byte[] sign(byte[] sighash) { return request.signer().sign(sighash, 0); }
            @Override public byte[] sign(byte[] sighash, int inputIndex, byte[] scriptPubKey) {
                return request.signer().sign(sighash, inputIndex, scriptPubKey);
            }
        };
        PublicKey pubKey = PublicKey.fromHex(request.publicKeyHexes().get(0));

        try {
            // Paired actions build both token TX and witness TX atomically
            if (action.endsWith("WithWitness")) {
                return buildPairedAction(action, params, request, signingCallback, pubKey);
            }

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

    /**
     * Builds a token TX and its witness TX atomically from the same UTXO pool.
     * The token TX uses fundingUtxos[0] for funding. The witness TX uses fundingUtxos[1].
     * PP2 in the token TX commits to fundingUtxos[1] — guaranteed to match because
     * both TXs are built in the same call with the same UTXO reservation.
     */
    private TransactionBuilderResult buildPairedAction(
            String action, Map<String, Object> params, PluginTransactionRequest request,
            SigningCallback signer, PublicKey pubKey) throws Exception {

        TransactionLookup lookup = request.transactionLookup();
        String baseAction = action.replace("WithWitness", "");

        // Determine witness action type
        String witnessAction;
        if (baseAction.equals("at.issue")) {
            witnessAction = "ISSUANCE";
        } else if (baseAction.equals("at.stamp")) {
            witnessAction = "STAMP";
        } else {
            throw new IllegalArgumentException("Paired action not supported: " + action);
        }

        // Build the token TX (uses fundingUtxos[0], commits to fundingUtxos[1] in PP2)
        Transaction tokenTx = dispatchBuild(baseAction, params, request, signer, pubKey);
        String tokenTxid = tokenTx.getTransactionId();
        String tokenRawHex = Utils.HEX.encode(tokenTx.serialize());

        // Build the witness TX using the SAME request (same UTXO pool).
        // The witness TX uses fundingUtxos[1] for funding — the same UTXO
        // that was committed in PP2 during the token TX build.
        Map<String, Object> witnessParams = new HashMap<>(params);
        witnessParams.put("action", "at.witness");
        witnessParams.put("tokenTxRawHex", tokenRawHex);
        witnessParams.put("witnessAction", witnessAction);
        if ("ISSUANCE".equals(witnessAction)) {
            witnessParams.put("parentTokenTxId", Utils.HEX.encode(new byte[32]));

            // Compute Rabin signature now that tokenId is known.
            // The tokenId is the funding TX's txid (= issuance TX's input[0] outpoint txid).
            computeAndSetRabinSignature(witnessParams, tokenTx);
        } else {
            // For stamp witness, the parent token TX is the prev token TX
            witnessParams.put("parentTokenTxId", requireString(params, "prevTokenTxId"));
            if (params.containsKey("prevTokenTxRawHex")) {
                witnessParams.put("parentTokenTxRawHex", params.get("prevTokenTxRawHex"));
            }
        }

        // The witness TX needs to use fundingUtxos[1]. Create a shifted request
        // that presents fundingUtxos[1] as the primary funding UTXO.
        var witnessFundingUtxos = request.fundingUtxos().size() > 1
                ? request.fundingUtxos().subList(1, request.fundingUtxos().size())
                : request.fundingUtxos();
        PluginTransactionRequest witnessRequest = new PluginTransactionRequest(
                witnessFundingUtxos, request.signer(), request.transactionLookup(),
                request.publicKeyHexes(), request.changeAddress(), witnessParams);

        Transaction witnessTx = dispatchBuild("at.witness", witnessParams, witnessRequest, signer, pubKey);
        String witnessTxid = witnessTx.getTransactionId();
        String witnessRawHex = Utils.HEX.encode(witnessTx.serialize());

        long tokenFee = computeFee(tokenTx, params, request);
        long witnessFee = computeFee(witnessTx, witnessParams, witnessRequest);

        return new TransactionBuilderResult(tokenTxid, tokenRawHex, tokenFee,
                witnessTxid, witnessRawHex, witnessFee);
    }

    @Override
    public java.util.List<org.twostack.libspiffy4j.plugin.ProvisionedTransaction> provisionFunding(
            PluginTransactionRequest request) {
        Map<String, Object> params = request.params();
        SigningCallback signer = sighash -> request.signer().sign(sighash, 0);
        PublicKey pubKey = PublicKey.fromHex(request.publicKeyHexes().get(0));

        int fundingVout = resolveFundingVout(params, request);
        Transaction fundingTx = lookupTransaction(
                request.transactionLookup() != null ? request.transactionLookup() : txid -> null,
                params, "fundingTxId", request);
        Address changeAddress = requireAddress(params, "changeAddress", networkAddressType);
        int lifecycleSteps = optionalInt(params, "lifecycleSteps", 1);
        long feeRateSatsPerKb = optionalLong(params, "feeRateSatsPerKb", 100);

        return FundingProvisionBuilder.provision(
                fundingTx, fundingVout, signer, pubKey, signer, pubKey,
                changeAddress, lifecycleSteps, feeRateSatsPerKb);
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
        long feePerKb = optionalLong(params, "feeRateSatsPerKb", 1);

        return switch (action) {
            case "nft.issue" -> {
                int fundingVout = resolveFundingVout(params, request);
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                yield new TokenTool(networkAddressType, null, feePerKb).createTokenIssuanceTxn(
                        fundingTx, fundingVout, signer, pubKey,
                        requireAddress(params, "recipientAddress", networkAddressType),
                        requireHexBytes(params, "witnessFundingTxId"),
                        requireHexBytes(params, "rabinPKH"),
                        requireHexBytes(params, "metadataBytes"));
            }
            case "nft.transfer" -> {
                int fundingVout = resolveFundingVout(params, request);
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction prevWitnessTx = resolveTransaction(lookup, requireString(params, "prevWitnessTxId"));
                Transaction prevTokenTx = resolveTransaction(lookup, requireString(params, "prevTokenTxId"));
                String ownerPubKeyHex = optionalString(params, "ownerPubKeyHex");
                PublicKey ownerPubKey = ownerPubKeyHex != null
                        ? PublicKey.fromHex(ownerPubKeyHex) : pubKey;
                yield new TokenTool(networkAddressType, null, feePerKb).createTokenTransferTxn(
                        prevWitnessTx, prevTokenTx, ownerPubKey,
                        requireAddress(params, "recipientAddress", networkAddressType),
                        fundingTx, fundingVout, signer, pubKey,
                        requireHexBytes(params, "recipientWitnessFundingTxId"),
                        requireHexBytes(params, "tokenId"),
                        requireHexBytes(params, "rabinPKH"));
            }
            case "nft.witness" -> {
                int fundingVout = resolveFundingVout(params, request);
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction tokenTx = resolveTransaction(lookup, requireString(params, "tokenTxId"));
                String parentTokenTxId = requireString(params, "parentTokenTxId");
                byte[] parentTokenTxBytes;
                if (parentTokenTxId.matches("^0+$")) {
                    parentTokenTxBytes = new byte[0]; // issuance — no parent token
                } else {
                    parentTokenTxBytes = Utils.HEX.decode(resolveRawHex(lookup, parentTokenTxId));
                }
                String actionType = optionalString(params, "witnessAction");
                TokenAction tokenAction = "ISSUANCE".equals(actionType)
                        ? TokenAction.ISSUANCE : TokenAction.TRANSFER;
                // Owner pubkey may differ from funding pubkey if at different derivation index
                String ownerPubKeyHex = optionalString(params, "ownerPubKeyHex");
                PublicKey ownerPubKey = ownerPubKeyHex != null
                        ? PublicKey.fromHex(ownerPubKeyHex) : pubKey;
                yield new TokenTool(networkAddressType, null, feePerKb).createWitnessTxn(
                        signer, pubKey, fundingTx, fundingVout, tokenTx, parentTokenTxBytes, ownerPubKey,
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
                yield new TokenTool(networkAddressType, null, feePerKb).createBurnTokenTxn(
                        tokenTx, signer, pubKey, fundingTx, signer, pubKey);
            }
            // ── FT ──
            case "ft.mint" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                yield new FungibleTokenTool(networkAddressType).createFungibleMintTxn(
                        fundingTx, signer, pubKey,
                        requireAddress(params, "recipientAddress", networkAddressType),
                        requireHexBytes(params, "witnessFundingTxId"),
                        requireHexBytes(params, "rabinPubKeyHash"),
                        requireLong(params, "amount"),
                        optionalHexBytes(params, "metadataBytes"));
            }
            case "ft.transfer" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction prevWitnessTx = resolveTransaction(lookup, requireString(params, "prevWitnessTxId"));
                Transaction prevTokenTx = resolveTransaction(lookup, requireString(params, "prevTokenTxId"));
                yield new FungibleTokenTool(networkAddressType).createFungibleTransferTxn(
                        prevWitnessTx, prevTokenTx, pubKey,
                        requireAddress(params, "recipientAddress", networkAddressType),
                        fundingTx, signer, pubKey,
                        requireHexBytes(params, "recipientWitnessFundingTxId"),
                        requireHexBytes(params, "tokenId"),
                        requireLong(params, "amount"),
                        optionalInt(params, "prevTripletBaseIndex", 1));
            }
            case "ft.split" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction prevWitnessTx = resolveTransaction(lookup, requireString(params, "prevWitnessTxId"));
                Transaction prevTokenTx = resolveTransaction(lookup, requireString(params, "prevTokenTxId"));
                yield new FungibleTokenTool(networkAddressType).createFungibleSplitTxn(
                        prevWitnessTx, prevTokenTx, pubKey,
                        requireAddress(params, "recipientAddress", networkAddressType),
                        requireLong(params, "sendAmount"),
                        fundingTx, signer, pubKey,
                        requireHexBytes(params, "recipientWitnessFundingTxId"),
                        requireHexBytes(params, "changeWitnessFundingTxId"),
                        requireHexBytes(params, "tokenId"),
                        requireLong(params, "totalAmount"),
                        optionalInt(params, "prevTripletBaseIndex", 1));
            }
            case "ft.merge" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction prevWitnessTxA = resolveTransaction(lookup, requireString(params, "prevWitnessTxIdA"));
                Transaction prevTokenTxA = resolveTransaction(lookup, requireString(params, "prevTokenTxIdA"));
                Transaction prevWitnessTxB = resolveTransaction(lookup, requireString(params, "prevWitnessTxIdB"));
                Transaction prevTokenTxB = resolveTransaction(lookup, requireString(params, "prevTokenTxIdB"));
                yield new FungibleTokenTool(networkAddressType).createFungibleMergeTxn(
                        prevWitnessTxA, prevTokenTxA, prevWitnessTxB, prevTokenTxB,
                        pubKey, signer, fundingTx, signer, pubKey,
                        requireHexBytes(params, "mergedWitnessFundingTxId"),
                        requireHexBytes(params, "tokenId"),
                        requireLong(params, "totalAmount"),
                        optionalInt(params, "prevTripletBaseIndexA", 1),
                        optionalInt(params, "prevTripletBaseIndexB", 1));
            }
            case "ft.witness" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction tokenTx = resolveTransaction(lookup, requireString(params, "tokenTxId"));
                String parentTokenTxId = requireString(params, "parentTokenTxId");
                byte[] parentTokenTxBytes = Utils.HEX.decode(resolveRawHex(lookup, parentTokenTxId));
                FungibleTokenAction ftAction = FungibleTokenAction.valueOf(
                        requireString(params, "witnessAction"));
                String parentTokenTxIdB = optionalString(params, "parentTokenTxIdB");
                byte[] parentTokenTxBytesB = parentTokenTxIdB != null
                        ? Utils.HEX.decode(resolveRawHex(lookup, parentTokenTxIdB)) : null;
                yield new FungibleTokenTool(networkAddressType).createFungibleWitnessTxn(
                        signer, pubKey, fundingTx, tokenTx, pubKey,
                        requireHexBytes(params, "tokenChangePKH"),
                        ftAction, parentTokenTxBytes,
                        requireInt(params, "parentOutputCount"),
                        optionalInt(params, "tripletBaseIndex", 1),
                        parentTokenTxBytesB,
                        optionalInt(params, "parentOutputCountB", 0),
                        optionalInt(params, "parentPP1FtIndexA", 1),
                        optionalInt(params, "parentPP1FtIndexB", 0),
                        optionalLong(params, "sendAmount", 0),
                        optionalLong(params, "changeAmount", 0),
                        optionalHexBytes(params, "recipientPKH"));
            }
            case "ft.burn" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction tokenTx = resolveTransaction(lookup, requireString(params, "tokenTxId"));
                yield new FungibleTokenTool(networkAddressType).createFungibleBurnTxn(
                        tokenTx, signer, pubKey, fundingTx, signer, pubKey,
                        optionalInt(params, "tripletBaseIndex", 1));
            }

            // ── AT ──
            case "at.issue" -> {
                int fundingVout = resolveFundingVout(params, request);
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                byte[] issuerPKH = pubKey.getPubKeyHash();
                AppendableTokenTool atTool = new AppendableTokenTool(networkAddressType);
                // PP2 embeds the full 36-byte outpoint that will fund the witness TX.
                // Use fundingUtxos[1]'s txid (wire order) + actual vout.
                byte[] witnessFundingOutpoint;
                if (request.fundingUtxos().size() > 1) {
                    var witnessUtxo = request.fundingUtxos().get(1);
                    byte[] witnessTxId = Utils.reverseBytes(Utils.HEX.decode(witnessUtxo.txid()));
                    witnessFundingOutpoint = atTool.getOutpoint(witnessTxId, witnessUtxo.vout());
                } else {
                    byte[] witnessFundingTxId = optionalHexBytes(params, "witnessFundingTxId");
                    if (witnessFundingTxId == null) witnessFundingTxId = new byte[32];
                    witnessFundingOutpoint = atTool.getOutpoint(witnessFundingTxId);
                }
                byte[] witnessChangePKH = pubKey.getPubKeyHash();
                yield atTool.createTokenIssuanceTxn(
                        fundingTx, fundingVout, signer, pubKey,
                        requireAddress(params, "recipientAddress", networkAddressType),
                        witnessFundingOutpoint,
                        witnessChangePKH,
                        issuerPKH,
                        requireHexBytes(params, "rabinPKH"),
                        requireInt(params, "threshold"),
                        optionalHexBytes(params, "metadataBytes"));
            }
            case "at.transfer" -> {
                int fundingVout = resolveFundingVout(params, request);
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction prevWitnessTx = resolveTransaction(lookup, requireString(params, "prevWitnessTxId"));
                Transaction prevTokenTx = resolveTransaction(lookup, requireString(params, "prevTokenTxId"));
                yield new AppendableTokenTool(networkAddressType).createTokenTransferTxn(
                        prevWitnessTx, prevTokenTx, pubKey,
                        requireAddress(params, "recipientAddress", networkAddressType),
                        fundingTx, fundingVout, signer, pubKey,
                        requireHexBytes(params, "recipientWitnessFundingTxId"),
                        requireHexBytes(params, "tokenId"),
                        requireHexBytes(params, "issuerPKH"),
                        requireInt(params, "stampCount"),
                        requireInt(params, "threshold"),
                        requireHexBytes(params, "stampsHash"));
            }
            case "at.stamp" -> {
                int fundingVout = resolveFundingVout(params, request);
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction prevWitnessTx = resolveTransaction(lookup, requireString(params, "prevWitnessTxId"));
                Transaction prevTokenTx = resolveTransaction(lookup, requireString(params, "prevTokenTxId"));
                // Extract ownerPKH from the parent PP1 output (carried forward, not recomputed).
                // Stamp signer is the issuer — derive issuerPKH from the coordinator's pubKey.
                byte[] parentPP1 = prevTokenTx.getOutputs().get(1).getScript().getProgram();
                byte[] ownerPKH = new byte[20];
                System.arraycopy(parentPP1, 1, ownerPKH, 0, 20);
                // PP2 commits to the full 36-byte witness funding outpoint.
                AppendableTokenTool stampAtTool = new AppendableTokenTool(networkAddressType);
                byte[] stampWitnessFundingOutpoint;
                if (request.fundingUtxos().size() > 1) {
                    var witnessUtxo = request.fundingUtxos().get(1);
                    byte[] witnessTxId = Utils.reverseBytes(Utils.HEX.decode(witnessUtxo.txid()));
                    stampWitnessFundingOutpoint = stampAtTool.getOutpoint(witnessTxId, witnessUtxo.vout());
                } else {
                    byte[] stampWitnessFundingTxId = optionalHexBytes(params, "issuerWitnessFundingTxId");
                    if (stampWitnessFundingTxId == null) stampWitnessFundingTxId = new byte[32];
                    stampWitnessFundingOutpoint = stampAtTool.getOutpoint(stampWitnessFundingTxId);
                }
                yield stampAtTool.createTokenStampTxn(
                        prevWitnessTx, prevTokenTx, pubKey,
                        fundingTx, fundingVout, signer, pubKey,
                        stampWitnessFundingOutpoint,
                        requireHexBytes(params, "stampMetadata"),
                        ownerPKH,
                        requireHexBytes(params, "tokenId"),
                        pubKey.getPubKeyHash(),
                        requireInt(params, "parentStampCount"),
                        requireInt(params, "threshold"),
                        requireHexBytes(params, "parentStampsHash"));
            }
            case "at.witness" -> {
                int fundingVout = resolveFundingVout(params, request);
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                // Accept raw hex directly to avoid read-model race after issuance/stamp
                String tokenTxRawHex = optionalString(params, "tokenTxRawHex");
                Transaction tokenTx = tokenTxRawHex != null
                        ? Transaction.fromHex(tokenTxRawHex)
                        : resolveTransaction(lookup, requireString(params, "tokenTxId"));
                String parentTokenTxId = requireString(params, "parentTokenTxId");
                byte[] parentTokenTxBytes;
                if ("0000000000000000000000000000000000000000000000000000000000000000".equals(parentTokenTxId)) {
                    parentTokenTxBytes = new byte[0]; // issuance has no parent
                } else {
                    String parentRawHex = optionalString(params, "parentTokenTxRawHex");
                    parentTokenTxBytes = parentRawHex != null
                            ? Utils.HEX.decode(parentRawHex)
                            : Utils.HEX.decode(resolveRawHex(lookup, parentTokenTxId));
                }
                AppendableTokenAction atAction = AppendableTokenAction.valueOf(
                        requireString(params, "witnessAction"));
                // tokenChangePKH must match the witness output lock (which uses pubKey),
                // so derive it from the coordinator's pubKey rather than external params.
                yield new AppendableTokenTool(networkAddressType).createWitnessTxn(
                        signer, pubKey, fundingTx, fundingVout, tokenTx, parentTokenTxBytes, pubKey,
                        pubKey.getPubKeyHash(),
                        atAction,
                        optionalHexBytes(params, "stampMetadata"),
                        optionalHexBytes(params, "rabinN"),
                        optionalHexBytes(params, "rabinS"),
                        optionalInt(params, "rabinPadding", 0),
                        optionalHexBytes(params, "identityTxId"),
                        optionalHexBytes(params, "ed25519PubKey"));
            }
            case "at.burn" -> {
                int fundingVout = resolveFundingVout(params, request);
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction tokenTx = resolveTransaction(lookup, requireString(params, "tokenTxId"));
                yield new AppendableTokenTool(networkAddressType).createBurnTokenTxn(
                        tokenTx, signer, pubKey, fundingTx, fundingVout, signer, pubKey);
            }
            case "at.redeem" -> {
                int fundingVout = resolveFundingVout(params, request);
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction tokenTx = resolveTransaction(lookup, requireString(params, "tokenTxId"));
                yield new AppendableTokenTool(networkAddressType).createRedeemTokenTxn(
                        tokenTx, signer, pubKey, fundingTx, fundingVout, signer, pubKey);
            }

            // ── SM ──
            case "sm.create" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                yield new StateMachineTool(networkAddressType).createTokenIssuanceTxn(
                        fundingTx, signer, pubKey,
                        requireAddress(params, "merchantAddress", networkAddressType),
                        requireHexBytes(params, "merchantPKH"),
                        requireHexBytes(params, "customerPKH"),
                        requireInt(params, "transitionBitmask"),
                        requireInt(params, "timeoutDelta"),
                        requireHexBytes(params, "witnessFundingTxId"),
                        requireHexBytes(params, "rabinPKH"),
                        optionalHexBytes(params, "metadataBytes"));
            }
            case "sm.enroll" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction prevWitnessTx = resolveTransaction(lookup, requireString(params, "prevWitnessTxId"));
                Transaction prevTokenTx = resolveTransaction(lookup, requireString(params, "prevTokenTxId"));
                yield new StateMachineTool(networkAddressType).createEnrollTxn(
                        prevWitnessTx, prevTokenTx, pubKey,
                        fundingTx, signer, pubKey,
                        requireHexBytes(params, "witnessFundingTxId"),
                        optionalHexBytes(params, "eventData"),
                        requireHexBytes(params, "tokenId"),
                        requireHexBytes(params, "merchantPKH"),
                        requireHexBytes(params, "customerPKH"),
                        requireInt(params, "state"),
                        requireInt(params, "milestoneCount"),
                        requireHexBytes(params, "commitmentHash"),
                        requireInt(params, "transitionBitmask"),
                        requireInt(params, "timeoutDelta"));
            }
            case "sm.transition" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction prevWitnessTx = resolveTransaction(lookup, requireString(params, "prevWitnessTxId"));
                Transaction prevTokenTx = resolveTransaction(lookup, requireString(params, "prevTokenTxId"));
                yield new StateMachineTool(networkAddressType).createTransitionTxn(
                        prevWitnessTx, prevTokenTx, pubKey,
                        fundingTx, signer, pubKey,
                        requireHexBytes(params, "witnessFundingTxId"),
                        requireInt(params, "newState"),
                        requireHexBytes(params, "newOwnerPKH"),
                        requireBoolean(params, "incrementMilestone"),
                        optionalHexBytes(params, "eventData"),
                        requireHexBytes(params, "tokenId"),
                        requireHexBytes(params, "merchantPKH"),
                        requireHexBytes(params, "customerPKH"),
                        requireInt(params, "state"),
                        requireInt(params, "milestoneCount"),
                        requireHexBytes(params, "commitmentHash"),
                        requireInt(params, "transitionBitmask"),
                        requireInt(params, "timeoutDelta"));
            }
            case "sm.settle" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction prevWitnessTx = resolveTransaction(lookup, requireString(params, "prevWitnessTxId"));
                Transaction prevTokenTx = resolveTransaction(lookup, requireString(params, "prevTokenTxId"));
                yield new StateMachineTool(networkAddressType).createSettleTxn(
                        prevWitnessTx, prevTokenTx, pubKey,
                        fundingTx, signer, pubKey,
                        requireHexBytes(params, "witnessFundingTxId"),
                        BigInteger.valueOf(requireLong(params, "custRewardAmount")),
                        BigInteger.valueOf(requireLong(params, "merchPayAmount")),
                        optionalHexBytes(params, "eventData"),
                        requireHexBytes(params, "tokenId"),
                        requireHexBytes(params, "merchantPKH"),
                        requireHexBytes(params, "customerPKH"),
                        requireInt(params, "state"),
                        requireInt(params, "milestoneCount"),
                        requireHexBytes(params, "commitmentHash"),
                        requireInt(params, "transitionBitmask"),
                        requireInt(params, "timeoutDelta"));
            }
            case "sm.timeout" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction prevWitnessTx = resolveTransaction(lookup, requireString(params, "prevWitnessTxId"));
                Transaction prevTokenTx = resolveTransaction(lookup, requireString(params, "prevTokenTxId"));
                yield new StateMachineTool(networkAddressType).createTimeoutTxn(
                        prevWitnessTx, prevTokenTx, pubKey,
                        fundingTx, signer, pubKey,
                        requireHexBytes(params, "witnessFundingTxId"),
                        BigInteger.valueOf(requireLong(params, "refundAmount")),
                        requireInt(params, "nLockTime"),
                        requireHexBytes(params, "tokenId"),
                        requireHexBytes(params, "merchantPKH"),
                        requireHexBytes(params, "customerPKH"),
                        requireInt(params, "state"),
                        requireInt(params, "milestoneCount"),
                        requireHexBytes(params, "commitmentHash"),
                        requireInt(params, "transitionBitmask"),
                        requireInt(params, "timeoutDelta"));
            }
            case "sm.witness" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction tokenTx = resolveTransaction(lookup, requireString(params, "tokenTxId"));
                String parentTokenTxId = requireString(params, "parentTokenTxId");
                byte[] parentTokenTxBytes = Utils.HEX.decode(resolveRawHex(lookup, parentTokenTxId));
                StateMachineAction smAction = StateMachineAction.valueOf(
                        requireString(params, "witnessAction"));
                yield new StateMachineTool(networkAddressType).createWitnessTxn(
                        signer, pubKey, fundingTx, tokenTx, parentTokenTxBytes, pubKey,
                        requireHexBytes(params, "tokenChangePKH"),
                        smAction,
                        optionalHexBytes(params, "eventData"),
                        optionalLong(params, "custRewardAmount", 0),
                        optionalLong(params, "merchPayAmount", 0),
                        optionalLong(params, "refundAmount", 0),
                        optionalInt(params, "nLockTime", 0),
                        optionalInt(params, "pp1OutputIndex", 1),
                        optionalInt(params, "pp2OutputIndex", 2));
            }
            case "sm.burn" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction tokenTx = resolveTransaction(lookup, requireString(params, "tokenTxId"));
                yield new StateMachineTool(networkAddressType).createBurnTokenTxn(
                        tokenTx, signer, pubKey, fundingTx, signer, pubKey,
                        optionalInt(params, "pp1OutputIndex", 1),
                        optionalInt(params, "pp2OutputIndex", 2),
                        optionalInt(params, "pp3OutputIndex", 3));
            }

            // ── RNFT ──
            case "rnft.issue" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                yield new RestrictedTokenTool(networkAddressType).createTokenIssuanceTxn(
                        fundingTx, signer, pubKey,
                        requireAddress(params, "recipientAddress", networkAddressType),
                        requireHexBytes(params, "witnessFundingTxId"),
                        requireHexBytes(params, "rabinPKH"),
                        requireInt(params, "flags"),
                        optionalHexBytes(params, "metadataBytes"));
            }
            case "rnft.transfer" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction prevWitnessTx = resolveTransaction(lookup, requireString(params, "prevWitnessTxId"));
                Transaction prevTokenTx = resolveTransaction(lookup, requireString(params, "prevTokenTxId"));
                yield new RestrictedTokenTool(networkAddressType).createTokenTransferTxn(
                        prevWitnessTx, prevTokenTx, pubKey,
                        requireAddress(params, "recipientAddress", networkAddressType),
                        fundingTx, signer, pubKey,
                        requireHexBytes(params, "recipientWitnessFundingTxId"),
                        requireHexBytes(params, "tokenId"),
                        requireHexBytes(params, "rabinPKH"),
                        requireInt(params, "flags"));
            }
            case "rnft.witness" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction tokenTx = resolveTransaction(lookup, requireString(params, "tokenTxId"));
                String parentTokenTxId = requireString(params, "parentTokenTxId");
                byte[] parentTokenTxBytes = Utils.HEX.decode(resolveRawHex(lookup, parentTokenTxId));
                RestrictedTokenAction rnftAction = RestrictedTokenAction.valueOf(
                        requireString(params, "witnessAction"));
                yield new RestrictedTokenTool(networkAddressType).createWitnessTxn(
                        signer, pubKey, fundingTx, tokenTx, parentTokenTxBytes, pubKey,
                        requireHexBytes(params, "tokenChangePKH"),
                        rnftAction,
                        optionalHexBytes(params, "rabinN"),
                        optionalHexBytes(params, "rabinS"),
                        optionalLong(params, "rabinPadding", 0),
                        optionalHexBytes(params, "identityTxId"),
                        optionalHexBytes(params, "ed25519PubKey"));
            }
            case "rnft.burn" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction tokenTx = resolveTransaction(lookup, requireString(params, "tokenTxId"));
                yield new RestrictedTokenTool(networkAddressType).createBurnTokenTxn(
                        tokenTx, signer, pubKey, fundingTx, signer, pubKey);
            }
            case "rnft.redeem" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction tokenTx = resolveTransaction(lookup, requireString(params, "tokenTxId"));
                yield new RestrictedTokenTool(networkAddressType).createRedeemTokenTxn(
                        tokenTx, signer, pubKey, fundingTx, signer, pubKey);
            }

            // ── RFT ──
            case "rft.mint" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                yield new RestrictedFungibleTokenTool(networkAddressType).createFungibleMintTxn(
                        fundingTx, signer, pubKey,
                        requireAddress(params, "recipientAddress", networkAddressType),
                        requireHexBytes(params, "witnessFundingTxId"),
                        requireHexBytes(params, "rabinPKH"),
                        requireInt(params, "flags"),
                        requireLong(params, "amount"),
                        optionalInt(params, "tokenSupply", 0),
                        optionalHexBytes(params, "merkleRoot") != null ? optionalHexBytes(params, "merkleRoot") : new byte[32],
                        optionalHexBytes(params, "metadataBytes"));
            }
            case "rft.transfer" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction prevWitnessTx = resolveTransaction(lookup, requireString(params, "prevWitnessTxId"));
                Transaction prevTokenTx = resolveTransaction(lookup, requireString(params, "prevTokenTxId"));
                yield new RestrictedFungibleTokenTool(networkAddressType).createRftTransferTxn(
                        prevWitnessTx, prevTokenTx, pubKey,
                        requireAddress(params, "recipientAddress", networkAddressType),
                        fundingTx, signer, pubKey,
                        requireHexBytes(params, "recipientWitnessFundingTxId"),
                        requireHexBytes(params, "tokenId"),
                        requireHexBytes(params, "rabinPKH"),
                        requireInt(params, "flags"),
                        requireLong(params, "amount"),
                        optionalInt(params, "tokenSupply", 0),
                        optionalHexBytes(params, "merkleRoot") != null ? optionalHexBytes(params, "merkleRoot") : new byte[32],
                        optionalInt(params, "prevTripletBaseIndex", 1));
            }
            case "rft.split" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction prevWitnessTx = resolveTransaction(lookup, requireString(params, "prevWitnessTxId"));
                Transaction prevTokenTx = resolveTransaction(lookup, requireString(params, "prevTokenTxId"));
                yield new RestrictedFungibleTokenTool(networkAddressType).createRftSplitTxn(
                        prevWitnessTx, prevTokenTx, pubKey,
                        requireAddress(params, "recipientAddress", networkAddressType),
                        requireLong(params, "sendAmount"),
                        fundingTx, signer, pubKey,
                        requireHexBytes(params, "recipientWitnessFundingTxId"),
                        requireHexBytes(params, "changeWitnessFundingTxId"),
                        requireHexBytes(params, "tokenId"),
                        requireHexBytes(params, "rabinPKH"),
                        requireInt(params, "flags"),
                        requireLong(params, "totalAmount"),
                        optionalInt(params, "tokenSupply", 0),
                        optionalHexBytes(params, "merkleRoot") != null ? optionalHexBytes(params, "merkleRoot") : new byte[32],
                        optionalInt(params, "prevTripletBaseIndex", 1));
            }
            case "rft.merge" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction prevWitnessTxA = resolveTransaction(lookup, requireString(params, "prevWitnessTxIdA"));
                Transaction prevTokenTxA = resolveTransaction(lookup, requireString(params, "prevTokenTxIdA"));
                Transaction prevWitnessTxB = resolveTransaction(lookup, requireString(params, "prevWitnessTxIdB"));
                Transaction prevTokenTxB = resolveTransaction(lookup, requireString(params, "prevTokenTxIdB"));
                yield new RestrictedFungibleTokenTool(networkAddressType).createRftMergeTxn(
                        prevWitnessTxA, prevTokenTxA, prevWitnessTxB, prevTokenTxB,
                        pubKey, signer, fundingTx, signer, pubKey,
                        requireHexBytes(params, "mergedWitnessFundingTxId"),
                        requireHexBytes(params, "tokenId"),
                        requireHexBytes(params, "rabinPKH"),
                        requireInt(params, "flags"),
                        requireLong(params, "totalAmount"),
                        optionalInt(params, "tokenSupply", 0),
                        optionalHexBytes(params, "merkleRoot") != null ? optionalHexBytes(params, "merkleRoot") : new byte[32],
                        optionalInt(params, "prevTripletBaseIndexA", 1),
                        optionalInt(params, "prevTripletBaseIndexB", 1));
            }
            case "rft.witness" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction tokenTx = resolveTransaction(lookup, requireString(params, "tokenTxId"));
                String parentTokenTxId = requireString(params, "parentTokenTxId");
                byte[] parentTokenTxBytes = Utils.HEX.decode(resolveRawHex(lookup, parentTokenTxId));
                RestrictedFungibleTokenAction rftAction = RestrictedFungibleTokenAction.valueOf(
                        requireString(params, "witnessAction"));
                String parentTokenTxIdB = optionalString(params, "parentTokenTxIdB");
                byte[] parentTokenTxBytesB = parentTokenTxIdB != null
                        ? Utils.HEX.decode(resolveRawHex(lookup, parentTokenTxIdB)) : null;
                yield new RestrictedFungibleTokenTool(networkAddressType).createRftWitnessTxn(
                        signer, pubKey, fundingTx, tokenTx, pubKey,
                        requireHexBytes(params, "tokenChangePKH"),
                        rftAction, parentTokenTxBytes,
                        requireInt(params, "parentOutputCount"),
                        optionalInt(params, "tripletBaseIndex", 1),
                        optionalInt(params, "parentPP1FtIndex", 1),
                        optionalHexBytes(params, "rabinN"),
                        optionalHexBytes(params, "rabinS"),
                        optionalInt(params, "rabinPadding", 0),
                        optionalHexBytes(params, "identityTxId"),
                        optionalHexBytes(params, "ed25519PubKey"),
                        parentTokenTxBytesB,
                        optionalInt(params, "parentOutputCountB", 0),
                        optionalInt(params, "parentPP1FtIndexB", 0),
                        optionalLong(params, "recipientAmount", 0),
                        optionalLong(params, "tokenChangeAmount", 0),
                        optionalHexBytes(params, "recipientPKH"),
                        optionalHexBytes(params, "merkleProof"),
                        optionalHexBytes(params, "merkleSides"));
            }
            case "rft.burn" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction tokenTx = resolveTransaction(lookup, requireString(params, "tokenTxId"));
                yield new RestrictedFungibleTokenTool(networkAddressType).createBurnTokenTxn(
                        tokenTx, signer, pubKey, fundingTx, signer, pubKey);
            }
            case "rft.redeem" -> {
                Transaction fundingTx = lookupTransaction(lookup, params, "fundingTxId", request);
                Transaction tokenTx = resolveTransaction(lookup, requireString(params, "tokenTxId"));
                yield new RestrictedFungibleTokenTool(networkAddressType).createRedeemTokenTxn(
                        tokenTx, signer, pubKey, fundingTx, signer, pubKey);
            }

            default -> throw new IllegalArgumentException("Action '" + action + "' not implemented");
        };
    }

    // ── Helpers ──

    /**
     * Resolve a funding transaction. First tries the params map for a txid,
     * then falls back to the first available funding UTXO.
     */
    /**
     * Resolve the funding output index. Uses the first funding UTXO's vout.
     */
    private int resolveFundingVout(Map<String, Object> params, PluginTransactionRequest request) {
        // Explicit override takes priority (e.g., witness must use vout=1)
        Integer explicit = optionalInt(params, "fundingVout", -1);
        if (explicit >= 0) return explicit;
        if (!request.fundingUtxos().isEmpty()) {
            return request.fundingUtxos().get(0).vout();
        }
        return 1; // legacy default
    }

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
        if (action.equals("funding.prepare")) {
            return -1; // variable: 1 change + N witness slots
        }
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

    /**
     * Computes the Rabin identity signature using the tokenId derived from the
     * issuance TX (tokenId = funding TX txid = issuance TX input[0] outpoint txid).
     * Requires rabinP, rabinQ, identityTxId, and ed25519PubKey in the params.
     */
    private void computeAndSetRabinSignature(Map<String, Object> params, Transaction tokenTx) {
        String rabinPHex = optionalString(params, "rabinP");
        String rabinQHex = optionalString(params, "rabinQ");
        if (rabinPHex == null || rabinQHex == null) return;

        java.math.BigInteger p = new java.math.BigInteger(rabinPHex, 16);
        java.math.BigInteger q = new java.math.BigInteger(rabinQHex, 16);

        // Extract tokenId from the PP1 script at offset [22:54] (display byte order).
        // This is the authoritative tokenId embedded in the locking script.
        byte[] pp1Script = tokenTx.getOutputs().get(1).getScript().getProgram();
        byte[] tokenId = new byte[32];
        System.arraycopy(pp1Script, 22, tokenId, 0, 32);

        byte[] identityTxId = optionalHexBytes(params, "identityTxId");
        if (identityTxId == null) identityTxId = new byte[32];
        byte[] ed25519PubKey = optionalHexBytes(params, "ed25519PubKey");
        if (ed25519PubKey == null) ed25519PubKey = new byte[32];

        // message = identityTxId || ed25519PubKey || tokenId
        byte[] message = new byte[identityTxId.length + ed25519PubKey.length + tokenId.length];
        System.arraycopy(identityTxId, 0, message, 0, identityTxId.length);
        System.arraycopy(ed25519PubKey, 0, message, identityTxId.length, ed25519PubKey.length);
        System.arraycopy(tokenId, 0, message, identityTxId.length + ed25519PubKey.length, tokenId.length);

        byte[] hash = org.twostack.bitcoin4j.Sha256Hash.hash(message);
        java.math.BigInteger messageHash = org.twostack.tstokenlib4j.crypto.Rabin.hashBytesToScriptInt(hash);
        org.twostack.tstokenlib4j.crypto.RabinSignature sig =
                org.twostack.tstokenlib4j.crypto.Rabin.sign(messageHash, p, q);

        params.put("rabinS", Utils.HEX.encode(
                org.twostack.tstokenlib4j.crypto.Rabin.bigIntToScriptNum(sig.s())));
        params.put("rabinPadding", sig.padding());

        // Remove private key material from params
        params.remove("rabinP");
        params.remove("rabinQ");
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
