package org.twostack.tstokenlib4j.unlock;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptBuilder;
import org.twostack.bitcoin4j.transaction.TransactionSignature;
import org.twostack.bitcoin4j.transaction.UnlockingScriptBuilder;

import java.io.IOException;

/**
 * Builds the unlocking script for a PP1 Non-Fungible Token (NFT) locking script.
 *
 * <p>Supported actions:
 * <ul>
 *   <li>{@link TokenAction#ISSUANCE} -- initial token issuance with Rabin identity binding</li>
 *   <li>{@link TokenAction#TRANSFER} -- ownership transfer to a new holder</li>
 *   <li>{@link TokenAction#BURN} -- permanent destruction of the token</li>
 * </ul>
 *
 * <p>Instances are created through the static factory methods {@link #forIssuance},
 * {@link #forTransfer}, and {@link #forBurn}. The constructor is private.
 *
 * <p>The TRANSFER and BURN actions require a signature to be added via
 * {@link #addSignature(TransactionSignature)} before {@link #getUnlockingScript()} will
 * produce a non-empty script. The ISSUANCE action does not require a signature.
 *
 * <p>The last item pushed onto the script stack is always the action's opValue integer.
 */
public class PP1NftUnlockBuilder extends UnlockingScriptBuilder {

    private final TokenAction action;
    private final byte[] preImage;
    private final byte[] witnessFundingTxId;
    private final byte[] witnessPadding;
    private final byte[] rabinN;
    private final byte[] rabinS;
    private final long rabinPadding;
    private final byte[] identityTxId;
    private final byte[] ed25519PubKey;
    private final byte[] pp2Output;
    private final PublicKey ownerPubKey;
    private final byte[] changePKH;
    private final long changeAmount;
    private final byte[] tokenLHS;
    private final byte[] prevTokenTx;

    private PP1NftUnlockBuilder(
            TokenAction action,
            byte[] preImage, byte[] witnessFundingTxId, byte[] witnessPadding,
            byte[] rabinN, byte[] rabinS, long rabinPadding,
            byte[] identityTxId, byte[] ed25519PubKey,
            byte[] pp2Output, PublicKey ownerPubKey,
            byte[] changePKH, long changeAmount,
            byte[] tokenLHS, byte[] prevTokenTx) {
        this.action = action;
        this.preImage = preImage;
        this.witnessFundingTxId = witnessFundingTxId;
        this.witnessPadding = witnessPadding;
        this.rabinN = rabinN;
        this.rabinS = rabinS;
        this.rabinPadding = rabinPadding;
        this.identityTxId = identityTxId;
        this.ed25519PubKey = ed25519PubKey;
        this.pp2Output = pp2Output;
        this.ownerPubKey = ownerPubKey;
        this.changePKH = changePKH;
        this.changeAmount = changeAmount;
        this.tokenLHS = tokenLHS;
        this.prevTokenTx = prevTokenTx;
    }

    /**
     * Creates a builder for the ISSUANCE action. No signature is required.
     *
     * @param preImage            sighash preimage of the transaction for OP_PUSH_TX validation
     * @param witnessFundingTxId  transaction ID of the witness funding UTXO
     * @param witnessPadding      padding bytes for witness transaction alignment
     * @param rabinN              Rabin signature public key N component
     * @param rabinS              Rabin signature S component
     * @param rabinPadding        padding value for Rabin signature verification
     * @param identityTxId        transaction ID anchoring the token's identity
     * @param ed25519PubKey       Ed25519 public key for identity verification
     * @return a new builder configured for issuance
     */
    public static PP1NftUnlockBuilder forIssuance(
            byte[] preImage, byte[] witnessFundingTxId, byte[] witnessPadding,
            byte[] rabinN, byte[] rabinS, long rabinPadding,
            byte[] identityTxId, byte[] ed25519PubKey) {
        return new PP1NftUnlockBuilder(
                TokenAction.ISSUANCE,
                preImage, witnessFundingTxId, witnessPadding,
                rabinN, rabinS, rabinPadding,
                identityTxId, ed25519PubKey,
                null, null, null, 0, null, null);
    }

    /**
     * Creates a builder for the TRANSFER action. Requires {@link #addSignature(TransactionSignature)}
     * before {@link #getUnlockingScript()} produces output.
     *
     * @param preImage        sighash preimage of the transaction for OP_PUSH_TX validation
     * @param pp2Output       serialized PP2 witness output for output structure verification
     * @param ownerPubKey     public key of the current token owner
     * @param changePKH       20-byte HASH160 for witness change output
     * @param changeAmount    satoshi amount for witness change
     * @param tokenLHS        left-hand side of serialized token output for structure verification
     * @param prevTokenTx     raw bytes of previous token transaction for inductive proof
     * @param witnessPadding  padding bytes for witness transaction alignment
     * @return a new builder configured for transfer
     */
    public static PP1NftUnlockBuilder forTransfer(
            byte[] preImage, byte[] pp2Output, PublicKey ownerPubKey,
            byte[] changePKH, long changeAmount,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] witnessPadding) {
        return new PP1NftUnlockBuilder(
                TokenAction.TRANSFER,
                preImage, null, witnessPadding,
                null, null, 0,
                null, null,
                pp2Output, ownerPubKey,
                changePKH, changeAmount,
                tokenLHS, prevTokenTx);
    }

    /**
     * Creates a builder for the BURN action. Requires {@link #addSignature(TransactionSignature)}
     * before {@link #getUnlockingScript()} produces output.
     *
     * @param ownerPubKey public key of the current token owner
     * @return a new builder configured for burn
     */
    public static PP1NftUnlockBuilder forBurn(PublicKey ownerPubKey) {
        return new PP1NftUnlockBuilder(
                TokenAction.BURN,
                null, null, null,
                null, null, 0,
                null, null,
                null, ownerPubKey,
                null, 0, null, null);
    }

    /**
     * Builds and returns the unlocking script by dispatching to the appropriate
     * private build method based on the configured {@link TokenAction}.
     *
     * <p>For TRANSFER and BURN, if no signature has been added an empty script is returned.
     * The last item pushed is always the action's opValue integer (ISSUANCE=0, TRANSFER=1, BURN=2).
     *
     * @return the unlocking {@link Script}, or an empty script when prerequisites are not met
     */
    @Override
    public Script getUnlockingScript() {
        switch (action) {
            case ISSUANCE:
                return buildIssuance();
            case TRANSFER:
                return buildTransfer();
            case BURN:
                return buildBurn();
            default:
                return new ScriptBuilder().build();
        }
    }

    private Script buildIssuance() {
        ScriptBuilder builder = new ScriptBuilder();
        builder.data(preImage);
        builder.data(witnessFundingTxId);
        builder.data(witnessPadding);
        builder.data(rabinN);
        builder.data(rabinS);
        builder.number(rabinPadding);
        builder.data(identityTxId);
        builder.data(ed25519PubKey);
        builder.number(0);
        return builder.build();
    }

    private Script buildTransfer() {
        if (getSignatures().isEmpty()) {
            return new ScriptBuilder().build();
        }
        try {
            ScriptBuilder builder = new ScriptBuilder();
            builder.data(preImage);
            builder.data(pp2Output);
            builder.data(ownerPubKey.getPubKeyBytes());
            builder.data(changePKH);
            builder.number(changeAmount);
            builder.data(getSignatures().get(0).toTxFormat());
            builder.data(tokenLHS);
            builder.data(prevTokenTx);
            builder.data(witnessPadding);
            builder.number(1);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }

    private Script buildBurn() {
        if (getSignatures().isEmpty()) {
            return new ScriptBuilder().build();
        }
        try {
            ScriptBuilder builder = new ScriptBuilder();
            builder.data(ownerPubKey.getPubKeyBytes());
            builder.data(getSignatures().get(0).toTxFormat());
            builder.number(2);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }
}
