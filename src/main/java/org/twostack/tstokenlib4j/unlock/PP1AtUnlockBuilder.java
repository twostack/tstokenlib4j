package org.twostack.tstokenlib4j.unlock;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptBuilder;
import org.twostack.bitcoin4j.transaction.UnlockingScriptBuilder;

import java.io.IOException;

/**
 * Builds the unlocking script for a PP1 Appendable Token (AT) locking script.
 *
 * <p>Supported actions:
 * <ul>
 *   <li>{@link AppendableTokenAction#ISSUANCE} -- initial token issuance</li>
 *   <li>{@link AppendableTokenAction#STAMP} -- append metadata to the token</li>
 *   <li>{@link AppendableTokenAction#TRANSFER} -- ownership transfer to a new holder</li>
 *   <li>{@link AppendableTokenAction#REDEEM} -- redeem the token back to the issuer</li>
 *   <li>{@link AppendableTokenAction#BURN} -- permanent destruction of the token</li>
 * </ul>
 *
 * <p>Instances are created through the static factory methods {@link #forIssuance},
 * {@link #forStamp}, {@link #forTransfer}, {@link #forRedeem}, and {@link #forBurn}.
 * The constructor is private.
 *
 * <p>All actions require a signature to be added via
 * {@link #addSignature(TransactionSignature)} before {@link #getUnlockingScript()} will
 * produce a non-empty script.
 *
 * <p>The last item pushed onto the script stack is always the action's opValue integer.
 */
public class PP1AtUnlockBuilder extends UnlockingScriptBuilder {

    private final AppendableTokenAction action;
    private final byte[] preImage;
    private final byte[] witnessFundingTxId;
    private final byte[] witnessPadding;
    private final byte[] pp2Output;
    private final PublicKey ownerPubKey;
    private final byte[] changePKH;
    private final long changeAmount;
    private final byte[] tokenLHS;
    private final byte[] prevTokenTx;
    private final byte[] stampMetadata;

    // Rabin identity fields (ISSUANCE only)
    private byte[] rabinN;
    private byte[] rabinS;
    private int rabinPadding;
    private byte[] identityTxId;
    private byte[] ed25519PubKey;

    private PP1AtUnlockBuilder(
            AppendableTokenAction action,
            byte[] preImage, byte[] witnessFundingTxId, byte[] witnessPadding,
            byte[] pp2Output, PublicKey ownerPubKey,
            byte[] changePKH, long changeAmount,
            byte[] tokenLHS, byte[] prevTokenTx,
            byte[] stampMetadata) {
        this.action = action;
        this.preImage = preImage;
        this.witnessFundingTxId = witnessFundingTxId;
        this.witnessPadding = witnessPadding;
        this.pp2Output = pp2Output;
        this.ownerPubKey = ownerPubKey;
        this.changePKH = changePKH;
        this.changeAmount = changeAmount;
        this.tokenLHS = tokenLHS;
        this.prevTokenTx = prevTokenTx;
        this.stampMetadata = stampMetadata;
    }

    /**
     * Creates a builder for the ISSUANCE action. Requires {@link #addSignature(TransactionSignature)}
     * before {@link #getUnlockingScript()} produces output.
     *
     * @param preImage            sighash preimage of the transaction for OP_PUSH_TX validation
     * @param witnessFundingTxId  transaction ID of the witness funding UTXO
     * @param witnessPadding      padding bytes for witness transaction alignment
     * @param issuerPubKey        public key of the token issuer
     * @return a new builder configured for issuance
     */
    public static PP1AtUnlockBuilder forIssuance(
            byte[] preImage, byte[] witnessFundingTxId, byte[] witnessPadding,
            PublicKey issuerPubKey,
            byte[] rabinN, byte[] rabinS, int rabinPadding,
            byte[] identityTxId, byte[] ed25519PubKey) {
        PP1AtUnlockBuilder b = new PP1AtUnlockBuilder(
                AppendableTokenAction.ISSUANCE,
                preImage, witnessFundingTxId, witnessPadding,
                null, issuerPubKey, null, 0, null, null, null);
        b.rabinN = rabinN;
        b.rabinS = rabinS;
        b.rabinPadding = rabinPadding;
        b.identityTxId = identityTxId;
        b.ed25519PubKey = ed25519PubKey;
        return b;
    }

    /**
     * Creates a builder for the STAMP action. Requires {@link #addSignature(TransactionSignature)}
     * before {@link #getUnlockingScript()} produces output.
     *
     * @param preImage        sighash preimage of the transaction for OP_PUSH_TX validation
     * @param pp2Output       serialized PP2 witness output for output structure verification
     * @param issuerPubKey    public key of the token issuer
     * @param changePKH       20-byte HASH160 for witness change output
     * @param changeAmount    satoshi amount for witness change
     * @param tokenLHS        left-hand side of serialized token output for structure verification
     * @param prevTokenTx     raw bytes of previous token transaction for inductive proof
     * @param witnessPadding  padding bytes for witness transaction alignment
     * @param stampMetadata   metadata bytes to append as a stamp
     * @return a new builder configured for stamping
     */
    public static PP1AtUnlockBuilder forStamp(
            byte[] preImage, byte[] pp2Output, PublicKey issuerPubKey,
            byte[] changePKH, long changeAmount,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] witnessPadding,
            byte[] stampMetadata) {
        return new PP1AtUnlockBuilder(
                AppendableTokenAction.STAMP,
                preImage, null, witnessPadding,
                pp2Output, issuerPubKey, changePKH, changeAmount,
                tokenLHS, prevTokenTx, stampMetadata);
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
    public static PP1AtUnlockBuilder forTransfer(
            byte[] preImage, byte[] pp2Output, PublicKey ownerPubKey,
            byte[] changePKH, long changeAmount,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] witnessPadding) {
        return new PP1AtUnlockBuilder(
                AppendableTokenAction.TRANSFER,
                preImage, null, witnessPadding,
                pp2Output, ownerPubKey, changePKH, changeAmount,
                tokenLHS, prevTokenTx, null);
    }

    /**
     * Creates a builder for the REDEEM action. Requires {@link #addSignature(TransactionSignature)}
     * before {@link #getUnlockingScript()} produces output.
     *
     * @param ownerPubKey public key of the current token owner
     * @return a new builder configured for redemption
     */
    public static PP1AtUnlockBuilder forRedeem(PublicKey ownerPubKey) {
        return new PP1AtUnlockBuilder(
                AppendableTokenAction.REDEEM,
                null, null, null,
                null, ownerPubKey, null, 0, null, null, null);
    }

    /**
     * Creates a builder for the BURN action. Requires {@link #addSignature(TransactionSignature)}
     * before {@link #getUnlockingScript()} produces output.
     *
     * @param ownerPubKey public key of the current token owner
     * @return a new builder configured for burn
     */
    public static PP1AtUnlockBuilder forBurn(PublicKey ownerPubKey) {
        return new PP1AtUnlockBuilder(
                AppendableTokenAction.BURN,
                null, null, null,
                null, ownerPubKey, null, 0, null, null, null);
    }

    /**
     * Builds and returns the unlocking script by dispatching to the appropriate
     * private build method based on the configured {@link AppendableTokenAction}.
     *
     * <p>For all actions, if no signature has been added an empty script is returned.
     * The last item pushed is always the action's opValue integer
     * (ISSUANCE=0, STAMP=1, REDEEM=2, TRANSFER=3, BURN=4).
     *
     * @return the unlocking {@link Script}, or an empty script when prerequisites are not met
     */
    @Override
    public Script getUnlockingScript() {
        switch (action) {
            case ISSUANCE:
                return buildIssuance();
            case STAMP:
                return buildStamp();
            case TRANSFER:
                return buildTransfer();
            case REDEEM:
                return buildRedeem();
            case BURN:
                return buildBurn();
            default:
                return new ScriptBuilder().build();
        }
    }

    private Script buildIssuance() {
        if (getSignatures().isEmpty()) {
            return new ScriptBuilder().build();
        }
        try {
            ScriptBuilder builder = new ScriptBuilder();
            builder.data(preImage);
            builder.data(witnessFundingTxId);
            builder.data(witnessPadding);
            builder.data(ownerPubKey.getPubKeyBytes());
            builder.data(getSignatures().get(0).toTxFormat());
            builder.data(rabinN);
            builder.data(rabinS);
            builder.number(rabinPadding);
            builder.data(identityTxId);
            builder.data(ed25519PubKey);
            builder.number(0);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }

    private Script buildStamp() {
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
            builder.data(stampMetadata);
            builder.number(1);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
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
            builder.number(3);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }

    private Script buildRedeem() {
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

    private Script buildBurn() {
        if (getSignatures().isEmpty()) {
            return new ScriptBuilder().build();
        }
        try {
            ScriptBuilder builder = new ScriptBuilder();
            builder.data(ownerPubKey.getPubKeyBytes());
            builder.data(getSignatures().get(0).toTxFormat());
            builder.number(4);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }
}
