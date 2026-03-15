package org.twostack.tstokenlib4j.unlock;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptBuilder;
import org.twostack.bitcoin4j.transaction.UnlockingScriptBuilder;

import java.io.IOException;

/**
 * Builds the unlocking script for a PP1 State Machine (SM) token locking script.
 *
 * <p>Supported actions:
 * <ul>
 *   <li>{@link StateMachineAction#CREATE} -- initial state machine creation</li>
 *   <li>{@link StateMachineAction#ENROLL} -- enroll a participant into the state machine</li>
 *   <li>{@link StateMachineAction#CONFIRM} -- confirm a state transition (dual-signature with customer)</li>
 *   <li>{@link StateMachineAction#CONVERT} -- convert the state machine state (dual-signature with customer)</li>
 *   <li>{@link StateMachineAction#SETTLE} -- settle the state machine with reward and payment amounts</li>
 *   <li>{@link StateMachineAction#TIMEOUT} -- timeout the state machine and issue a refund</li>
 *   <li>{@link StateMachineAction#BURN} -- permanent destruction of the token</li>
 * </ul>
 *
 * <p>Instances are created through the static factory methods {@link #forCreate},
 * {@link #forEnroll}, {@link #forConfirm}, {@link #forConvert}, {@link #forSettle},
 * {@link #forTimeout}, and {@link #forBurn}. The constructor is private.
 *
 * <p>All actions except CREATE require a signature to be added via
 * {@link #addSignature(TransactionSignature)} before {@link #getUnlockingScript()} will
 * produce a non-empty script. The CREATE action does not require a signature.
 *
 * <p>The last item pushed onto the script stack is always the action's opValue integer.
 */
public class PP1SmUnlockBuilder extends UnlockingScriptBuilder {

    private final StateMachineAction action;
    private final byte[] preImage;
    private final byte[] witnessFundingTxId;
    private final byte[] witnessPadding;
    private final byte[] pp2Output;
    private final PublicKey merchantPubKey;
    private final byte[] changePKH;
    private final long changeAmount;
    private final byte[] tokenLHS;
    private final byte[] prevTokenTx;
    private final byte[] eventData;

    // CONFIRM/CONVERT dual-sig extras
    private final PublicKey customerPubKey;
    private final byte[] customerSigBytes;

    // SETTLE extras
    private final long custRewardAmount;
    private final long merchPayAmount;

    // TIMEOUT extras
    private final long refundAmount;

    private PP1SmUnlockBuilder(
            StateMachineAction action,
            byte[] preImage, byte[] witnessFundingTxId, byte[] witnessPadding,
            byte[] pp2Output, PublicKey merchantPubKey,
            byte[] changePKH, long changeAmount,
            byte[] tokenLHS, byte[] prevTokenTx,
            byte[] eventData,
            PublicKey customerPubKey, byte[] customerSigBytes,
            long custRewardAmount, long merchPayAmount,
            long refundAmount) {
        this.action = action;
        this.preImage = preImage;
        this.witnessFundingTxId = witnessFundingTxId;
        this.witnessPadding = witnessPadding;
        this.pp2Output = pp2Output;
        this.merchantPubKey = merchantPubKey;
        this.changePKH = changePKH;
        this.changeAmount = changeAmount;
        this.tokenLHS = tokenLHS;
        this.prevTokenTx = prevTokenTx;
        this.eventData = eventData;
        this.customerPubKey = customerPubKey;
        this.customerSigBytes = customerSigBytes;
        this.custRewardAmount = custRewardAmount;
        this.merchPayAmount = merchPayAmount;
        this.refundAmount = refundAmount;
    }

    /**
     * Creates a builder for the CREATE action. No signature is required.
     *
     * @param preImage            sighash preimage of the transaction for OP_PUSH_TX validation
     * @param witnessFundingTxId  transaction ID of the witness funding UTXO
     * @param witnessPadding      padding bytes for witness transaction alignment
     * @return a new builder configured for state machine creation
     */
    public static PP1SmUnlockBuilder forCreate(
            byte[] preImage, byte[] witnessFundingTxId, byte[] witnessPadding) {
        return new PP1SmUnlockBuilder(
                StateMachineAction.CREATE,
                preImage, witnessFundingTxId, witnessPadding,
                null, null, null, 0, null, null,
                null, null, null, 0, 0, 0);
    }

    /**
     * Creates a builder for the ENROLL action. Requires {@link #addSignature(TransactionSignature)}
     * before {@link #getUnlockingScript()} produces output.
     *
     * @param preImage        sighash preimage of the transaction for OP_PUSH_TX validation
     * @param pp2Output       serialized PP2 witness output for output structure verification
     * @param merchantPubKey  public key of the merchant (state machine owner)
     * @param changePKH       20-byte HASH160 for witness change output
     * @param changeAmount    satoshi amount for witness change
     * @param eventData       event data bytes for state machine transitions
     * @param tokenLHS        left-hand side of serialized token output for structure verification
     * @param prevTokenTx     raw bytes of previous token transaction for inductive proof
     * @param witnessPadding  padding bytes for witness transaction alignment
     * @return a new builder configured for enrollment
     */
    public static PP1SmUnlockBuilder forEnroll(
            byte[] preImage, byte[] pp2Output, PublicKey merchantPubKey,
            byte[] changePKH, long changeAmount,
            byte[] eventData,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] witnessPadding) {
        return new PP1SmUnlockBuilder(
                StateMachineAction.ENROLL,
                preImage, null, witnessPadding,
                pp2Output, merchantPubKey, changePKH, changeAmount,
                tokenLHS, prevTokenTx,
                eventData, null, null, 0, 0, 0);
    }

    /**
     * Creates a builder for the CONFIRM action. Requires {@link #addSignature(TransactionSignature)}
     * before {@link #getUnlockingScript()} produces output. This is a dual-signature action
     * requiring both the merchant's signature (via addSignature) and the customer's signature bytes.
     *
     * @param preImage          sighash preimage of the transaction for OP_PUSH_TX validation
     * @param pp2Output         serialized PP2 witness output for output structure verification
     * @param merchantPubKey    public key of the merchant (state machine owner)
     * @param changePKH         20-byte HASH160 for witness change output
     * @param changeAmount      satoshi amount for witness change
     * @param customerPubKey    customer's public key for dual-signature verification
     * @param customerSigBytes  customer's signature bytes for dual-signature verification
     * @param eventData         event data bytes for state machine transitions
     * @param tokenLHS          left-hand side of serialized token output for structure verification
     * @param prevTokenTx       raw bytes of previous token transaction for inductive proof
     * @param witnessPadding    padding bytes for witness transaction alignment
     * @return a new builder configured for confirmation
     */
    public static PP1SmUnlockBuilder forConfirm(
            byte[] preImage, byte[] pp2Output, PublicKey merchantPubKey,
            byte[] changePKH, long changeAmount,
            PublicKey customerPubKey, byte[] customerSigBytes,
            byte[] eventData,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] witnessPadding) {
        return new PP1SmUnlockBuilder(
                StateMachineAction.CONFIRM,
                preImage, null, witnessPadding,
                pp2Output, merchantPubKey, changePKH, changeAmount,
                tokenLHS, prevTokenTx,
                eventData, customerPubKey, customerSigBytes, 0, 0, 0);
    }

    /**
     * Creates a builder for the CONVERT action. Requires {@link #addSignature(TransactionSignature)}
     * before {@link #getUnlockingScript()} produces output. This is a dual-signature action
     * requiring both the merchant's signature (via addSignature) and the customer's signature bytes.
     *
     * @param preImage          sighash preimage of the transaction for OP_PUSH_TX validation
     * @param pp2Output         serialized PP2 witness output for output structure verification
     * @param merchantPubKey    public key of the merchant (state machine owner)
     * @param changePKH         20-byte HASH160 for witness change output
     * @param changeAmount      satoshi amount for witness change
     * @param customerPubKey    customer's public key for dual-signature verification
     * @param customerSigBytes  customer's signature bytes for dual-signature verification
     * @param eventData         event data bytes for state machine transitions
     * @param tokenLHS          left-hand side of serialized token output for structure verification
     * @param prevTokenTx       raw bytes of previous token transaction for inductive proof
     * @param witnessPadding    padding bytes for witness transaction alignment
     * @return a new builder configured for conversion
     */
    public static PP1SmUnlockBuilder forConvert(
            byte[] preImage, byte[] pp2Output, PublicKey merchantPubKey,
            byte[] changePKH, long changeAmount,
            PublicKey customerPubKey, byte[] customerSigBytes,
            byte[] eventData,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] witnessPadding) {
        return new PP1SmUnlockBuilder(
                StateMachineAction.CONVERT,
                preImage, null, witnessPadding,
                pp2Output, merchantPubKey, changePKH, changeAmount,
                tokenLHS, prevTokenTx,
                eventData, customerPubKey, customerSigBytes, 0, 0, 0);
    }

    /**
     * Creates a builder for the SETTLE action. Requires {@link #addSignature(TransactionSignature)}
     * before {@link #getUnlockingScript()} produces output.
     *
     * @param preImage          sighash preimage of the transaction for OP_PUSH_TX validation
     * @param pp2Output         serialized PP2 witness output for output structure verification
     * @param merchantPubKey    public key of the merchant (state machine owner)
     * @param changePKH         20-byte HASH160 for witness change output
     * @param changeAmount      satoshi amount for witness change
     * @param custRewardAmount  satoshi amount rewarded to the customer on settlement
     * @param merchPayAmount    satoshi amount paid to the merchant on settlement
     * @param eventData         event data bytes for state machine transitions
     * @param tokenLHS          left-hand side of serialized token output for structure verification
     * @param prevTokenTx       raw bytes of previous token transaction for inductive proof
     * @param witnessPadding    padding bytes for witness transaction alignment
     * @return a new builder configured for settlement
     */
    public static PP1SmUnlockBuilder forSettle(
            byte[] preImage, byte[] pp2Output, PublicKey merchantPubKey,
            byte[] changePKH, long changeAmount,
            long custRewardAmount, long merchPayAmount,
            byte[] eventData,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] witnessPadding) {
        return new PP1SmUnlockBuilder(
                StateMachineAction.SETTLE,
                preImage, null, witnessPadding,
                pp2Output, merchantPubKey, changePKH, changeAmount,
                tokenLHS, prevTokenTx,
                eventData, null, null, custRewardAmount, merchPayAmount, 0);
    }

    /**
     * Creates a builder for the TIMEOUT action. Requires {@link #addSignature(TransactionSignature)}
     * before {@link #getUnlockingScript()} produces output.
     *
     * @param preImage        sighash preimage of the transaction for OP_PUSH_TX validation
     * @param pp2Output       serialized PP2 witness output for output structure verification
     * @param merchantPubKey  public key of the merchant (state machine owner)
     * @param changePKH       20-byte HASH160 for witness change output
     * @param changeAmount    satoshi amount for witness change
     * @param refundAmount    satoshi amount to refund on timeout
     * @param tokenLHS        left-hand side of serialized token output for structure verification
     * @param prevTokenTx     raw bytes of previous token transaction for inductive proof
     * @param witnessPadding  padding bytes for witness transaction alignment
     * @return a new builder configured for timeout
     */
    public static PP1SmUnlockBuilder forTimeout(
            byte[] preImage, byte[] pp2Output, PublicKey merchantPubKey,
            byte[] changePKH, long changeAmount,
            long refundAmount,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] witnessPadding) {
        return new PP1SmUnlockBuilder(
                StateMachineAction.TIMEOUT,
                preImage, null, witnessPadding,
                pp2Output, merchantPubKey, changePKH, changeAmount,
                tokenLHS, prevTokenTx,
                null, null, null, 0, 0, refundAmount);
    }

    /**
     * Creates a builder for the BURN action. Requires {@link #addSignature(TransactionSignature)}
     * before {@link #getUnlockingScript()} produces output.
     *
     * @param merchantPubKey public key of the merchant (state machine owner)
     * @return a new builder configured for burn
     */
    public static PP1SmUnlockBuilder forBurn(PublicKey merchantPubKey) {
        return new PP1SmUnlockBuilder(
                StateMachineAction.BURN,
                null, null, null,
                null, merchantPubKey, null, 0, null, null,
                null, null, null, 0, 0, 0);
    }

    /**
     * Builds and returns the unlocking script by dispatching to the appropriate
     * private build method based on the configured {@link StateMachineAction}.
     *
     * <p>For all actions except CREATE, if no signature has been added an empty script
     * is returned. The last item pushed is always the action's opValue integer
     * (CREATE=0, ENROLL=1, CONFIRM=2, CONVERT=3, SETTLE=4, TIMEOUT=5, BURN=6).
     *
     * @return the unlocking {@link Script}, or an empty script when prerequisites are not met
     */
    @Override
    public Script getUnlockingScript() {
        switch (action) {
            case CREATE:
                return buildCreate();
            case ENROLL:
                return buildEnroll();
            case CONFIRM:
                return buildConfirm();
            case CONVERT:
                return buildConvert();
            case SETTLE:
                return buildSettle();
            case TIMEOUT:
                return buildTimeout();
            case BURN:
                return buildBurn();
            default:
                return new ScriptBuilder().build();
        }
    }

    private Script buildCreate() {
        ScriptBuilder builder = new ScriptBuilder();
        builder.data(preImage);
        builder.data(witnessFundingTxId);
        builder.data(witnessPadding);
        builder.number(0);
        return builder.build();
    }

    private Script buildEnroll() {
        if (getSignatures().isEmpty()) {
            return new ScriptBuilder().build();
        }
        try {
            ScriptBuilder builder = new ScriptBuilder();
            builder.data(preImage);
            builder.data(pp2Output);
            builder.data(merchantPubKey.getPubKeyBytes());
            builder.data(changePKH);
            builder.number(changeAmount);
            builder.data(getSignatures().get(0).toTxFormat());
            builder.data(eventData);
            builder.data(tokenLHS);
            builder.data(prevTokenTx);
            builder.data(witnessPadding);
            builder.number(1);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }

    private Script buildConfirm() {
        if (getSignatures().isEmpty()) {
            return new ScriptBuilder().build();
        }
        try {
            ScriptBuilder builder = new ScriptBuilder();
            builder.data(preImage);
            builder.data(pp2Output);
            builder.data(merchantPubKey.getPubKeyBytes());
            builder.data(changePKH);
            builder.number(changeAmount);
            builder.data(getSignatures().get(0).toTxFormat());
            builder.data(customerPubKey.getPubKeyBytes());
            builder.data(customerSigBytes);
            builder.data(eventData);
            builder.data(tokenLHS);
            builder.data(prevTokenTx);
            builder.data(witnessPadding);
            builder.number(2);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }

    private Script buildConvert() {
        if (getSignatures().isEmpty()) {
            return new ScriptBuilder().build();
        }
        try {
            ScriptBuilder builder = new ScriptBuilder();
            builder.data(preImage);
            builder.data(pp2Output);
            builder.data(merchantPubKey.getPubKeyBytes());
            builder.data(changePKH);
            builder.number(changeAmount);
            builder.data(getSignatures().get(0).toTxFormat());
            builder.data(customerPubKey.getPubKeyBytes());
            builder.data(customerSigBytes);
            builder.data(eventData);
            builder.data(tokenLHS);
            builder.data(prevTokenTx);
            builder.data(witnessPadding);
            builder.number(3);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }

    private Script buildSettle() {
        if (getSignatures().isEmpty()) {
            return new ScriptBuilder().build();
        }
        try {
            ScriptBuilder builder = new ScriptBuilder();
            builder.data(preImage);
            builder.data(pp2Output);
            builder.data(merchantPubKey.getPubKeyBytes());
            builder.data(changePKH);
            builder.number(changeAmount);
            builder.data(getSignatures().get(0).toTxFormat());
            builder.number(custRewardAmount);
            builder.number(merchPayAmount);
            builder.data(eventData);
            builder.data(tokenLHS);
            builder.data(prevTokenTx);
            builder.data(witnessPadding);
            builder.number(4);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }

    private Script buildTimeout() {
        if (getSignatures().isEmpty()) {
            return new ScriptBuilder().build();
        }
        try {
            ScriptBuilder builder = new ScriptBuilder();
            builder.data(preImage);
            builder.data(pp2Output);
            builder.data(merchantPubKey.getPubKeyBytes());
            builder.data(changePKH);
            builder.number(changeAmount);
            builder.data(getSignatures().get(0).toTxFormat());
            builder.number(refundAmount);
            builder.data(tokenLHS);
            builder.data(prevTokenTx);
            builder.data(witnessPadding);
            builder.number(5);
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
            builder.data(merchantPubKey.getPubKeyBytes());
            builder.data(getSignatures().get(0).toTxFormat());
            builder.number(6);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }
}
