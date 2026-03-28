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
 *   <li>{@link StateMachineAction#CONFIRM} -- confirm a state transition (dual-signature with counterparty)</li>
 *   <li>{@link StateMachineAction#CONVERT} -- convert the state machine state (dual-signature with counterparty)</li>
 *   <li>{@link StateMachineAction#SETTLE} -- settle the state machine, distributing shares to operator and counterparty</li>
 *   <li>{@link StateMachineAction#TIMEOUT} -- timeout the state machine and recover value to operator</li>
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
    private final byte[] witnessFundingOutpoint;
    private final byte[] witnessPadding;
    private final byte[] pp2Output;
    // NOTE: operatorPubKey and changePKH serve distinct roles and may identify different parties.
    // operatorPubKey (33-byte compressed pubkey) is consumed by OP_CHECKSIG to verify the
    // transaction signature. changePKH (20-byte HASH160) is used for output-structure
    // verification — the lock script checks that the token TX's change output pays to this
    // hash via the sighash preimage. In dual-sig actions (CONFIRM, CONVERT), the operator
    // signs but the counterparty may own the change output, so these are genuinely independent.
    private final PublicKey operatorPubKey;
    private final byte[] changePKH;
    private final long changeAmount;
    private final byte[] tokenLHS;
    private final byte[] prevTokenTx;
    private final byte[] eventData;

    // CONFIRM/CONVERT dual-sig extras
    private final PublicKey counterpartyPubKey;
    private final byte[] counterpartySigBytes;

    // SETTLE extras
    private final long counterpartyShareAmount;
    private final long operatorShareAmount;

    // TIMEOUT extras
    private final long recoveryAmount;

    // Rabin identity fields (CREATE only)
    private byte[] rabinN;
    private byte[] rabinS;
    private int rabinPadding;
    private byte[] identityTxId;
    private byte[] ed25519PubKey;

    private PP1SmUnlockBuilder(
            StateMachineAction action,
            byte[] preImage, byte[] witnessFundingOutpoint, byte[] witnessPadding,
            byte[] pp2Output, PublicKey operatorPubKey,
            byte[] changePKH, long changeAmount,
            byte[] tokenLHS, byte[] prevTokenTx,
            byte[] eventData,
            PublicKey counterpartyPubKey, byte[] counterpartySigBytes,
            long counterpartyShareAmount, long operatorShareAmount,
            long recoveryAmount) {
        this.action = action;
        this.preImage = preImage;
        this.witnessFundingOutpoint = witnessFundingOutpoint;
        this.witnessPadding = witnessPadding;
        this.pp2Output = pp2Output;
        this.operatorPubKey = operatorPubKey;
        this.changePKH = changePKH;
        this.changeAmount = changeAmount;
        this.tokenLHS = tokenLHS;
        this.prevTokenTx = prevTokenTx;
        this.eventData = eventData;
        this.counterpartyPubKey = counterpartyPubKey;
        this.counterpartySigBytes = counterpartySigBytes;
        this.counterpartyShareAmount = counterpartyShareAmount;
        this.operatorShareAmount = operatorShareAmount;
        this.recoveryAmount = recoveryAmount;
    }

    /**
     * Creates a builder for the CREATE action. No signature is required.
     *
     * @param preImage            sighash preimage of the transaction for OP_PUSH_TX validation
     * @param witnessFundingOutpoint  36-byte outpoint (txid + vout LE) of the witness funding UTXO
     * @param witnessPadding      padding bytes for witness transaction alignment
     * @return a new builder configured for state machine creation
     */
    public static PP1SmUnlockBuilder forCreate(
            byte[] preImage, byte[] witnessFundingOutpoint, byte[] witnessPadding,
            byte[] rabinN, byte[] rabinS, int rabinPadding,
            byte[] identityTxId, byte[] ed25519PubKey) {
        PP1SmUnlockBuilder b = new PP1SmUnlockBuilder(
                StateMachineAction.CREATE,
                preImage, witnessFundingOutpoint, witnessPadding,
                null, null, null, 0, null, null,
                null, null, null, 0, 0, 0);
        b.rabinN = rabinN;
        b.rabinS = rabinS;
        b.rabinPadding = rabinPadding;
        b.identityTxId = identityTxId;
        b.ed25519PubKey = ed25519PubKey;
        return b;
    }

    /**
     * Creates a builder for the ENROLL action. Requires {@link #addSignature(TransactionSignature)}
     * before {@link #getUnlockingScript()} produces output.
     *
     * @param preImage        sighash preimage of the transaction for OP_PUSH_TX validation
     * @param pp2Output       serialized PP2 witness output for output structure verification
     * @param operatorPubKey  public key of the operator (state machine owner)
     * @param changePKH       20-byte HASH160 for witness change output
     * @param changeAmount    satoshi amount for witness change
     * @param eventData       event data bytes for state machine transitions
     * @param tokenLHS        left-hand side of serialized token output for structure verification
     * @param prevTokenTx     raw bytes of previous token transaction for inductive proof
     * @param witnessPadding  padding bytes for witness transaction alignment
     * @return a new builder configured for enrollment
     */
    public static PP1SmUnlockBuilder forEnroll(
            byte[] preImage, byte[] pp2Output, PublicKey operatorPubKey,
            byte[] changePKH, long changeAmount,
            byte[] eventData,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] witnessPadding) {
        return new PP1SmUnlockBuilder(
                StateMachineAction.ENROLL,
                preImage, null, witnessPadding,
                pp2Output, operatorPubKey, changePKH, changeAmount,
                tokenLHS, prevTokenTx,
                eventData, null, null, 0, 0, 0);
    }

    /**
     * Creates a builder for the CONFIRM action. Requires {@link #addSignature(TransactionSignature)}
     * before {@link #getUnlockingScript()} produces output. This is a dual-signature action
     * requiring both the operator's signature (via addSignature) and the counterparty's signature bytes.
     *
     * @param preImage          sighash preimage of the transaction for OP_PUSH_TX validation
     * @param pp2Output         serialized PP2 witness output for output structure verification
     * @param operatorPubKey    public key of the operator (state machine owner)
     * @param changePKH         20-byte HASH160 for witness change output
     * @param changeAmount      satoshi amount for witness change
     * @param counterpartyPubKey    counterparty's public key for dual-signature verification
     * @param counterpartySigBytes  counterparty's signature bytes for dual-signature verification
     * @param eventData         event data bytes for state machine transitions
     * @param tokenLHS          left-hand side of serialized token output for structure verification
     * @param prevTokenTx       raw bytes of previous token transaction for inductive proof
     * @param witnessPadding    padding bytes for witness transaction alignment
     * @return a new builder configured for confirmation
     */
    public static PP1SmUnlockBuilder forConfirm(
            byte[] preImage, byte[] pp2Output, PublicKey operatorPubKey,
            byte[] changePKH, long changeAmount,
            PublicKey counterpartyPubKey, byte[] counterpartySigBytes,
            byte[] eventData,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] witnessPadding) {
        return new PP1SmUnlockBuilder(
                StateMachineAction.CONFIRM,
                preImage, null, witnessPadding,
                pp2Output, operatorPubKey, changePKH, changeAmount,
                tokenLHS, prevTokenTx,
                eventData, counterpartyPubKey, counterpartySigBytes, 0, 0, 0);
    }

    /**
     * Creates a builder for the CONVERT action. Requires {@link #addSignature(TransactionSignature)}
     * before {@link #getUnlockingScript()} produces output. This is a dual-signature action
     * requiring both the operator's signature (via addSignature) and the counterparty's signature bytes.
     *
     * @param preImage          sighash preimage of the transaction for OP_PUSH_TX validation
     * @param pp2Output         serialized PP2 witness output for output structure verification
     * @param operatorPubKey    public key of the operator (state machine owner)
     * @param changePKH         20-byte HASH160 for witness change output
     * @param changeAmount      satoshi amount for witness change
     * @param counterpartyPubKey    counterparty's public key for dual-signature verification
     * @param counterpartySigBytes  counterparty's signature bytes for dual-signature verification
     * @param eventData         event data bytes for state machine transitions
     * @param tokenLHS          left-hand side of serialized token output for structure verification
     * @param prevTokenTx       raw bytes of previous token transaction for inductive proof
     * @param witnessPadding    padding bytes for witness transaction alignment
     * @return a new builder configured for conversion
     */
    public static PP1SmUnlockBuilder forConvert(
            byte[] preImage, byte[] pp2Output, PublicKey operatorPubKey,
            byte[] changePKH, long changeAmount,
            PublicKey counterpartyPubKey, byte[] counterpartySigBytes,
            byte[] eventData,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] witnessPadding) {
        return new PP1SmUnlockBuilder(
                StateMachineAction.CONVERT,
                preImage, null, witnessPadding,
                pp2Output, operatorPubKey, changePKH, changeAmount,
                tokenLHS, prevTokenTx,
                eventData, counterpartyPubKey, counterpartySigBytes, 0, 0, 0);
    }

    /**
     * Creates a builder for the SETTLE action. Requires {@link #addSignature(TransactionSignature)}
     * before {@link #getUnlockingScript()} produces output.
     *
     * @param preImage          sighash preimage of the transaction for OP_PUSH_TX validation
     * @param pp2Output         serialized PP2 witness output for output structure verification
     * @param operatorPubKey    public key of the operator (state machine owner)
     * @param changePKH         20-byte HASH160 for witness change output
     * @param changeAmount      satoshi amount for witness change
     * @param counterpartyShareAmount  satoshi amount distributed to the counterparty on settlement
     * @param operatorShareAmount    satoshi amount distributed to the operator on settlement
     * @param eventData         event data bytes for state machine transitions
     * @param tokenLHS          left-hand side of serialized token output for structure verification
     * @param prevTokenTx       raw bytes of previous token transaction for inductive proof
     * @param witnessPadding    padding bytes for witness transaction alignment
     * @return a new builder configured for settlement
     */
    public static PP1SmUnlockBuilder forSettle(
            byte[] preImage, byte[] pp2Output, PublicKey operatorPubKey,
            byte[] changePKH, long changeAmount,
            long counterpartyShareAmount, long operatorShareAmount,
            byte[] eventData,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] witnessPadding) {
        return new PP1SmUnlockBuilder(
                StateMachineAction.SETTLE,
                preImage, null, witnessPadding,
                pp2Output, operatorPubKey, changePKH, changeAmount,
                tokenLHS, prevTokenTx,
                eventData, null, null, counterpartyShareAmount, operatorShareAmount, 0);
    }

    /**
     * Creates a builder for the TIMEOUT action. Requires {@link #addSignature(TransactionSignature)}
     * before {@link #getUnlockingScript()} produces output.
     *
     * @param preImage        sighash preimage of the transaction for OP_PUSH_TX validation
     * @param pp2Output       serialized PP2 witness output for output structure verification
     * @param operatorPubKey  public key of the operator (state machine owner)
     * @param changePKH       20-byte HASH160 for witness change output
     * @param changeAmount    satoshi amount for witness change
     * @param recoveryAmount    satoshi amount to recover on timeout
     * @param tokenLHS        left-hand side of serialized token output for structure verification
     * @param prevTokenTx     raw bytes of previous token transaction for inductive proof
     * @param witnessPadding  padding bytes for witness transaction alignment
     * @return a new builder configured for timeout
     */
    public static PP1SmUnlockBuilder forTimeout(
            byte[] preImage, byte[] pp2Output, PublicKey operatorPubKey,
            byte[] changePKH, long changeAmount,
            long recoveryAmount,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] witnessPadding) {
        return new PP1SmUnlockBuilder(
                StateMachineAction.TIMEOUT,
                preImage, null, witnessPadding,
                pp2Output, operatorPubKey, changePKH, changeAmount,
                tokenLHS, prevTokenTx,
                null, null, null, 0, 0, recoveryAmount);
    }

    /**
     * Creates a builder for the BURN action. Requires {@link #addSignature(TransactionSignature)}
     * before {@link #getUnlockingScript()} produces output.
     *
     * @param operatorPubKey public key of the operator (state machine owner)
     * @return a new builder configured for burn
     */
    public static PP1SmUnlockBuilder forBurn(PublicKey operatorPubKey) {
        return new PP1SmUnlockBuilder(
                StateMachineAction.BURN,
                null, null, null,
                null, operatorPubKey, null, 0, null, null,
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
        builder.data(witnessFundingOutpoint);
        builder.data(witnessPadding);
        builder.data(rabinN);
        builder.data(rabinS);
        builder.number(rabinPadding);
        builder.data(identityTxId);
        builder.data(ed25519PubKey);
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
            builder.data(operatorPubKey.getPubKeyBytes());
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
            builder.data(operatorPubKey.getPubKeyBytes());
            builder.data(changePKH);
            builder.number(changeAmount);
            builder.data(getSignatures().get(0).toTxFormat());
            builder.data(counterpartyPubKey.getPubKeyBytes());
            builder.data(counterpartySigBytes);
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
            builder.data(operatorPubKey.getPubKeyBytes());
            builder.data(changePKH);
            builder.number(changeAmount);
            builder.data(getSignatures().get(0).toTxFormat());
            builder.data(counterpartyPubKey.getPubKeyBytes());
            builder.data(counterpartySigBytes);
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
            builder.data(operatorPubKey.getPubKeyBytes());
            builder.data(changePKH);
            builder.number(changeAmount);
            builder.data(getSignatures().get(0).toTxFormat());
            builder.number(counterpartyShareAmount);
            builder.number(operatorShareAmount);
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
            builder.data(operatorPubKey.getPubKeyBytes());
            builder.data(changePKH);
            builder.number(changeAmount);
            builder.data(getSignatures().get(0).toTxFormat());
            builder.number(recoveryAmount);
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
            builder.data(operatorPubKey.getPubKeyBytes());
            builder.data(getSignatures().get(0).toTxFormat());
            builder.number(6);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }
}
