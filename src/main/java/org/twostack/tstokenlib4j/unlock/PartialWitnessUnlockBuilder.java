package org.twostack.tstokenlib4j.unlock;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptBuilder;
import org.twostack.bitcoin4j.transaction.UnlockingScriptBuilder;

import java.io.IOException;

/**
 * Builds the unlocking script for a PP3 partial witness locking script.
 *
 * <p>Supported actions:
 * <ul>
 *   <li>Unlock (forUnlock) -- standard partial witness unlock with preimage and partial hash</li>
 *   <li>Burn (forBurn) -- destroy the partial witness output with owner signature</li>
 * </ul>
 *
 * <p>Instances are created through the static factory methods {@link #forUnlock}
 * and {@link #forBurn(PublicKey)}. The constructor is private.
 *
 * <p>The BURN action requires a signature to be added via
 * {@link #addSignature(TransactionSignature)} before {@link #getUnlockingScript()} will
 * produce a non-empty script. The UNLOCK action does not require a signature.
 *
 * <p>The last item pushed onto the script stack is always the action's opValue integer.
 */
public class PartialWitnessUnlockBuilder extends UnlockingScriptBuilder {

    private final TokenAction action;
    private final byte[] preImage;
    private final byte[] partialHash;
    private final byte[] partialWitnessPreImage;
    private final byte[] fundingTxId;
    private final PublicKey ownerPubKey;

    private PartialWitnessUnlockBuilder(
            TokenAction action,
            byte[] preImage, byte[] partialHash,
            byte[] partialWitnessPreImage, byte[] fundingTxId,
            PublicKey ownerPubKey) {
        this.action = action;
        this.preImage = preImage;
        this.partialHash = partialHash;
        this.partialWitnessPreImage = partialWitnessPreImage;
        this.fundingTxId = fundingTxId;
        this.ownerPubKey = ownerPubKey;
    }

    /**
     * Creates a builder for the UNLOCK action. No signature is required.
     *
     * @param preImage                sighash preimage of the transaction for OP_PUSH_TX validation
     * @param partialHash             partial hash for witness verification
     * @param partialWitnessPreImage  preimage for partial witness hash verification
     * @param fundingTxId             transaction ID of the funding input
     * @return a new builder configured for partial witness unlock
     */
    public static PartialWitnessUnlockBuilder forUnlock(
            byte[] preImage, byte[] partialHash,
            byte[] partialWitnessPreImage, byte[] fundingTxId) {
        return new PartialWitnessUnlockBuilder(
                TokenAction.ISSUANCE,
                preImage, partialHash, partialWitnessPreImage, fundingTxId,
                null);
    }

    /**
     * Creates a builder for the BURN action. Requires {@link #addSignature(TransactionSignature)}
     * before {@link #getUnlockingScript()} produces output.
     *
     * @param ownerPubKey public key of the current token owner
     * @return a new builder configured for burn
     */
    public static PartialWitnessUnlockBuilder forBurn(PublicKey ownerPubKey) {
        return new PartialWitnessUnlockBuilder(
                TokenAction.BURN,
                null, null, null, null,
                ownerPubKey);
    }

    /**
     * Builds and returns the unlocking script by dispatching to the appropriate
     * private build method based on the configured action.
     *
     * <p>For BURN, if no signature has been added an empty script is returned.
     * The last item pushed is always the action's opValue integer (UNLOCK=0, BURN=1).
     *
     * @return the unlocking {@link Script}, or an empty script when prerequisites are not met
     */
    @Override
    public Script getUnlockingScript() {
        switch (action) {
            case ISSUANCE:
                return buildUnlock();
            case BURN:
                return buildBurn();
            default:
                return new ScriptBuilder().build();
        }
    }

    private Script buildUnlock() {
        ScriptBuilder builder = new ScriptBuilder();
        builder.data(preImage);
        builder.data(partialHash);
        builder.data(partialWitnessPreImage);
        builder.data(fundingTxId);
        builder.number(0);
        return builder.build();
    }

    private Script buildBurn() {
        if (getSignatures().isEmpty()) {
            return new ScriptBuilder().build();
        }
        try {
            ScriptBuilder builder = new ScriptBuilder();
            builder.data(ownerPubKey.getPubKeyBytes());
            builder.data(getSignatures().get(0).toTxFormat());
            builder.number(1);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }
}
