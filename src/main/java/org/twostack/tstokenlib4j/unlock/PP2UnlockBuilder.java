package org.twostack.tstokenlib4j.unlock;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptBuilder;
import org.twostack.bitcoin4j.transaction.TransactionSignature;
import org.twostack.bitcoin4j.transaction.UnlockingScriptBuilder;

import java.io.IOException;

/**
 * Builds the unlocking script for a PP2 witness locking script.
 *
 * <p>Supported actions:
 * <ul>
 *   <li>Normal (forNormal) -- standard witness unlock using the outpoint transaction ID</li>
 *   <li>Burn (forBurn) -- destroy the witness output with owner signature</li>
 * </ul>
 *
 * <p>Instances are created through the static factory methods {@link #forNormal(byte[])}
 * and {@link #forBurn(PublicKey)}. The constructor is private.
 *
 * <p>The BURN action requires a signature to be added via
 * {@link #addSignature(TransactionSignature)} before {@link #getUnlockingScript()} will
 * produce a non-empty script. The NORMAL action does not require a signature.
 *
 * <p>The last item pushed onto the script stack is always the action's opValue integer.
 */
public class PP2UnlockBuilder extends UnlockingScriptBuilder {

    private final byte[] outpointTxId;
    private final PublicKey ownerPubKey;
    private final boolean isBurn;

    private PP2UnlockBuilder(byte[] outpointTxId, PublicKey ownerPubKey, boolean isBurn) {
        this.outpointTxId = outpointTxId;
        this.ownerPubKey = ownerPubKey;
        this.isBurn = isBurn;
    }

    /**
     * Creates a builder for the NORMAL witness unlock action. No signature is required.
     *
     * @param outpointTxId transaction ID of the outpoint being spent
     * @return a new builder configured for normal witness unlock
     */
    public static PP2UnlockBuilder forNormal(byte[] outpointTxId) {
        return new PP2UnlockBuilder(outpointTxId, null, false);
    }

    /**
     * Creates a builder for the BURN witness action. Requires {@link #addSignature(TransactionSignature)}
     * before {@link #getUnlockingScript()} produces output.
     *
     * @param ownerPubKey public key of the current token owner
     * @return a new builder configured for burn
     */
    public static PP2UnlockBuilder forBurn(PublicKey ownerPubKey) {
        return new PP2UnlockBuilder(null, ownerPubKey, true);
    }

    /**
     * Builds and returns the unlocking script.
     *
     * <p>For NORMAL, pushes the outpoint transaction ID followed by opValue 0.
     * For BURN, if no signature has been added an empty script is returned; otherwise
     * pushes the owner public key, signature, and opValue 1.
     *
     * @return the unlocking {@link Script}, or an empty script when prerequisites are not met
     */
    @Override
    public Script getUnlockingScript() {
        if (isBurn) {
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
        } else {
            ScriptBuilder builder = new ScriptBuilder();
            builder.data(outpointTxId);
            builder.number(0);
            return builder.build();
        }
    }
}
