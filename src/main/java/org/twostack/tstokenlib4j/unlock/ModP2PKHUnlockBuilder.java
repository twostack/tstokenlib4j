package org.twostack.tstokenlib4j.unlock;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptBuilder;
import org.twostack.bitcoin4j.transaction.TransactionSignature;
import org.twostack.bitcoin4j.transaction.UnlockingScriptBuilder;

import java.io.IOException;

/**
 * Builds the unlocking script for a Modified P2PKH (Pay-to-Public-Key-Hash) locking script.
 *
 * <p>This builder produces a simple signature-plus-public-key unlock. Unlike the standard
 * P2PKH template the public key is pushed before the signature.
 *
 * <p>A signature must be added via {@link #addSignature(TransactionSignature)} before
 * {@link #getUnlockingScript()} will produce a non-empty script.
 */
public class ModP2PKHUnlockBuilder extends UnlockingScriptBuilder {

    private final PublicKey signerPubKey;

    /**
     * Creates a new ModP2PKH unlock builder.
     *
     * @param signerPubKey public key of the signer whose signature will unlock the output
     */
    public ModP2PKHUnlockBuilder(PublicKey signerPubKey) {
        this.signerPubKey = signerPubKey;
    }

    /**
     * Builds and returns the unlocking script.
     *
     * <p>If no signature has been added via {@link #addSignature(TransactionSignature)},
     * an empty script is returned. Otherwise the script pushes the signer's public key
     * followed by the transaction-format signature.
     *
     * @return the unlocking {@link Script}, or an empty script when no signature is present
     */
    @Override
    public Script getUnlockingScript() {
        if (getSignatures().isEmpty()) {
            return new ScriptBuilder().build();
        }

        try {
            ScriptBuilder builder = new ScriptBuilder();
            builder.data(signerPubKey.getPubKeyBytes());
            builder.data(getSignatures().get(0).toTxFormat());
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }
}
