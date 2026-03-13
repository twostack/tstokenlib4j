package org.twostack.tstokenlib4j.unlock;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptBuilder;
import org.twostack.bitcoin4j.transaction.TransactionSignature;
import org.twostack.bitcoin4j.transaction.UnlockingScriptBuilder;

import java.io.IOException;

public class ModP2PKHUnlockBuilder extends UnlockingScriptBuilder {

    private final PublicKey signerPubKey;

    public ModP2PKHUnlockBuilder(PublicKey signerPubKey) {
        this.signerPubKey = signerPubKey;
    }

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
