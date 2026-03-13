package org.twostack.tstokenlib4j.unlock;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptBuilder;
import org.twostack.bitcoin4j.transaction.TransactionSignature;
import org.twostack.bitcoin4j.transaction.UnlockingScriptBuilder;

import java.io.IOException;

public class PP2UnlockBuilder extends UnlockingScriptBuilder {

    private final byte[] outpointTxId;
    private final PublicKey ownerPubKey;
    private final boolean isBurn;

    private PP2UnlockBuilder(byte[] outpointTxId, PublicKey ownerPubKey, boolean isBurn) {
        this.outpointTxId = outpointTxId;
        this.ownerPubKey = ownerPubKey;
        this.isBurn = isBurn;
    }

    public static PP2UnlockBuilder forNormal(byte[] outpointTxId) {
        return new PP2UnlockBuilder(outpointTxId, null, false);
    }

    public static PP2UnlockBuilder forBurn(PublicKey ownerPubKey) {
        return new PP2UnlockBuilder(null, ownerPubKey, true);
    }

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
