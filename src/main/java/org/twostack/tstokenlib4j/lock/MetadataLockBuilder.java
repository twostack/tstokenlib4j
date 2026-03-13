package org.twostack.tstokenlib4j.lock;

import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptBuilder;
import org.twostack.bitcoin4j.script.ScriptOpCodes;
import org.twostack.bitcoin4j.transaction.LockingScriptBuilder;

public class MetadataLockBuilder extends LockingScriptBuilder {

    private final byte[] metadataBytes;

    public MetadataLockBuilder(byte[] metadataBytes) {
        this.metadataBytes = metadataBytes != null ? metadataBytes.clone() : null;
    }

    public MetadataLockBuilder() {
        this.metadataBytes = null;
    }

    @Override
    public Script getLockingScript() {
        ScriptBuilder builder = new ScriptBuilder();
        builder.op(ScriptOpCodes.OP_FALSE);
        builder.op(ScriptOpCodes.OP_RETURN);
        if (metadataBytes != null && metadataBytes.length > 0) {
            builder.data(metadataBytes);
        }
        return builder.build();
    }

    public byte[] getMetadataBytes() {
        return metadataBytes != null ? metadataBytes.clone() : null;
    }
}
