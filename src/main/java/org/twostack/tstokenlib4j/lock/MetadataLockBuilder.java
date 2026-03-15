package org.twostack.tstokenlib4j.lock;

import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptBuilder;
import org.twostack.bitcoin4j.script.ScriptOpCodes;
import org.twostack.bitcoin4j.transaction.LockingScriptBuilder;

/**
 * Builds an {@code OP_FALSE OP_RETURN} metadata locking script for TSL1 token transactions.
 *
 * <p>This builder produces a provably-unspendable output that carries arbitrary metadata.
 * Unlike all other lock builders in this package, {@code MetadataLockBuilder} does
 * <em>not</em> use a pre-compiled hex template. Instead, it constructs the script
 * programmatically via {@link ScriptBuilder}, emitting {@code OP_FALSE OP_RETURN}
 * followed by an optional pushdata containing the caller-supplied metadata bytes.</p>
 *
 * <p>The metadata payload is optional; when omitted (via the no-arg constructor), the
 * resulting script consists of only {@code OP_FALSE OP_RETURN}.</p>
 *
 * @see <a href="https://github.com/twostack/tsl1">TSL1 Specification</a>
 */
public class MetadataLockBuilder extends LockingScriptBuilder {

    private final byte[] metadataBytes;

    /**
     * Creates a metadata lock builder with the given payload.
     *
     * @param metadataBytes the raw metadata to embed after {@code OP_RETURN}, or {@code null}
     *                      for an empty metadata output; defensively cloned if non-null
     */
    public MetadataLockBuilder(byte[] metadataBytes) {
        this.metadataBytes = metadataBytes != null ? metadataBytes.clone() : null;
    }

    /**
     * Creates a metadata lock builder with no payload.
     * The resulting script will consist of only {@code OP_FALSE OP_RETURN}.
     */
    public MetadataLockBuilder() {
        this.metadataBytes = null;
    }

    /**
     * Builds the metadata locking script by emitting {@code OP_FALSE OP_RETURN} followed
     * by the optional metadata payload as a pushdata element.
     *
     * <p>No template is used; the script is assembled directly via {@link ScriptBuilder}.</p>
     *
     * @return the fully assembled locking {@link Script}
     */
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

    /** @return a defensive copy of the metadata bytes, or {@code null} if none were provided */
    public byte[] getMetadataBytes() {
        return metadataBytes != null ? metadataBytes.clone() : null;
    }
}
