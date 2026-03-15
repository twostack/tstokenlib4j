package org.twostack.tstokenlib4j.encoding;

import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.ScriptBuilder;

/**
 * Encodes byte arrays as Bitcoin pushdata script fragments for use in PP2
 * locking script template substitution.
 *
 * <p>Unlike PP1 templates where pushdata prefixes are baked into the template hex,
 * PP2 templates require dynamic-length encoding. This encoder produces the complete
 * script fragment (length prefix + data) as a hex string.
 *
 * @see org.twostack.tstokenlib4j.lock.PP2LockBuilder
 * @see org.twostack.tstokenlib4j.lock.PP2FtLockBuilder
 */
public class PushdataEncoder {

    /**
     * Encodes a byte array as a Bitcoin pushdata operation, returning the hex string
     * of the complete script fragment (length prefix + data bytes).
     *
     * Delegates to ScriptBuilder.data() for guaranteed byte-identity with bitcoin4j.
     */
    public static String encode(byte[] data) {
        byte[] program = new ScriptBuilder().data(data).build().getProgram();
        return Utils.HEX.encode(program);
    }
}
