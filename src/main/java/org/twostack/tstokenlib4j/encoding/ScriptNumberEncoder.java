package org.twostack.tstokenlib4j.encoding;

import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.ScriptBuilder;

/**
 * Encodes numeric values as Bitcoin script number fragments for use in PP2
 * locking script template substitution.
 *
 * <p>Small values (0-16) are encoded as single-byte opcodes (OP_0 through OP_16).
 * Larger values are encoded as pushdata + little-endian bytes. The encoder produces
 * the complete script fragment as a hex string.
 *
 * @see org.twostack.tstokenlib4j.lock.PP2LockBuilder
 * @see org.twostack.tstokenlib4j.lock.PP2FtLockBuilder
 */
public class ScriptNumberEncoder {

    /**
     * Encodes a long value as a Bitcoin script number, returning the hex string
     * of the complete script fragment (opcode or pushdata + LE bytes).
     *
     * Delegates to ScriptBuilder.number() for guaranteed byte-identity with bitcoin4j.
     */
    public static String encode(long value) {
        byte[] program = new ScriptBuilder().number(value).build().getProgram();
        return Utils.HEX.encode(program);
    }
}
