package org.twostack.tstokenlib4j.encoding;

import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.ScriptBuilder;

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
