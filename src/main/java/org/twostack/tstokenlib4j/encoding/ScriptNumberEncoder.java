package org.twostack.tstokenlib4j.encoding;

import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.ScriptBuilder;

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
