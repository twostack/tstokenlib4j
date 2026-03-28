package org.twostack.tstokenlib4j.parser;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.*;

import java.util.Arrays;
import java.util.List;

/**
 * ScriptTemplate for the Modified P2PKH (ModP2PKH) utility output.
 *
 * <p>Layout: {@code OP_SWAP OP_DUP OP_HASH160 PUSH20 <20-byte PKH> OP_EQUALVERIFY OP_CHECKSIG}
 * <br>Hex: {@code 7c 76 a9 14 <PKH> 88 ac} — exactly 26 bytes.
 *
 * <p>Used for witness outputs and token change outputs in TSL1 transactions.
 */
public class ModP2PKHTemplate implements ScriptTemplate {

    private static final int SCRIPT_LEN = 26;

    @Override
    public String getName() {
        return "ModP2PKH";
    }

    @Override
    public boolean matches(Script script) {
        byte[] p = script.getProgram();
        return p.length == SCRIPT_LEN
                && p[0] == 0x7c          // OP_SWAP
                && p[1] == 0x76          // OP_DUP
                && p[2] == (byte) 0xa9   // OP_HASH160
                && p[3] == 0x14          // PUSH 20
                && p[24] == (byte) 0x88  // OP_EQUALVERIFY
                && p[25] == (byte) 0xac; // OP_CHECKSIG
    }

    @Override
    public boolean canBeSatisfiedBy(List<PublicKey> keys, Script script) {
        if (!matches(script) || keys == null || keys.isEmpty()) return false;
        byte[] ownerPKH = extractOwnerPKH(script.getProgram());
        for (PublicKey key : keys) {
            if (Arrays.equals(key.getPubKeyHash(), ownerPKH)) return true;
        }
        return false;
    }

    @Override
    public ScriptInfo extractScriptInfo(Script script) {
        if (!matches(script)) {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                    "Script is not a ModP2PKH script");
        }
        return new ModP2PKHScriptInfo(extractOwnerPKH(script.getProgram()));
    }

    static byte[] extractOwnerPKH(byte[] program) {
        byte[] pkh = new byte[20];
        System.arraycopy(program, 4, pkh, 0, 20);
        return pkh;
    }
}
