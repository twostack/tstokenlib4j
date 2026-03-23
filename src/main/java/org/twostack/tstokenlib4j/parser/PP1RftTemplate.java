package org.twostack.tstokenlib4j.parser;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.*;

import java.util.Arrays;
import java.util.List;

/**
 * ScriptTemplate for PP1 Restricted Fungible Token (RFT) scripts.
 *
 * <p>Layout after the 54-byte common prefix:
 * <pre>
 *   byte[54]      = 0x14 (push 20: rabinPKH)
 *   byte[55..74]  = rabinPKH
 *   byte[75]      = 0x04 (push 4: flags)
 *   byte[76..79]  = flags (LE uint32)
 *   byte[80]      = 0x08 (push 8: amount)
 *   byte[81..88]  = amount (LE uint56)
 *   byte[89]      = 0x04 (push 4: tokenSupply)
 *   byte[90..93]  = tokenSupply (LE uint32)
 *   byte[94]      = 0x20 (push 32: merkleRoot)
 *   byte[95..126] = merkleRoot
 * </pre>
 */
public class PP1RftTemplate implements ScriptTemplate {

    private static final int MIN_LEN = 127; // 54 + 1+20 + 1+4 + 1+8 + 1+4 + 1+32

    @Override
    public String getName() {
        return "PP1_RFT";
    }

    @Override
    public boolean matches(Script script) {
        byte[] p = script.getProgram();
        if (!PP1TemplateBase.hasValidPrefix(p, MIN_LEN)) return false;
        return p[54] == PP1TemplateBase.PUSH_20
                && p[75] == PP1TemplateBase.PUSH_4    // flags
                && p[80] == PP1TemplateBase.PUSH_8    // amount
                && p[89] == PP1TemplateBase.PUSH_4    // tokenSupply
                && p[94] == PP1TemplateBase.PUSH_32;  // merkleRoot
    }

    @Override
    public boolean canBeSatisfiedBy(List<PublicKey> keys, Script script) {
        if (!matches(script) || keys == null || keys.isEmpty()) return false;
        byte[] ownerPKH = PP1TemplateBase.extractOwnerPKH(script.getProgram());
        for (PublicKey key : keys) {
            if (Arrays.equals(key.getPubKeyHash(), ownerPKH)) return true;
        }
        return false;
    }

    @Override
    public ScriptInfo extractScriptInfo(Script script) {
        if (!matches(script)) {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                    "Script is not a PP1_RFT script");
        }
        byte[] p = script.getProgram();
        return new PP1RftScriptInfo(
                PP1TemplateBase.extractOwnerPKH(p),
                PP1TemplateBase.extractTokenId(p),
                PP1TemplateBase.extractBytes(p, 55, 20),
                PP1TemplateBase.readLeUint32(p, 76),
                PP1TemplateBase.readLeUint56(p, 81),
                PP1TemplateBase.readLeUint32(p, 90),
                PP1TemplateBase.extractBytes(p, 95, 32)
        );
    }
}
