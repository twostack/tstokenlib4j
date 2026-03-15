package org.twostack.tstokenlib4j.parser;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.*;

import java.util.Arrays;
import java.util.List;

/**
 * ScriptTemplate for PP1 Restricted Non-Fungible Token (RNFT) scripts.
 *
 * <p>Layout after the 54-byte common prefix:
 * <pre>
 *   byte[54]     = 0x14 (push 20: rabinPKH)
 *   byte[55..74] = rabinPKH
 *   byte[75]     = 0x04 (push 4: flags)
 *   byte[76..79] = flags (LE uint32)
 *   byte[80]     != 0x08 (no amount field — distinguishes from RFT)
 * </pre>
 */
public class PP1RnftTemplate implements ScriptTemplate {

    private static final int MIN_LEN = 80; // 54 + 1+20 + 1+4

    @Override
    public String getName() {
        return "PP1_RNFT";
    }

    @Override
    public boolean matches(Script script) {
        byte[] p = script.getProgram();
        if (!PP1TemplateBase.hasValidPrefix(p, MIN_LEN)) return false;
        if (p[54] != PP1TemplateBase.PUSH_20) return false;
        if (p[75] != PP1TemplateBase.PUSH_4) return false;
        // Distinguish from AT: AT has 0x04 at [80], but also 0x20 at [85]
        // Distinguish from RFT: RFT has 0x08 at [80]
        if (p.length > 80 && p[80] == PP1TemplateBase.PUSH_8) return false;  // RFT
        if (p.length > 85 && p[80] == PP1TemplateBase.PUSH_4 && p[85] == PP1TemplateBase.PUSH_32) return false; // AT
        return true;
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
                    "Script is not a PP1_RNFT script");
        }
        byte[] p = script.getProgram();
        return new PP1RnftScriptInfo(
                PP1TemplateBase.extractOwnerPKH(p),
                PP1TemplateBase.extractTokenId(p),
                PP1TemplateBase.extractBytes(p, 55, 20),
                PP1TemplateBase.readLeUint32(p, 76)
        );
    }
}
