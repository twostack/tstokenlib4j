package org.twostack.tstokenlib4j.parser;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.*;

import java.util.Arrays;
import java.util.List;

/**
 * ScriptTemplate for PP1 Appendable Token (AT) scripts.
 *
 * <p>Layout after the 54-byte common prefix:
 * <pre>
 *   byte[54]      = 0x14 (push 20: issuerPKH)
 *   byte[55..74]  = issuerPKH
 *   byte[75]      = 0x04 (push 4: stampCount)
 *   byte[76..79]  = stampCount (LE uint32)
 *   byte[80]      = 0x04 (push 4: threshold)
 *   byte[81..84]  = threshold (LE uint32)
 *   byte[85]      = 0x20 (push 32: stampsHash)
 *   byte[86..117] = stampsHash
 * </pre>
 */
public class PP1AtTemplate implements ScriptTemplate {

    private static final int MIN_LEN = 118; // 54 + 1+20 + 1+4 + 1+4 + 1+32

    @Override
    public String getName() {
        return "PP1_AT";
    }

    @Override
    public boolean matches(Script script) {
        byte[] p = script.getProgram();
        if (!PP1TemplateBase.hasValidPrefix(p, MIN_LEN)) return false;
        return p[54] == PP1TemplateBase.PUSH_20
                && p[75] == PP1TemplateBase.PUSH_4
                && p[80] == PP1TemplateBase.PUSH_4
                && p[85] == PP1TemplateBase.PUSH_32;
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
                    "Script is not a PP1_AT script");
        }
        byte[] p = script.getProgram();
        return new PP1AtScriptInfo(
                PP1TemplateBase.extractOwnerPKH(p),
                PP1TemplateBase.extractTokenId(p),
                PP1TemplateBase.extractBytes(p, 55, 20),
                PP1TemplateBase.readLeUint32(p, 76),
                PP1TemplateBase.readLeUint32(p, 81),
                PP1TemplateBase.extractBytes(p, 86, 32)
        );
    }
}
