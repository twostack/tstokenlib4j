package org.twostack.tstokenlib4j.parser;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.*;

import java.util.Arrays;
import java.util.List;

/**
 * ScriptTemplate for PP1 Fungible Token (FT) scripts.
 *
 * <p>Layout after the 54-byte common prefix:
 * <pre>
 *   byte[54]     = 0x08 (push 8: amount)
 *   byte[55..62] = amount (LE uint56)
 * </pre>
 *
 * <p>FT is uniquely identified by having 0x08 at byte[54] — no other PP1
 * archetype starts with an 8-byte push after the common prefix.</p>
 */
public class PP1FtTemplate implements ScriptTemplate {

    private static final int MIN_LEN = 63; // 54 + 1+8

    @Override
    public String getName() {
        return "PP1_FT";
    }

    @Override
    public boolean matches(Script script) {
        byte[] p = script.getProgram();
        if (!PP1TemplateBase.hasValidPrefix(p, MIN_LEN)) return false;
        return p[54] == PP1TemplateBase.PUSH_8;
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
                    "Script is not a PP1_FT script");
        }
        byte[] p = script.getProgram();
        return new PP1FtScriptInfo(
                PP1TemplateBase.extractOwnerPKH(p),
                PP1TemplateBase.extractTokenId(p),
                PP1TemplateBase.readLeUint56(p, 55)
        );
    }
}
