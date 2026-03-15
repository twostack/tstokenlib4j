package org.twostack.tstokenlib4j.parser;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.*;

import java.util.Arrays;
import java.util.List;

/**
 * ScriptTemplate for PP1 Non-Fungible Token (NFT) scripts.
 *
 * <p>Layout after the 54-byte common prefix:
 * <pre>
 *   byte[54]     = 0x14 (push 20: rabinPKH)
 *   byte[55..74] = rabinPKH
 *   byte[75]     != 0x14 (not SM) and != 0x04 (not AT/RNFT/RFT)
 * </pre>
 *
 * <p>NFT is the "base" pattern — any PP1 script with a 20-byte field after the prefix
 * that doesn't match the more specific AT, SM, RNFT, or RFT discriminators.</p>
 */
public class PP1NftTemplate implements ScriptTemplate {

    private static final int MIN_LEN = 75; // 54 + 1+20

    @Override
    public String getName() {
        return "PP1_NFT";
    }

    @Override
    public boolean matches(Script script) {
        byte[] p = script.getProgram();
        if (!PP1TemplateBase.hasValidPrefix(p, MIN_LEN)) return false;
        if (p[54] != PP1TemplateBase.PUSH_20) return false;
        // Exclude more specific archetypes
        if (p.length >= 76 && p[75] == PP1TemplateBase.PUSH_20) return false; // SM
        if (p.length >= 76 && p[75] == PP1TemplateBase.PUSH_4) return false;  // AT, RNFT, or RFT
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
                    "Script is not a PP1_NFT script");
        }
        byte[] p = script.getProgram();
        return new PP1NftScriptInfo(
                PP1TemplateBase.extractOwnerPKH(p),
                PP1TemplateBase.extractTokenId(p),
                PP1TemplateBase.extractBytes(p, 55, 20)
        );
    }
}
