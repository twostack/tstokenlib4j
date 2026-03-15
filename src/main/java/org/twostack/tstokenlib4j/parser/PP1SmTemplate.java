package org.twostack.tstokenlib4j.parser;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.*;

import java.util.Arrays;
import java.util.List;

/**
 * ScriptTemplate for PP1 State Machine (SM) scripts.
 *
 * <p>Layout after the 54-byte common prefix:
 * <pre>
 *   byte[54]       = 0x14 (push 20: merchantPKH)
 *   byte[55..74]   = merchantPKH
 *   byte[75]       = 0x14 (push 20: customerPKH)
 *   byte[76..95]   = customerPKH
 *   byte[96]       = 0x01 (push 1: currentState)
 *   byte[97]       = currentState
 *   byte[98]       = 0x01 (push 1: milestoneCount)
 *   byte[99]       = milestoneCount
 *   byte[100]      = 0x20 (push 32: commitmentHash)
 *   byte[101..132] = commitmentHash
 *   byte[133]      = 0x01 (push 1: transitionBitmask)
 *   byte[134]      = transitionBitmask
 *   byte[135]      = 0x04 (push 4: timeoutDelta)
 *   byte[136..139] = timeoutDelta (LE uint32)
 * </pre>
 */
public class PP1SmTemplate implements ScriptTemplate {

    private static final int MIN_LEN = 140; // 54 + 1+20 + 1+20 + 1+1 + 1+1 + 1+32 + 1+1 + 1+4

    @Override
    public String getName() {
        return "PP1_SM";
    }

    @Override
    public boolean matches(Script script) {
        byte[] p = script.getProgram();
        if (!PP1TemplateBase.hasValidPrefix(p, MIN_LEN)) return false;
        return p[54] == PP1TemplateBase.PUSH_20
                && p[75] == PP1TemplateBase.PUSH_20;
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
                    "Script is not a PP1_SM script");
        }
        byte[] p = script.getProgram();
        return new PP1SmScriptInfo(
                PP1TemplateBase.extractOwnerPKH(p),
                PP1TemplateBase.extractTokenId(p),
                PP1TemplateBase.extractBytes(p, 55, 20),   // merchantPKH
                PP1TemplateBase.extractBytes(p, 76, 20),   // customerPKH
                p[97] & 0xFF,                               // currentState
                p[99] & 0xFF,                               // milestoneCount
                PP1TemplateBase.extractBytes(p, 101, 32),  // commitmentHash
                p[134] & 0xFF,                              // transitionBitmask
                PP1TemplateBase.readLeUint32(p, 136)       // timeoutDelta
        );
    }
}
