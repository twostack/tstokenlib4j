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
 *   byte[54]       = 0x14 (push 20: operatorPKH)
 *   byte[55..74]   = operatorPKH
 *   byte[75]       = 0x14 (push 20: counterpartyPKH)
 *   byte[76..95]   = counterpartyPKH
 *   byte[96]       = 0x14 (push 20: rabinPubKeyHash)
 *   byte[97..116]  = rabinPubKeyHash
 *   byte[117]      = 0x01 (push 1: currentState)
 *   byte[118]      = currentState
 *   byte[119]      = 0x01 (push 1: checkpointCount)
 *   byte[120]      = checkpointCount
 *   byte[121]      = 0x20 (push 32: commitmentHash)
 *   byte[122..153] = commitmentHash
 *   byte[154]      = 0x01 (push 1: transitionBitmask)
 *   byte[155]      = transitionBitmask
 *   byte[156]      = 0x04 (push 4: timeoutDelta)
 *   byte[157..160] = timeoutDelta (LE uint32)
 * </pre>
 */
public class PP1SmTemplate implements ScriptTemplate {

    private static final int MIN_LEN = 161; // 54 + 3*(1+20) + 1+1 + 1+1 + 1+32 + 1+1 + 1+4

    @Override
    public String getName() {
        return "PP1_SM";
    }

    @Override
    public boolean matches(Script script) {
        byte[] p = script.getProgram();
        if (!PP1TemplateBase.hasValidPrefix(p, MIN_LEN)) return false;
        // Three consecutive 0x14 pushes (operatorPKH, counterpartyPKH, rabinPKH)
        return p[54] == PP1TemplateBase.PUSH_20
                && p[75] == PP1TemplateBase.PUSH_20
                && p[96] == PP1TemplateBase.PUSH_20;
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
                PP1TemplateBase.extractBytes(p, 55, 20),   // operatorPKH
                PP1TemplateBase.extractBytes(p, 76, 20),   // counterpartyPKH
                PP1TemplateBase.extractBytes(p, 97, 20),   // rabinPubKeyHash
                p[118] & 0xFF,                              // currentState (shifted +21)
                p[120] & 0xFF,                              // checkpointCount (shifted +21)
                PP1TemplateBase.extractBytes(p, 122, 32),  // commitmentHash (shifted +21)
                p[155] & 0xFF,                              // transitionBitmask (shifted +21)
                PP1TemplateBase.readLeUint32(p, 157)       // timeoutDelta (shifted +21)
        );
    }
}
