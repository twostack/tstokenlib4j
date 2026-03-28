package org.twostack.tstokenlib4j.parser;

import org.twostack.bitcoin4j.script.ScriptInfo;

/**
 * Parsed information from a ModP2PKH locking script.
 */
public class ModP2PKHScriptInfo extends ScriptInfo {

    private final byte[] ownerPKH;

    public ModP2PKHScriptInfo(byte[] ownerPKH) {
        super("ModP2PKH");
        this.ownerPKH = ownerPKH;
    }

    public byte[] getOwnerPKH() { return ownerPKH; }
}
