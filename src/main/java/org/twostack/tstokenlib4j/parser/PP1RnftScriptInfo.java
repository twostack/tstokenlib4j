package org.twostack.tstokenlib4j.parser;

import org.twostack.bitcoin4j.script.ScriptInfo;

public class PP1RnftScriptInfo extends ScriptInfo {

    private final byte[] ownerPKH;
    private final byte[] tokenId;
    private final byte[] rabinPKH;
    private final int flags;

    public PP1RnftScriptInfo(byte[] ownerPKH, byte[] tokenId, byte[] rabinPKH, int flags) {
        super("PP1_RNFT");
        this.ownerPKH = ownerPKH;
        this.tokenId = tokenId;
        this.rabinPKH = rabinPKH;
        this.flags = flags;
    }

    public byte[] getOwnerPKH() { return ownerPKH; }
    public byte[] getTokenId() { return tokenId; }
    public byte[] getRabinPKH() { return rabinPKH; }
    public int getFlags() { return flags; }
}
