package org.twostack.tstokenlib4j.parser;

import org.twostack.bitcoin4j.script.ScriptInfo;

public class PP1RftScriptInfo extends ScriptInfo {

    private final byte[] ownerPKH;
    private final byte[] tokenId;
    private final byte[] rabinPKH;
    private final int flags;
    private final long amount;

    public PP1RftScriptInfo(byte[] ownerPKH, byte[] tokenId, byte[] rabinPKH,
                            int flags, long amount) {
        super("PP1_RFT");
        this.ownerPKH = ownerPKH;
        this.tokenId = tokenId;
        this.rabinPKH = rabinPKH;
        this.flags = flags;
        this.amount = amount;
    }

    public byte[] getOwnerPKH() { return ownerPKH; }
    public byte[] getTokenId() { return tokenId; }
    public byte[] getRabinPKH() { return rabinPKH; }
    public int getFlags() { return flags; }
    public long getAmount() { return amount; }
}
