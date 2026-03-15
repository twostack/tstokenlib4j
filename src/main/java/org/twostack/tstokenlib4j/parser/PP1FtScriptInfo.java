package org.twostack.tstokenlib4j.parser;

import org.twostack.bitcoin4j.script.ScriptInfo;

public class PP1FtScriptInfo extends ScriptInfo {

    private final byte[] ownerPKH;
    private final byte[] tokenId;
    private final long amount;

    public PP1FtScriptInfo(byte[] ownerPKH, byte[] tokenId, long amount) {
        super("PP1_FT");
        this.ownerPKH = ownerPKH;
        this.tokenId = tokenId;
        this.amount = amount;
    }

    public byte[] getOwnerPKH() { return ownerPKH; }
    public byte[] getTokenId() { return tokenId; }
    public long getAmount() { return amount; }
}
