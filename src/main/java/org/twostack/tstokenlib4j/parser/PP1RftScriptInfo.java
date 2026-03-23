package org.twostack.tstokenlib4j.parser;

import org.twostack.bitcoin4j.script.ScriptInfo;

public class PP1RftScriptInfo extends ScriptInfo {

    private final byte[] ownerPKH;
    private final byte[] tokenId;
    private final byte[] rabinPKH;
    private final int flags;
    private final long amount;
    private final int tokenSupply;
    private final byte[] merkleRoot;

    public PP1RftScriptInfo(byte[] ownerPKH, byte[] tokenId, byte[] rabinPKH,
                            int flags, long amount, int tokenSupply, byte[] merkleRoot) {
        super("PP1_RFT");
        this.ownerPKH = ownerPKH;
        this.tokenId = tokenId;
        this.rabinPKH = rabinPKH;
        this.flags = flags;
        this.amount = amount;
        this.tokenSupply = tokenSupply;
        this.merkleRoot = merkleRoot;
    }

    public byte[] getOwnerPKH() { return ownerPKH; }
    public byte[] getTokenId() { return tokenId; }
    public byte[] getRabinPKH() { return rabinPKH; }
    public int getFlags() { return flags; }
    public long getAmount() { return amount; }
    public int getTokenSupply() { return tokenSupply; }
    public byte[] getMerkleRoot() { return merkleRoot; }
}
