package org.twostack.tstokenlib4j.parser;

import org.twostack.bitcoin4j.script.ScriptInfo;

public class PP1NftScriptInfo extends ScriptInfo {

    private final byte[] ownerPKH;
    private final byte[] tokenId;
    private final byte[] rabinPKH;

    public PP1NftScriptInfo(byte[] ownerPKH, byte[] tokenId, byte[] rabinPKH) {
        super("PP1_NFT");
        this.ownerPKH = ownerPKH;
        this.tokenId = tokenId;
        this.rabinPKH = rabinPKH;
    }

    public byte[] getOwnerPKH() { return ownerPKH; }
    public byte[] getTokenId() { return tokenId; }
    public byte[] getRabinPKH() { return rabinPKH; }
}
