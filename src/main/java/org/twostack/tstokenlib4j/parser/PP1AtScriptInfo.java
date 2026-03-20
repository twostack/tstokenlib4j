package org.twostack.tstokenlib4j.parser;

import org.twostack.bitcoin4j.script.ScriptInfo;

public class PP1AtScriptInfo extends ScriptInfo {

    private final byte[] ownerPKH;
    private final byte[] tokenId;
    private final byte[] issuerPKH;
    private final byte[] rabinPubKeyHash;
    private final int stampCount;
    private final int threshold;
    private final byte[] stampsHash;

    public PP1AtScriptInfo(byte[] ownerPKH, byte[] tokenId, byte[] issuerPKH,
                           byte[] rabinPubKeyHash,
                           int stampCount, int threshold, byte[] stampsHash) {
        super("PP1_AT");
        this.ownerPKH = ownerPKH;
        this.tokenId = tokenId;
        this.issuerPKH = issuerPKH;
        this.rabinPubKeyHash = rabinPubKeyHash;
        this.stampCount = stampCount;
        this.threshold = threshold;
        this.stampsHash = stampsHash;
    }

    public byte[] getOwnerPKH() { return ownerPKH; }
    public byte[] getTokenId() { return tokenId; }
    public byte[] getIssuerPKH() { return issuerPKH; }
    public byte[] getRabinPubKeyHash() { return rabinPubKeyHash; }
    public int getStampCount() { return stampCount; }
    public int getThreshold() { return threshold; }
    public byte[] getStampsHash() { return stampsHash; }
}
