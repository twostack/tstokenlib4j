package org.twostack.tstokenlib4j.lock;

import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.transaction.LockingScriptBuilder;
import org.twostack.tstokenlib4j.template.TemplateDescriptor;
import org.twostack.tstokenlib4j.template.TemplateLoader;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PP1AtLockBuilder extends LockingScriptBuilder {

    private final byte[] ownerPKH;
    private final byte[] tokenId;
    private final byte[] issuerPKH;
    private final int stampCount;
    private final int threshold;
    private final byte[] stampsHash;

    public PP1AtLockBuilder(byte[] ownerPKH, byte[] tokenId, byte[] issuerPKH,
                            int stampCount, int threshold, byte[] stampsHash) {
        if (ownerPKH == null || ownerPKH.length != 20) {
            throw new IllegalArgumentException("ownerPKH must be 20 bytes");
        }
        if (tokenId == null || tokenId.length != 32) {
            throw new IllegalArgumentException("tokenId must be 32 bytes");
        }
        if (issuerPKH == null || issuerPKH.length != 20) {
            throw new IllegalArgumentException("issuerPKH must be 20 bytes");
        }
        if (stampsHash == null || stampsHash.length != 32) {
            throw new IllegalArgumentException("stampsHash must be 32 bytes");
        }
        this.ownerPKH = ownerPKH.clone();
        this.tokenId = tokenId.clone();
        this.issuerPKH = issuerPKH.clone();
        this.stampCount = stampCount;
        this.threshold = threshold;
        this.stampsHash = stampsHash.clone();
    }

    @Override
    public Script getLockingScript() {
        TemplateDescriptor td = TemplateLoader.load("templates/nft/pp1_at.json");
        String hex = td.getHex();
        hex = hex.replace("{{ownerPKH}}", Utils.HEX.encode(ownerPKH));
        hex = hex.replace("{{tokenId}}", Utils.HEX.encode(tokenId));
        hex = hex.replace("{{issuerPKH}}", Utils.HEX.encode(issuerPKH));
        hex = hex.replace("{{stampCount}}", encodeLeUint32(stampCount));
        hex = hex.replace("{{threshold}}", encodeLeUint32(threshold));
        hex = hex.replace("{{stampsHash}}", Utils.HEX.encode(stampsHash));
        return Script.fromByteArray(Utils.HEX.decode(hex));
    }

    private static String encodeLeUint32(int value) {
        byte[] bytes = new byte[4];
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(value);
        return Utils.HEX.encode(bytes);
    }

    public byte[] getOwnerPKH() { return ownerPKH.clone(); }
    public byte[] getTokenId() { return tokenId.clone(); }
    public byte[] getIssuerPKH() { return issuerPKH.clone(); }
    public int getStampCount() { return stampCount; }
    public int getThreshold() { return threshold; }
    public byte[] getStampsHash() { return stampsHash.clone(); }
}
