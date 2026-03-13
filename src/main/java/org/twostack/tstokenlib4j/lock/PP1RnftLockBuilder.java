package org.twostack.tstokenlib4j.lock;

import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.transaction.LockingScriptBuilder;
import org.twostack.tstokenlib4j.template.TemplateDescriptor;
import org.twostack.tstokenlib4j.template.TemplateLoader;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PP1RnftLockBuilder extends LockingScriptBuilder {

    private final byte[] ownerPKH;
    private final byte[] tokenId;
    private final byte[] rabinPubKeyHash;
    private final int flags;

    public PP1RnftLockBuilder(byte[] ownerPKH, byte[] tokenId, byte[] rabinPubKeyHash, int flags) {
        if (ownerPKH == null || ownerPKH.length != 20) {
            throw new IllegalArgumentException("ownerPKH must be 20 bytes");
        }
        if (tokenId == null || tokenId.length != 32) {
            throw new IllegalArgumentException("tokenId must be 32 bytes");
        }
        if (rabinPubKeyHash == null || rabinPubKeyHash.length != 20) {
            throw new IllegalArgumentException("rabinPubKeyHash must be 20 bytes");
        }
        this.ownerPKH = ownerPKH.clone();
        this.tokenId = tokenId.clone();
        this.rabinPubKeyHash = rabinPubKeyHash.clone();
        this.flags = flags;
    }

    @Override
    public Script getLockingScript() {
        TemplateDescriptor td = TemplateLoader.load("templates/nft/pp1_rnft.json");
        String hex = td.getHex();
        hex = hex.replace("{{ownerPKH}}", Utils.HEX.encode(ownerPKH));
        hex = hex.replace("{{tokenId}}", Utils.HEX.encode(tokenId));
        hex = hex.replace("{{rabinPubKeyHash}}", Utils.HEX.encode(rabinPubKeyHash));
        hex = hex.replace("{{flags}}", encodeLeUint32(flags));
        return Script.fromByteArray(Utils.HEX.decode(hex));
    }

    private static String encodeLeUint32(int value) {
        byte[] bytes = new byte[4];
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(value);
        return Utils.HEX.encode(bytes);
    }

    public byte[] getOwnerPKH() { return ownerPKH.clone(); }
    public byte[] getTokenId() { return tokenId.clone(); }
    public byte[] getRabinPubKeyHash() { return rabinPubKeyHash.clone(); }
    public int getFlags() { return flags; }
}
