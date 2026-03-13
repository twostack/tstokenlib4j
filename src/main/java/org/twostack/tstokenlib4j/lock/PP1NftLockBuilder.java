package org.twostack.tstokenlib4j.lock;

import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.transaction.LockingScriptBuilder;
import org.twostack.tstokenlib4j.template.TemplateDescriptor;
import org.twostack.tstokenlib4j.template.TemplateLoader;

public class PP1NftLockBuilder extends LockingScriptBuilder {

    private final byte[] ownerPKH;
    private final byte[] tokenId;
    private final byte[] rabinPubKeyHash;

    public PP1NftLockBuilder(byte[] ownerPKH, byte[] tokenId, byte[] rabinPubKeyHash) {
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
    }

    @Override
    public Script getLockingScript() {
        TemplateDescriptor td = TemplateLoader.load("templates/nft/pp1_nft.json");
        String hex = td.getHex();
        hex = hex.replace("{{ownerPKH}}", Utils.HEX.encode(ownerPKH));
        hex = hex.replace("{{tokenId}}", Utils.HEX.encode(tokenId));
        hex = hex.replace("{{rabinPubKeyHash}}", Utils.HEX.encode(rabinPubKeyHash));
        return Script.fromByteArray(Utils.HEX.decode(hex));
    }

    public byte[] getOwnerPKH() {
        return ownerPKH.clone();
    }

    public byte[] getTokenId() {
        return tokenId.clone();
    }

    public byte[] getRabinPubKeyHash() {
        return rabinPubKeyHash.clone();
    }
}
