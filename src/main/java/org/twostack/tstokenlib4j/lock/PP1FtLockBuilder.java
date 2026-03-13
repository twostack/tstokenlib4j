package org.twostack.tstokenlib4j.lock;

import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.transaction.LockingScriptBuilder;
import org.twostack.tstokenlib4j.encoding.AmountEncoder;
import org.twostack.tstokenlib4j.template.TemplateDescriptor;
import org.twostack.tstokenlib4j.template.TemplateLoader;

public class PP1FtLockBuilder extends LockingScriptBuilder {

    private final byte[] ownerPKH;
    private final byte[] tokenId;
    private final long amount;

    public PP1FtLockBuilder(byte[] ownerPKH, byte[] tokenId, long amount) {
        if (ownerPKH == null || ownerPKH.length != 20) {
            throw new IllegalArgumentException("ownerPKH must be 20 bytes");
        }
        if (tokenId == null || tokenId.length != 32) {
            throw new IllegalArgumentException("tokenId must be 32 bytes");
        }
        if (amount < 0 || amount >= (1L << 55)) {
            throw new IllegalArgumentException("amount must be >= 0 and < 2^55");
        }
        this.ownerPKH = ownerPKH.clone();
        this.tokenId = tokenId.clone();
        this.amount = amount;
    }

    @Override
    public Script getLockingScript() {
        TemplateDescriptor td = TemplateLoader.load("templates/ft/pp1_ft.json");
        String hex = td.getHex();
        hex = hex.replace("{{ownerPKH}}", Utils.HEX.encode(ownerPKH));
        hex = hex.replace("{{tokenId}}", Utils.HEX.encode(tokenId));
        hex = hex.replace("{{amount}}", Utils.HEX.encode(AmountEncoder.encodeLeUint56(amount)));
        return Script.fromByteArray(Utils.HEX.decode(hex));
    }

    public byte[] getOwnerPKH() {
        return ownerPKH.clone();
    }

    public byte[] getTokenId() {
        return tokenId.clone();
    }

    public long getAmount() {
        return amount;
    }
}
