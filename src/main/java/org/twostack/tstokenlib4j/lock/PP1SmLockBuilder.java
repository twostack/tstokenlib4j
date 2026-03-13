package org.twostack.tstokenlib4j.lock;

import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.transaction.LockingScriptBuilder;
import org.twostack.tstokenlib4j.template.TemplateDescriptor;
import org.twostack.tstokenlib4j.template.TemplateLoader;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PP1SmLockBuilder extends LockingScriptBuilder {

    private final byte[] ownerPKH;
    private final byte[] tokenId;
    private final byte[] merchantPKH;
    private final byte[] customerPKH;
    private final int currentState;
    private final int milestoneCount;
    private final byte[] commitmentHash;
    private final int transitionBitmask;
    private final int timeoutDelta;

    public PP1SmLockBuilder(byte[] ownerPKH, byte[] tokenId,
                            byte[] merchantPKH, byte[] customerPKH,
                            int currentState, int milestoneCount,
                            byte[] commitmentHash, int transitionBitmask,
                            int timeoutDelta) {
        if (ownerPKH == null || ownerPKH.length != 20) {
            throw new IllegalArgumentException("ownerPKH must be 20 bytes");
        }
        if (tokenId == null || tokenId.length != 32) {
            throw new IllegalArgumentException("tokenId must be 32 bytes");
        }
        if (merchantPKH == null || merchantPKH.length != 20) {
            throw new IllegalArgumentException("merchantPKH must be 20 bytes");
        }
        if (customerPKH == null || customerPKH.length != 20) {
            throw new IllegalArgumentException("customerPKH must be 20 bytes");
        }
        if (commitmentHash == null || commitmentHash.length != 32) {
            throw new IllegalArgumentException("commitmentHash must be 32 bytes");
        }
        this.ownerPKH = ownerPKH.clone();
        this.tokenId = tokenId.clone();
        this.merchantPKH = merchantPKH.clone();
        this.customerPKH = customerPKH.clone();
        this.currentState = currentState;
        this.milestoneCount = milestoneCount;
        this.commitmentHash = commitmentHash.clone();
        this.transitionBitmask = transitionBitmask;
        this.timeoutDelta = timeoutDelta;
    }

    @Override
    public Script getLockingScript() {
        TemplateDescriptor td = TemplateLoader.load("templates/sm/pp1_sm.json");
        String hex = td.getHex();
        hex = hex.replace("{{ownerPKH}}", Utils.HEX.encode(ownerPKH));
        hex = hex.replace("{{tokenId}}", Utils.HEX.encode(tokenId));
        hex = hex.replace("{{merchantPKH}}", Utils.HEX.encode(merchantPKH));
        hex = hex.replace("{{customerPKH}}", Utils.HEX.encode(customerPKH));
        hex = hex.replace("{{currentState}}", encodeHexByte(currentState));
        hex = hex.replace("{{milestoneCount}}", encodeHexByte(milestoneCount));
        hex = hex.replace("{{commitmentHash}}", Utils.HEX.encode(commitmentHash));
        hex = hex.replace("{{transitionBitmask}}", encodeHexByte(transitionBitmask));
        hex = hex.replace("{{timeoutDelta}}", encodeLeUint32(timeoutDelta));
        return Script.fromByteArray(Utils.HEX.decode(hex));
    }

    private static String encodeHexByte(int value) {
        return String.format("%02x", value & 0xFF);
    }

    private static String encodeLeUint32(int value) {
        byte[] bytes = new byte[4];
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(value);
        return Utils.HEX.encode(bytes);
    }

    public byte[] getOwnerPKH() { return ownerPKH.clone(); }
    public byte[] getTokenId() { return tokenId.clone(); }
    public byte[] getMerchantPKH() { return merchantPKH.clone(); }
    public byte[] getCustomerPKH() { return customerPKH.clone(); }
    public int getCurrentState() { return currentState; }
    public int getMilestoneCount() { return milestoneCount; }
    public byte[] getCommitmentHash() { return commitmentHash.clone(); }
    public int getTransitionBitmask() { return transitionBitmask; }
    public int getTimeoutDelta() { return timeoutDelta; }
}
