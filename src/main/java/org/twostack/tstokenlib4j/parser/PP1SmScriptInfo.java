package org.twostack.tstokenlib4j.parser;

import org.twostack.bitcoin4j.script.ScriptInfo;

public class PP1SmScriptInfo extends ScriptInfo {

    private final byte[] ownerPKH;
    private final byte[] tokenId;
    private final byte[] merchantPKH;
    private final byte[] customerPKH;
    private final byte[] rabinPubKeyHash;
    private final int currentState;
    private final int milestoneCount;
    private final byte[] commitmentHash;
    private final int transitionBitmask;
    private final int timeoutDelta;

    public PP1SmScriptInfo(byte[] ownerPKH, byte[] tokenId,
                           byte[] merchantPKH, byte[] customerPKH,
                           byte[] rabinPubKeyHash,
                           int currentState, int milestoneCount,
                           byte[] commitmentHash, int transitionBitmask,
                           int timeoutDelta) {
        super("PP1_SM");
        this.ownerPKH = ownerPKH;
        this.tokenId = tokenId;
        this.merchantPKH = merchantPKH;
        this.customerPKH = customerPKH;
        this.rabinPubKeyHash = rabinPubKeyHash;
        this.currentState = currentState;
        this.milestoneCount = milestoneCount;
        this.commitmentHash = commitmentHash;
        this.transitionBitmask = transitionBitmask;
        this.timeoutDelta = timeoutDelta;
    }

    public byte[] getOwnerPKH() { return ownerPKH; }
    public byte[] getTokenId() { return tokenId; }
    public byte[] getMerchantPKH() { return merchantPKH; }
    public byte[] getCustomerPKH() { return customerPKH; }
    public byte[] getRabinPubKeyHash() { return rabinPubKeyHash; }
    public int getCurrentState() { return currentState; }
    public int getMilestoneCount() { return milestoneCount; }
    public byte[] getCommitmentHash() { return commitmentHash; }
    public int getTransitionBitmask() { return transitionBitmask; }
    public int getTimeoutDelta() { return timeoutDelta; }
}
