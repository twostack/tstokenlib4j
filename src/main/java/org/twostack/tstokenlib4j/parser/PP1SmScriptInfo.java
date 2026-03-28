package org.twostack.tstokenlib4j.parser;

import org.twostack.bitcoin4j.script.ScriptInfo;

public class PP1SmScriptInfo extends ScriptInfo {

    private final byte[] ownerPKH;
    private final byte[] tokenId;
    private final byte[] operatorPKH;
    private final byte[] counterpartyPKH;
    private final byte[] rabinPubKeyHash;
    private final int currentState;
    private final int checkpointCount;
    private final byte[] commitmentHash;
    private final int transitionBitmask;
    private final int timeoutDelta;

    public PP1SmScriptInfo(byte[] ownerPKH, byte[] tokenId,
                           byte[] operatorPKH, byte[] counterpartyPKH,
                           byte[] rabinPubKeyHash,
                           int currentState, int checkpointCount,
                           byte[] commitmentHash, int transitionBitmask,
                           int timeoutDelta) {
        super("PP1_SM");
        this.ownerPKH = ownerPKH;
        this.tokenId = tokenId;
        this.operatorPKH = operatorPKH;
        this.counterpartyPKH = counterpartyPKH;
        this.rabinPubKeyHash = rabinPubKeyHash;
        this.currentState = currentState;
        this.checkpointCount = checkpointCount;
        this.commitmentHash = commitmentHash;
        this.transitionBitmask = transitionBitmask;
        this.timeoutDelta = timeoutDelta;
    }

    public byte[] getOwnerPKH() { return ownerPKH; }
    public byte[] getTokenId() { return tokenId; }
    public byte[] getOperatorPKH() { return operatorPKH; }
    public byte[] getCounterpartyPKH() { return counterpartyPKH; }
    public byte[] getRabinPubKeyHash() { return rabinPubKeyHash; }
    public int getCurrentState() { return currentState; }
    public int getCheckpointCount() { return checkpointCount; }
    public byte[] getCommitmentHash() { return commitmentHash; }
    public int getTransitionBitmask() { return transitionBitmask; }
    public int getTimeoutDelta() { return timeoutDelta; }
}
