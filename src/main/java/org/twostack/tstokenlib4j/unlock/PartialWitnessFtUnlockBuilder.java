package org.twostack.tstokenlib4j.unlock;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptBuilder;
import org.twostack.bitcoin4j.transaction.UnlockingScriptBuilder;

import java.io.IOException;

public class PartialWitnessFtUnlockBuilder extends UnlockingScriptBuilder {

    private final FungibleTokenAction action;
    private final byte[] preImage;
    private final byte[] partialHash;
    private final byte[] partialWitnessPreImage;
    private final byte[] fundingTxId;
    private final PublicKey ownerPubKey;

    private PartialWitnessFtUnlockBuilder(
            FungibleTokenAction action,
            byte[] preImage, byte[] partialHash,
            byte[] partialWitnessPreImage, byte[] fundingTxId,
            PublicKey ownerPubKey) {
        this.action = action;
        this.preImage = preImage;
        this.partialHash = partialHash;
        this.partialWitnessPreImage = partialWitnessPreImage;
        this.fundingTxId = fundingTxId;
        this.ownerPubKey = ownerPubKey;
    }

    public static PartialWitnessFtUnlockBuilder forUnlock(
            byte[] preImage, byte[] partialHash,
            byte[] partialWitnessPreImage, byte[] fundingTxId) {
        return new PartialWitnessFtUnlockBuilder(
                FungibleTokenAction.MINT,
                preImage, partialHash, partialWitnessPreImage, fundingTxId,
                null);
    }

    public static PartialWitnessFtUnlockBuilder forBurn(PublicKey ownerPubKey) {
        return new PartialWitnessFtUnlockBuilder(
                FungibleTokenAction.BURN,
                null, null, null, null,
                ownerPubKey);
    }

    @Override
    public Script getUnlockingScript() {
        switch (action) {
            case MINT:
                return buildUnlock();
            case BURN:
                return buildBurn();
            default:
                return new ScriptBuilder().build();
        }
    }

    private Script buildUnlock() {
        ScriptBuilder builder = new ScriptBuilder();
        builder.data(preImage);
        builder.data(partialHash);
        builder.data(partialWitnessPreImage);
        builder.data(fundingTxId);
        builder.number(0);
        return builder.build();
    }

    private Script buildBurn() {
        if (getSignatures().isEmpty()) {
            return new ScriptBuilder().build();
        }
        try {
            ScriptBuilder builder = new ScriptBuilder();
            builder.data(ownerPubKey.getPubKeyBytes());
            builder.data(getSignatures().get(0).toTxFormat());
            builder.number(1);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }
}
