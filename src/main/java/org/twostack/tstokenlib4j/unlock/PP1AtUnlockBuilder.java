package org.twostack.tstokenlib4j.unlock;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptBuilder;
import org.twostack.bitcoin4j.transaction.UnlockingScriptBuilder;

import java.io.IOException;

public class PP1AtUnlockBuilder extends UnlockingScriptBuilder {

    private final AppendableTokenAction action;
    private final byte[] preImage;
    private final byte[] witnessFundingTxId;
    private final byte[] witnessPadding;
    private final byte[] pp2Output;
    private final PublicKey ownerPubKey;
    private final byte[] changePKH;
    private final long changeAmount;
    private final byte[] tokenLHS;
    private final byte[] prevTokenTx;
    private final byte[] stampMetadata;

    private PP1AtUnlockBuilder(
            AppendableTokenAction action,
            byte[] preImage, byte[] witnessFundingTxId, byte[] witnessPadding,
            byte[] pp2Output, PublicKey ownerPubKey,
            byte[] changePKH, long changeAmount,
            byte[] tokenLHS, byte[] prevTokenTx,
            byte[] stampMetadata) {
        this.action = action;
        this.preImage = preImage;
        this.witnessFundingTxId = witnessFundingTxId;
        this.witnessPadding = witnessPadding;
        this.pp2Output = pp2Output;
        this.ownerPubKey = ownerPubKey;
        this.changePKH = changePKH;
        this.changeAmount = changeAmount;
        this.tokenLHS = tokenLHS;
        this.prevTokenTx = prevTokenTx;
        this.stampMetadata = stampMetadata;
    }

    public static PP1AtUnlockBuilder forIssuance(
            byte[] preImage, byte[] witnessFundingTxId, byte[] witnessPadding,
            PublicKey issuerPubKey) {
        return new PP1AtUnlockBuilder(
                AppendableTokenAction.ISSUANCE,
                preImage, witnessFundingTxId, witnessPadding,
                null, issuerPubKey, null, 0, null, null, null);
    }

    public static PP1AtUnlockBuilder forStamp(
            byte[] preImage, byte[] pp2Output, PublicKey issuerPubKey,
            byte[] changePKH, long changeAmount,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] witnessPadding,
            byte[] stampMetadata) {
        return new PP1AtUnlockBuilder(
                AppendableTokenAction.STAMP,
                preImage, null, witnessPadding,
                pp2Output, issuerPubKey, changePKH, changeAmount,
                tokenLHS, prevTokenTx, stampMetadata);
    }

    public static PP1AtUnlockBuilder forTransfer(
            byte[] preImage, byte[] pp2Output, PublicKey ownerPubKey,
            byte[] changePKH, long changeAmount,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] witnessPadding) {
        return new PP1AtUnlockBuilder(
                AppendableTokenAction.TRANSFER,
                preImage, null, witnessPadding,
                pp2Output, ownerPubKey, changePKH, changeAmount,
                tokenLHS, prevTokenTx, null);
    }

    public static PP1AtUnlockBuilder forRedeem(PublicKey ownerPubKey) {
        return new PP1AtUnlockBuilder(
                AppendableTokenAction.REDEEM,
                null, null, null,
                null, ownerPubKey, null, 0, null, null, null);
    }

    public static PP1AtUnlockBuilder forBurn(PublicKey ownerPubKey) {
        return new PP1AtUnlockBuilder(
                AppendableTokenAction.BURN,
                null, null, null,
                null, ownerPubKey, null, 0, null, null, null);
    }

    @Override
    public Script getUnlockingScript() {
        switch (action) {
            case ISSUANCE:
                return buildIssuance();
            case STAMP:
                return buildStamp();
            case TRANSFER:
                return buildTransfer();
            case REDEEM:
                return buildRedeem();
            case BURN:
                return buildBurn();
            default:
                return new ScriptBuilder().build();
        }
    }

    private Script buildIssuance() {
        if (getSignatures().isEmpty()) {
            return new ScriptBuilder().build();
        }
        try {
            ScriptBuilder builder = new ScriptBuilder();
            builder.data(preImage);
            builder.data(witnessFundingTxId);
            builder.data(witnessPadding);
            builder.data(ownerPubKey.getPubKeyBytes());
            builder.data(getSignatures().get(0).toTxFormat());
            builder.number(0);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }

    private Script buildStamp() {
        if (getSignatures().isEmpty()) {
            return new ScriptBuilder().build();
        }
        try {
            ScriptBuilder builder = new ScriptBuilder();
            builder.data(preImage);
            builder.data(pp2Output);
            builder.data(ownerPubKey.getPubKeyBytes());
            builder.data(changePKH);
            builder.number(changeAmount);
            builder.data(getSignatures().get(0).toTxFormat());
            builder.data(tokenLHS);
            builder.data(prevTokenTx);
            builder.data(witnessPadding);
            builder.data(stampMetadata);
            builder.number(1);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }

    private Script buildTransfer() {
        if (getSignatures().isEmpty()) {
            return new ScriptBuilder().build();
        }
        try {
            ScriptBuilder builder = new ScriptBuilder();
            builder.data(preImage);
            builder.data(pp2Output);
            builder.data(ownerPubKey.getPubKeyBytes());
            builder.data(changePKH);
            builder.number(changeAmount);
            builder.data(getSignatures().get(0).toTxFormat());
            builder.data(tokenLHS);
            builder.data(prevTokenTx);
            builder.data(witnessPadding);
            builder.number(3);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }

    private Script buildRedeem() {
        if (getSignatures().isEmpty()) {
            return new ScriptBuilder().build();
        }
        try {
            ScriptBuilder builder = new ScriptBuilder();
            builder.data(ownerPubKey.getPubKeyBytes());
            builder.data(getSignatures().get(0).toTxFormat());
            builder.number(2);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }

    private Script buildBurn() {
        if (getSignatures().isEmpty()) {
            return new ScriptBuilder().build();
        }
        try {
            ScriptBuilder builder = new ScriptBuilder();
            builder.data(ownerPubKey.getPubKeyBytes());
            builder.data(getSignatures().get(0).toTxFormat());
            builder.number(4);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }
}
