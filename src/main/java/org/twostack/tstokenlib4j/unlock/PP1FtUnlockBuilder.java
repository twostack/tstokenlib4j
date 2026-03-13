package org.twostack.tstokenlib4j.unlock;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptBuilder;
import org.twostack.bitcoin4j.transaction.TransactionSignature;
import org.twostack.bitcoin4j.transaction.UnlockingScriptBuilder;

import java.io.IOException;

public class PP1FtUnlockBuilder extends UnlockingScriptBuilder {

    private final FungibleTokenAction action;
    private final byte[] preImage;
    private final byte[] witnessFundingTxId;
    private final byte[] witnessPadding;
    private final byte[] pp2Output;
    private final PublicKey ownerPubKey;
    private final byte[] changePKH;
    private final long changeAmount;
    private final byte[] tokenLHS;
    private final byte[] prevTokenTx;
    private final int parentOutputCount;
    private final int parentPP1FtIndex;

    // SPLIT_TRANSFER extras
    private final byte[] pp2ChangeOutput;
    private final long recipientAmount;
    private final long tokenChangeAmount;
    private final byte[] recipientPKH;
    private final int myOutputIndex;

    // MERGE extras
    private final byte[] prevTokenTxB;
    private final int parentOutputCountB;
    private final int parentPP1FtIndexB;

    private PP1FtUnlockBuilder(
            FungibleTokenAction action,
            byte[] preImage, byte[] witnessFundingTxId, byte[] witnessPadding,
            byte[] pp2Output, PublicKey ownerPubKey,
            byte[] changePKH, long changeAmount,
            byte[] tokenLHS, byte[] prevTokenTx,
            int parentOutputCount, int parentPP1FtIndex,
            byte[] pp2ChangeOutput, long recipientAmount, long tokenChangeAmount,
            byte[] recipientPKH, int myOutputIndex,
            byte[] prevTokenTxB, int parentOutputCountB, int parentPP1FtIndexB) {
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
        this.parentOutputCount = parentOutputCount;
        this.parentPP1FtIndex = parentPP1FtIndex;
        this.pp2ChangeOutput = pp2ChangeOutput;
        this.recipientAmount = recipientAmount;
        this.tokenChangeAmount = tokenChangeAmount;
        this.recipientPKH = recipientPKH;
        this.myOutputIndex = myOutputIndex;
        this.prevTokenTxB = prevTokenTxB;
        this.parentOutputCountB = parentOutputCountB;
        this.parentPP1FtIndexB = parentPP1FtIndexB;
    }

    public static PP1FtUnlockBuilder forMint(
            byte[] preImage, byte[] witnessFundingTxId, byte[] witnessPadding) {
        return new PP1FtUnlockBuilder(
                FungibleTokenAction.MINT,
                preImage, witnessFundingTxId, witnessPadding,
                null, null, null, 0, null, null,
                0, 0,
                null, 0, 0, null, 0,
                null, 0, 0);
    }

    public static PP1FtUnlockBuilder forTransfer(
            byte[] preImage, byte[] pp2Output, PublicKey ownerPubKey,
            byte[] changePKH, long changeAmount,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] witnessPadding,
            int parentOutputCount, int parentPP1FtIndex) {
        return new PP1FtUnlockBuilder(
                FungibleTokenAction.TRANSFER,
                preImage, null, witnessPadding,
                pp2Output, ownerPubKey, changePKH, changeAmount,
                tokenLHS, prevTokenTx,
                parentOutputCount, parentPP1FtIndex,
                null, 0, 0, null, 0,
                null, 0, 0);
    }

    public static PP1FtUnlockBuilder forSplitTransfer(
            byte[] preImage, byte[] pp2RecipientOutput, byte[] pp2ChangeOutput,
            PublicKey ownerPubKey, byte[] changePKH, long changeAmount,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] witnessPadding,
            long recipientAmount, long tokenChangeAmount,
            byte[] recipientPKH, int myOutputIndex,
            int parentOutputCount, int parentPP1FtIndex) {
        return new PP1FtUnlockBuilder(
                FungibleTokenAction.SPLIT_TRANSFER,
                preImage, null, witnessPadding,
                pp2RecipientOutput, ownerPubKey, changePKH, changeAmount,
                tokenLHS, prevTokenTx,
                parentOutputCount, parentPP1FtIndex,
                pp2ChangeOutput, recipientAmount, tokenChangeAmount,
                recipientPKH, myOutputIndex,
                null, 0, 0);
    }

    public static PP1FtUnlockBuilder forMerge(
            byte[] preImage, byte[] pp2Output, PublicKey ownerPubKey,
            byte[] changePKH, long changeAmount,
            byte[] tokenLHS, byte[] prevTokenTxA, byte[] prevTokenTxB,
            byte[] witnessPadding,
            int parentOutputCountA, int parentOutputCountB,
            int parentPP1FtIndexA, int parentPP1FtIndexB) {
        return new PP1FtUnlockBuilder(
                FungibleTokenAction.MERGE,
                preImage, null, witnessPadding,
                pp2Output, ownerPubKey, changePKH, changeAmount,
                tokenLHS, prevTokenTxA,
                parentOutputCountA, parentPP1FtIndexA,
                null, 0, 0, null, 0,
                prevTokenTxB, parentOutputCountB, parentPP1FtIndexB);
    }

    public static PP1FtUnlockBuilder forBurn(PublicKey ownerPubKey) {
        return new PP1FtUnlockBuilder(
                FungibleTokenAction.BURN,
                null, null, null,
                null, ownerPubKey, null, 0, null, null,
                0, 0,
                null, 0, 0, null, 0,
                null, 0, 0);
    }

    @Override
    public Script getUnlockingScript() {
        switch (action) {
            case MINT:
                return buildMint();
            case TRANSFER:
                return buildTransfer();
            case SPLIT_TRANSFER:
                return buildSplitTransfer();
            case MERGE:
                return buildMerge();
            case BURN:
                return buildBurn();
            default:
                return new ScriptBuilder().build();
        }
    }

    private Script buildMint() {
        ScriptBuilder builder = new ScriptBuilder();
        builder.data(preImage);
        builder.data(witnessFundingTxId);
        builder.data(witnessPadding);
        builder.number(0);
        return builder.build();
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
            builder.number(parentOutputCount);
            builder.number(parentPP1FtIndex);
            builder.number(1);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }

    private Script buildSplitTransfer() {
        if (getSignatures().isEmpty()) {
            return new ScriptBuilder().build();
        }
        try {
            ScriptBuilder builder = new ScriptBuilder();
            builder.data(preImage);
            builder.data(pp2Output);
            builder.data(pp2ChangeOutput);
            builder.data(ownerPubKey.getPubKeyBytes());
            builder.data(changePKH);
            builder.number(changeAmount);
            builder.data(getSignatures().get(0).toTxFormat());
            builder.data(tokenLHS);
            builder.data(prevTokenTx);
            builder.data(witnessPadding);
            builder.number(recipientAmount);
            builder.number(tokenChangeAmount);
            builder.data(recipientPKH);
            builder.number(myOutputIndex);
            builder.number(parentOutputCount);
            builder.number(parentPP1FtIndex);
            builder.number(2);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }

    private Script buildMerge() {
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
            builder.data(prevTokenTxB);
            builder.data(witnessPadding);
            builder.number(parentOutputCount);
            builder.number(parentOutputCountB);
            builder.number(parentPP1FtIndex);
            builder.number(parentPP1FtIndexB);
            builder.number(3);
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
