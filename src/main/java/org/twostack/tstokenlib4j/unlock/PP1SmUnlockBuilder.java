package org.twostack.tstokenlib4j.unlock;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptBuilder;
import org.twostack.bitcoin4j.transaction.UnlockingScriptBuilder;

import java.io.IOException;

public class PP1SmUnlockBuilder extends UnlockingScriptBuilder {

    private final StateMachineAction action;
    private final byte[] preImage;
    private final byte[] witnessFundingTxId;
    private final byte[] witnessPadding;
    private final byte[] pp2Output;
    private final PublicKey merchantPubKey;
    private final byte[] changePKH;
    private final long changeAmount;
    private final byte[] tokenLHS;
    private final byte[] prevTokenTx;
    private final byte[] eventData;

    // CONFIRM/CONVERT dual-sig extras
    private final PublicKey customerPubKey;
    private final byte[] customerSigBytes;

    // SETTLE extras
    private final long custRewardAmount;
    private final long merchPayAmount;

    // TIMEOUT extras
    private final long refundAmount;

    private PP1SmUnlockBuilder(
            StateMachineAction action,
            byte[] preImage, byte[] witnessFundingTxId, byte[] witnessPadding,
            byte[] pp2Output, PublicKey merchantPubKey,
            byte[] changePKH, long changeAmount,
            byte[] tokenLHS, byte[] prevTokenTx,
            byte[] eventData,
            PublicKey customerPubKey, byte[] customerSigBytes,
            long custRewardAmount, long merchPayAmount,
            long refundAmount) {
        this.action = action;
        this.preImage = preImage;
        this.witnessFundingTxId = witnessFundingTxId;
        this.witnessPadding = witnessPadding;
        this.pp2Output = pp2Output;
        this.merchantPubKey = merchantPubKey;
        this.changePKH = changePKH;
        this.changeAmount = changeAmount;
        this.tokenLHS = tokenLHS;
        this.prevTokenTx = prevTokenTx;
        this.eventData = eventData;
        this.customerPubKey = customerPubKey;
        this.customerSigBytes = customerSigBytes;
        this.custRewardAmount = custRewardAmount;
        this.merchPayAmount = merchPayAmount;
        this.refundAmount = refundAmount;
    }

    public static PP1SmUnlockBuilder forCreate(
            byte[] preImage, byte[] witnessFundingTxId, byte[] witnessPadding) {
        return new PP1SmUnlockBuilder(
                StateMachineAction.CREATE,
                preImage, witnessFundingTxId, witnessPadding,
                null, null, null, 0, null, null,
                null, null, null, 0, 0, 0);
    }

    public static PP1SmUnlockBuilder forEnroll(
            byte[] preImage, byte[] pp2Output, PublicKey merchantPubKey,
            byte[] changePKH, long changeAmount,
            byte[] eventData,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] witnessPadding) {
        return new PP1SmUnlockBuilder(
                StateMachineAction.ENROLL,
                preImage, null, witnessPadding,
                pp2Output, merchantPubKey, changePKH, changeAmount,
                tokenLHS, prevTokenTx,
                eventData, null, null, 0, 0, 0);
    }

    public static PP1SmUnlockBuilder forConfirm(
            byte[] preImage, byte[] pp2Output, PublicKey merchantPubKey,
            byte[] changePKH, long changeAmount,
            PublicKey customerPubKey, byte[] customerSigBytes,
            byte[] eventData,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] witnessPadding) {
        return new PP1SmUnlockBuilder(
                StateMachineAction.CONFIRM,
                preImage, null, witnessPadding,
                pp2Output, merchantPubKey, changePKH, changeAmount,
                tokenLHS, prevTokenTx,
                eventData, customerPubKey, customerSigBytes, 0, 0, 0);
    }

    public static PP1SmUnlockBuilder forConvert(
            byte[] preImage, byte[] pp2Output, PublicKey merchantPubKey,
            byte[] changePKH, long changeAmount,
            PublicKey customerPubKey, byte[] customerSigBytes,
            byte[] eventData,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] witnessPadding) {
        return new PP1SmUnlockBuilder(
                StateMachineAction.CONVERT,
                preImage, null, witnessPadding,
                pp2Output, merchantPubKey, changePKH, changeAmount,
                tokenLHS, prevTokenTx,
                eventData, customerPubKey, customerSigBytes, 0, 0, 0);
    }

    public static PP1SmUnlockBuilder forSettle(
            byte[] preImage, byte[] pp2Output, PublicKey merchantPubKey,
            byte[] changePKH, long changeAmount,
            long custRewardAmount, long merchPayAmount,
            byte[] eventData,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] witnessPadding) {
        return new PP1SmUnlockBuilder(
                StateMachineAction.SETTLE,
                preImage, null, witnessPadding,
                pp2Output, merchantPubKey, changePKH, changeAmount,
                tokenLHS, prevTokenTx,
                eventData, null, null, custRewardAmount, merchPayAmount, 0);
    }

    public static PP1SmUnlockBuilder forTimeout(
            byte[] preImage, byte[] pp2Output, PublicKey merchantPubKey,
            byte[] changePKH, long changeAmount,
            long refundAmount,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] witnessPadding) {
        return new PP1SmUnlockBuilder(
                StateMachineAction.TIMEOUT,
                preImage, null, witnessPadding,
                pp2Output, merchantPubKey, changePKH, changeAmount,
                tokenLHS, prevTokenTx,
                null, null, null, 0, 0, refundAmount);
    }

    public static PP1SmUnlockBuilder forBurn(PublicKey merchantPubKey) {
        return new PP1SmUnlockBuilder(
                StateMachineAction.BURN,
                null, null, null,
                null, merchantPubKey, null, 0, null, null,
                null, null, null, 0, 0, 0);
    }

    @Override
    public Script getUnlockingScript() {
        switch (action) {
            case CREATE:
                return buildCreate();
            case ENROLL:
                return buildEnroll();
            case CONFIRM:
                return buildConfirm();
            case CONVERT:
                return buildConvert();
            case SETTLE:
                return buildSettle();
            case TIMEOUT:
                return buildTimeout();
            case BURN:
                return buildBurn();
            default:
                return new ScriptBuilder().build();
        }
    }

    private Script buildCreate() {
        ScriptBuilder builder = new ScriptBuilder();
        builder.data(preImage);
        builder.data(witnessFundingTxId);
        builder.data(witnessPadding);
        builder.number(0);
        return builder.build();
    }

    private Script buildEnroll() {
        if (getSignatures().isEmpty()) {
            return new ScriptBuilder().build();
        }
        try {
            ScriptBuilder builder = new ScriptBuilder();
            builder.data(preImage);
            builder.data(pp2Output);
            builder.data(merchantPubKey.getPubKeyBytes());
            builder.data(changePKH);
            builder.number(changeAmount);
            builder.data(getSignatures().get(0).toTxFormat());
            builder.data(eventData);
            builder.data(tokenLHS);
            builder.data(prevTokenTx);
            builder.data(witnessPadding);
            builder.number(1);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }

    private Script buildConfirm() {
        if (getSignatures().isEmpty()) {
            return new ScriptBuilder().build();
        }
        try {
            ScriptBuilder builder = new ScriptBuilder();
            builder.data(preImage);
            builder.data(pp2Output);
            builder.data(merchantPubKey.getPubKeyBytes());
            builder.data(changePKH);
            builder.number(changeAmount);
            builder.data(getSignatures().get(0).toTxFormat());
            builder.data(customerPubKey.getPubKeyBytes());
            builder.data(customerSigBytes);
            builder.data(eventData);
            builder.data(tokenLHS);
            builder.data(prevTokenTx);
            builder.data(witnessPadding);
            builder.number(2);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }

    private Script buildConvert() {
        if (getSignatures().isEmpty()) {
            return new ScriptBuilder().build();
        }
        try {
            ScriptBuilder builder = new ScriptBuilder();
            builder.data(preImage);
            builder.data(pp2Output);
            builder.data(merchantPubKey.getPubKeyBytes());
            builder.data(changePKH);
            builder.number(changeAmount);
            builder.data(getSignatures().get(0).toTxFormat());
            builder.data(customerPubKey.getPubKeyBytes());
            builder.data(customerSigBytes);
            builder.data(eventData);
            builder.data(tokenLHS);
            builder.data(prevTokenTx);
            builder.data(witnessPadding);
            builder.number(3);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }

    private Script buildSettle() {
        if (getSignatures().isEmpty()) {
            return new ScriptBuilder().build();
        }
        try {
            ScriptBuilder builder = new ScriptBuilder();
            builder.data(preImage);
            builder.data(pp2Output);
            builder.data(merchantPubKey.getPubKeyBytes());
            builder.data(changePKH);
            builder.number(changeAmount);
            builder.data(getSignatures().get(0).toTxFormat());
            builder.number(custRewardAmount);
            builder.number(merchPayAmount);
            builder.data(eventData);
            builder.data(tokenLHS);
            builder.data(prevTokenTx);
            builder.data(witnessPadding);
            builder.number(4);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }

    private Script buildTimeout() {
        if (getSignatures().isEmpty()) {
            return new ScriptBuilder().build();
        }
        try {
            ScriptBuilder builder = new ScriptBuilder();
            builder.data(preImage);
            builder.data(pp2Output);
            builder.data(merchantPubKey.getPubKeyBytes());
            builder.data(changePKH);
            builder.number(changeAmount);
            builder.data(getSignatures().get(0).toTxFormat());
            builder.number(refundAmount);
            builder.data(tokenLHS);
            builder.data(prevTokenTx);
            builder.data(witnessPadding);
            builder.number(5);
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
            builder.data(merchantPubKey.getPubKeyBytes());
            builder.data(getSignatures().get(0).toTxFormat());
            builder.number(6);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }
}
