package org.twostack.tstokenlib4j.unlock;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptBuilder;
import org.twostack.bitcoin4j.transaction.UnlockingScriptBuilder;

import java.io.IOException;

public class PP1RnftUnlockBuilder extends UnlockingScriptBuilder {

    private final RestrictedTokenAction action;
    private final byte[] preImage;
    private final byte[] witnessFundingTxId;
    private final byte[] witnessPadding;
    private final byte[] pp2Output;
    private final PublicKey ownerPubKey;
    private final byte[] changePKH;
    private final long changeAmount;
    private final byte[] tokenLHS;
    private final byte[] prevTokenTx;

    // ISSUANCE extras (Rabin identity binding)
    private final byte[] rabinN;
    private final byte[] rabinS;
    private final long rabinPadding;
    private final byte[] identityTxId;
    private final byte[] ed25519PubKey;

    private PP1RnftUnlockBuilder(
            RestrictedTokenAction action,
            byte[] preImage, byte[] witnessFundingTxId, byte[] witnessPadding,
            byte[] pp2Output, PublicKey ownerPubKey,
            byte[] changePKH, long changeAmount,
            byte[] tokenLHS, byte[] prevTokenTx,
            byte[] rabinN, byte[] rabinS, long rabinPadding,
            byte[] identityTxId, byte[] ed25519PubKey) {
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
        this.rabinN = rabinN;
        this.rabinS = rabinS;
        this.rabinPadding = rabinPadding;
        this.identityTxId = identityTxId;
        this.ed25519PubKey = ed25519PubKey;
    }

    public static PP1RnftUnlockBuilder forIssuance(
            byte[] preImage, byte[] witnessFundingTxId, byte[] witnessPadding,
            byte[] rabinN, byte[] rabinS, long rabinPadding,
            byte[] identityTxId, byte[] ed25519PubKey) {
        return new PP1RnftUnlockBuilder(
                RestrictedTokenAction.ISSUANCE,
                preImage, witnessFundingTxId, witnessPadding,
                null, null, null, 0, null, null,
                rabinN, rabinS, rabinPadding, identityTxId, ed25519PubKey);
    }

    public static PP1RnftUnlockBuilder forTransfer(
            byte[] preImage, byte[] pp2Output, PublicKey ownerPubKey,
            byte[] changePKH, long changeAmount,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] witnessPadding) {
        return new PP1RnftUnlockBuilder(
                RestrictedTokenAction.TRANSFER,
                preImage, null, witnessPadding,
                pp2Output, ownerPubKey, changePKH, changeAmount,
                tokenLHS, prevTokenTx,
                null, null, 0, null, null);
    }

    public static PP1RnftUnlockBuilder forRedeem(PublicKey ownerPubKey) {
        return new PP1RnftUnlockBuilder(
                RestrictedTokenAction.REDEEM,
                null, null, null,
                null, ownerPubKey, null, 0, null, null,
                null, null, 0, null, null);
    }

    public static PP1RnftUnlockBuilder forBurn(PublicKey ownerPubKey) {
        return new PP1RnftUnlockBuilder(
                RestrictedTokenAction.BURN,
                null, null, null,
                null, ownerPubKey, null, 0, null, null,
                null, null, 0, null, null);
    }

    @Override
    public Script getUnlockingScript() {
        switch (action) {
            case ISSUANCE:
                return buildIssuance();
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
        ScriptBuilder builder = new ScriptBuilder();
        builder.data(preImage);
        builder.data(witnessFundingTxId);
        builder.data(witnessPadding);
        builder.data(rabinN);
        builder.data(rabinS);
        builder.number(rabinPadding);
        builder.data(identityTxId);
        builder.data(ed25519PubKey);
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
            builder.number(1);
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
            builder.number(3);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }
}
