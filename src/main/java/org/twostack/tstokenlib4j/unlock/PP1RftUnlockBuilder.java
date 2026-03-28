package org.twostack.tstokenlib4j.unlock;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptBuilder;
import org.twostack.bitcoin4j.transaction.UnlockingScriptBuilder;

import java.io.IOException;

/**
 * Builds the unlocking script for a PP1 Restricted Fungible Token (RFT) locking script.
 *
 * <p>Supported actions:
 * <ul>
 *   <li>{@link RestrictedFungibleTokenAction#MINT} -- initial token minting with Rabin identity binding</li>
 *   <li>{@link RestrictedFungibleTokenAction#TRANSFER} -- full-amount transfer to a new holder</li>
 *   <li>{@link RestrictedFungibleTokenAction#SPLIT_TRANSFER} -- partial transfer, splitting the token amount</li>
 *   <li>{@link RestrictedFungibleTokenAction#MERGE} -- merge two token UTXOs into one</li>
 *   <li>{@link RestrictedFungibleTokenAction#REDEEM} -- redeem the token back to the issuer</li>
 *   <li>{@link RestrictedFungibleTokenAction#BURN} -- permanent destruction of the token</li>
 * </ul>
 *
 * <p>Instances are created through the static factory methods {@link #forMint},
 * {@link #forTransfer}, {@link #forSplitTransfer}, {@link #forMerge}, {@link #forRedeem},
 * and {@link #forBurn}. The constructor is private.
 *
 * <p>The TRANSFER, SPLIT_TRANSFER, MERGE, REDEEM, and BURN actions require a signature to be
 * added via {@link #addSignature(TransactionSignature)} before {@link #getUnlockingScript()}
 * will produce a non-empty script. The MINT action does not require a signature.
 *
 * <p>The last item pushed onto the script stack is always the action's opValue integer.
 */
public class PP1RftUnlockBuilder extends UnlockingScriptBuilder {

    private final RestrictedFungibleTokenAction action;
    private final byte[] preImage;
    private final byte[] witnessFundingOutpoint;
    private final byte[] witnessPadding;
    private final byte[] pp2Output;
    // NOTE: ownerPubKey and changePKH serve distinct roles in lock script execution.
    // ownerPubKey (33-byte compressed pubkey) is consumed by OP_CHECKSIG to verify the
    // transaction signature. changePKH (20-byte HASH160) is used for output-structure
    // verification — the lock script checks that the token TX's change output pays to this
    // hash via the sighash preimage. These cannot be consolidated because HASH160 is one-way
    // and the lock script needs both forms at different execution stages.
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

    // Merkle whitelist fields (TRANSFER + SPLIT)
    private final byte[] transferRecipientPKH;
    private final byte[] merkleProof;
    private final byte[] merkleSides;

    // MINT extras (Rabin identity binding)
    private final byte[] rabinN;
    private final byte[] rabinS;
    private final long rabinPadding;
    private final byte[] identityTxId;
    private final byte[] ed25519PubKey;

    private PP1RftUnlockBuilder(
            RestrictedFungibleTokenAction action,
            byte[] preImage, byte[] witnessFundingOutpoint, byte[] witnessPadding,
            byte[] pp2Output, PublicKey ownerPubKey,
            byte[] changePKH, long changeAmount,
            byte[] tokenLHS, byte[] prevTokenTx,
            int parentOutputCount, int parentPP1FtIndex,
            byte[] pp2ChangeOutput, long recipientAmount, long tokenChangeAmount,
            byte[] recipientPKH, int myOutputIndex,
            byte[] prevTokenTxB, int parentOutputCountB, int parentPP1FtIndexB,
            byte[] rabinN, byte[] rabinS, long rabinPadding,
            byte[] identityTxId, byte[] ed25519PubKey,
            byte[] transferRecipientPKH, byte[] merkleProof, byte[] merkleSides) {
        this.action = action;
        this.preImage = preImage;
        this.witnessFundingOutpoint = witnessFundingOutpoint;
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
        this.rabinN = rabinN;
        this.rabinS = rabinS;
        this.rabinPadding = rabinPadding;
        this.identityTxId = identityTxId;
        this.ed25519PubKey = ed25519PubKey;
        this.transferRecipientPKH = transferRecipientPKH;
        this.merkleProof = merkleProof;
        this.merkleSides = merkleSides;
    }

    /**
     * Creates a builder for the MINT action. No signature is required.
     *
     * @param preImage            sighash preimage of the transaction for OP_PUSH_TX validation
     * @param witnessFundingOutpoint  36-byte outpoint (txid + vout LE) of the witness funding UTXO
     * @param witnessPadding      padding bytes for witness transaction alignment
     * @param rabinN              Rabin signature public key N component
     * @param rabinS              Rabin signature S component
     * @param rabinPadding        padding value for Rabin signature verification
     * @param identityTxId        transaction ID anchoring the token's identity
     * @param ed25519PubKey       Ed25519 public key for identity verification
     * @return a new builder configured for minting
     */
    public static PP1RftUnlockBuilder forMint(
            byte[] preImage, byte[] witnessFundingOutpoint, byte[] witnessPadding,
            byte[] rabinN, byte[] rabinS, long rabinPadding,
            byte[] identityTxId, byte[] ed25519PubKey) {
        return new PP1RftUnlockBuilder(
                RestrictedFungibleTokenAction.MINT,
                preImage, witnessFundingOutpoint, witnessPadding,
                null, null, null, 0, null, null,
                0, 0,
                null, 0, 0, null, 0,
                null, 0, 0,
                rabinN, rabinS, rabinPadding, identityTxId, ed25519PubKey,
                null, null, null);
    }

    /**
     * Creates a builder for the TRANSFER action. Requires {@link #addSignature(TransactionSignature)}
     * before {@link #getUnlockingScript()} produces output.
     *
     * @param preImage           sighash preimage of the transaction for OP_PUSH_TX validation
     * @param pp2Output          serialized PP2 witness output for output structure verification
     * @param ownerPubKey        public key of the current token owner
     * @param changePKH          20-byte HASH160 for witness change output
     * @param changeAmount       satoshi amount for witness change
     * @param tokenLHS           left-hand side of serialized token output for structure verification
     * @param prevTokenTx        raw bytes of previous token transaction for inductive proof
     * @param witnessPadding     padding bytes for witness transaction alignment
     * @param parentOutputCount  number of outputs in the parent transaction
     * @param parentPP1FtIndex   index of the PP1 FT output in the parent transaction
     * @return a new builder configured for transfer
     */
    public static PP1RftUnlockBuilder forTransfer(
            byte[] preImage, byte[] pp2Output, PublicKey ownerPubKey,
            byte[] changePKH, long changeAmount,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] witnessPadding,
            int parentOutputCount, int parentPP1FtIndex,
            byte[] transferRecipientPKH, byte[] merkleProof, byte[] merkleSides) {
        return new PP1RftUnlockBuilder(
                RestrictedFungibleTokenAction.TRANSFER,
                preImage, null, witnessPadding,
                pp2Output, ownerPubKey, changePKH, changeAmount,
                tokenLHS, prevTokenTx,
                parentOutputCount, parentPP1FtIndex,
                null, 0, 0, null, 0,
                null, 0, 0,
                null, null, 0, null, null,
                transferRecipientPKH, merkleProof, merkleSides);
    }

    /**
     * Creates a builder for the SPLIT_TRANSFER action. Requires {@link #addSignature(TransactionSignature)}
     * before {@link #getUnlockingScript()} produces output.
     *
     * @param preImage             sighash preimage of the transaction for OP_PUSH_TX validation
     * @param pp2RecipientOutput   serialized PP2 witness output for the recipient
     * @param pp2ChangeOutput      serialized PP2 witness output for the token change
     * @param ownerPubKey          public key of the current token owner
     * @param changePKH            20-byte HASH160 for witness change output
     * @param changeAmount         satoshi amount for witness change
     * @param tokenLHS             left-hand side of serialized token output for structure verification
     * @param prevTokenTx          raw bytes of previous token transaction for inductive proof
     * @param witnessPadding       padding bytes for witness transaction alignment
     * @param recipientAmount      satoshi amount being sent to the recipient
     * @param tokenChangeAmount    satoshi amount remaining as token change
     * @param recipientPKH         20-byte HASH160 of the recipient's public key
     * @param myOutputIndex        index of this token's output in the transaction
     * @param parentOutputCount    number of outputs in the parent transaction
     * @param parentPP1FtIndex     index of the PP1 FT output in the parent transaction
     * @return a new builder configured for split transfer
     */
    public static PP1RftUnlockBuilder forSplitTransfer(
            byte[] preImage, byte[] pp2RecipientOutput, byte[] pp2ChangeOutput,
            PublicKey ownerPubKey, byte[] changePKH, long changeAmount,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] witnessPadding,
            long recipientAmount, long tokenChangeAmount,
            byte[] recipientPKH, int myOutputIndex,
            int parentOutputCount, int parentPP1FtIndex,
            byte[] merkleProof, byte[] merkleSides) {
        return new PP1RftUnlockBuilder(
                RestrictedFungibleTokenAction.SPLIT_TRANSFER,
                preImage, null, witnessPadding,
                pp2RecipientOutput, ownerPubKey, changePKH, changeAmount,
                tokenLHS, prevTokenTx,
                parentOutputCount, parentPP1FtIndex,
                pp2ChangeOutput, recipientAmount, tokenChangeAmount,
                recipientPKH, myOutputIndex,
                null, 0, 0,
                null, null, 0, null, null,
                null, merkleProof, merkleSides);
    }

    /**
     * Creates a builder for the MERGE action. Requires {@link #addSignature(TransactionSignature)}
     * before {@link #getUnlockingScript()} produces output.
     *
     * @param preImage            sighash preimage of the transaction for OP_PUSH_TX validation
     * @param pp2Output           serialized PP2 witness output for output structure verification
     * @param ownerPubKey         public key of the current token owner
     * @param changePKH           20-byte HASH160 for witness change output
     * @param changeAmount        satoshi amount for witness change
     * @param tokenLHS            left-hand side of serialized token output for structure verification
     * @param prevTokenTxA        raw bytes of the first previous token transaction for inductive proof
     * @param prevTokenTxB        raw bytes of the second previous token transaction for inductive proof
     * @param witnessPadding      padding bytes for witness transaction alignment
     * @param parentOutputCountA  number of outputs in the first parent transaction
     * @param parentOutputCountB  number of outputs in the second parent transaction
     * @param parentPP1FtIndexA   index of the PP1 FT output in the first parent transaction
     * @param parentPP1FtIndexB   index of the PP1 FT output in the second parent transaction
     * @return a new builder configured for merge
     */
    public static PP1RftUnlockBuilder forMerge(
            byte[] preImage, byte[] pp2Output, PublicKey ownerPubKey,
            byte[] changePKH, long changeAmount,
            byte[] tokenLHS, byte[] prevTokenTxA, byte[] prevTokenTxB,
            byte[] witnessPadding,
            int parentOutputCountA, int parentOutputCountB,
            int parentPP1FtIndexA, int parentPP1FtIndexB) {
        return new PP1RftUnlockBuilder(
                RestrictedFungibleTokenAction.MERGE,
                preImage, null, witnessPadding,
                pp2Output, ownerPubKey, changePKH, changeAmount,
                tokenLHS, prevTokenTxA,
                parentOutputCountA, parentPP1FtIndexA,
                null, 0, 0, null, 0,
                prevTokenTxB, parentOutputCountB, parentPP1FtIndexB,
                null, null, 0, null, null,
                null, null, null);
    }

    /**
     * Creates a builder for the REDEEM action. Requires {@link #addSignature(TransactionSignature)}
     * before {@link #getUnlockingScript()} produces output.
     *
     * @param ownerPubKey public key of the current token owner
     * @return a new builder configured for redemption
     */
    public static PP1RftUnlockBuilder forRedeem(PublicKey ownerPubKey) {
        return new PP1RftUnlockBuilder(
                RestrictedFungibleTokenAction.REDEEM,
                null, null, null,
                null, ownerPubKey, null, 0, null, null,
                0, 0,
                null, 0, 0, null, 0,
                null, 0, 0,
                null, null, 0, null, null,
                null, null, null);
    }

    /**
     * Creates a builder for the BURN action. Requires {@link #addSignature(TransactionSignature)}
     * before {@link #getUnlockingScript()} produces output.
     *
     * @param ownerPubKey public key of the current token owner
     * @return a new builder configured for burn
     */
    public static PP1RftUnlockBuilder forBurn(PublicKey ownerPubKey) {
        return new PP1RftUnlockBuilder(
                RestrictedFungibleTokenAction.BURN,
                null, null, null,
                null, ownerPubKey, null, 0, null, null,
                0, 0,
                null, 0, 0, null, 0,
                null, 0, 0,
                null, null, 0, null, null,
                null, null, null);
    }

    /**
     * Builds and returns the unlocking script by dispatching to the appropriate
     * private build method based on the configured {@link RestrictedFungibleTokenAction}.
     *
     * <p>For TRANSFER, SPLIT_TRANSFER, MERGE, REDEEM, and BURN, if no signature has been
     * added an empty script is returned. The last item pushed is always the action's opValue
     * integer (MINT=0, TRANSFER=1, SPLIT_TRANSFER=2, MERGE=3, REDEEM=4, BURN=5).
     *
     * @return the unlocking {@link Script}, or an empty script when prerequisites are not met
     */
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
            case REDEEM:
                return buildRedeem();
            case BURN:
                return buildBurn();
            default:
                return new ScriptBuilder().build();
        }
    }

    private Script buildMint() {
        ScriptBuilder builder = new ScriptBuilder();
        builder.data(preImage);
        builder.data(witnessFundingOutpoint);
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
            builder.number(parentOutputCount);
            builder.number(parentPP1FtIndex);
            builder.data(transferRecipientPKH != null ? transferRecipientPKH : new byte[0]);
            builder.data(merkleProof != null ? merkleProof : new byte[0]);
            builder.data(merkleSides != null ? merkleSides : new byte[0]);
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
            builder.data(merkleProof != null ? merkleProof : new byte[0]);
            builder.data(merkleSides != null ? merkleSides : new byte[0]);
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

    private Script buildRedeem() {
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

    private Script buildBurn() {
        if (getSignatures().isEmpty()) {
            return new ScriptBuilder().build();
        }
        try {
            ScriptBuilder builder = new ScriptBuilder();
            builder.data(ownerPubKey.getPubKeyBytes());
            builder.data(getSignatures().get(0).toTxFormat());
            builder.number(5);
            return builder.build();
        } catch (IOException e) {
            return new ScriptBuilder().build();
        }
    }
}
