package org.twostack.tstokenlib4j.transaction;

import org.twostack.bitcoin4j.Address;
import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.address.LegacyAddress;
import org.twostack.bitcoin4j.exception.SigHashException;
import org.twostack.bitcoin4j.exception.SignatureDecodeException;
import org.twostack.bitcoin4j.exception.TransactionException;
import org.twostack.bitcoin4j.params.NetworkAddressType;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.transaction.*;

import org.twostack.tstokenlib4j.lock.*;
import org.twostack.tstokenlib4j.unlock.*;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * High-level API for creating NFT token transactions (issuance, transfer, witness, burn).
 *
 * <p>Encapsulates the construction of multi-output token transactions that conform
 * to the TSL1 protocol's proof-carrying transaction structure.
 */
public class TokenTool {

    private final NetworkAddressType networkAddressType;
    private final BigInteger defaultFee;
    private final int sigHashAll;

    public TokenTool(NetworkAddressType networkAddressType, BigInteger defaultFee) {
        this.networkAddressType = networkAddressType;
        this.defaultFee = defaultFee != null ? defaultFee : BigInteger.valueOf(135);
        this.sigHashAll = SigHashType.FORKID.value | SigHashType.ALL.value;
    }

    public TokenTool(NetworkAddressType networkAddressType) {
        this(networkAddressType, null);
    }

    /**
     * Constructs a 36-byte outpoint from a transaction ID and output index.
     */
    public byte[] getOutpoint(byte[] txId, int outputIndex) {
        ByteBuffer buf = ByteBuffer.allocate(36);
        buf.order(ByteOrder.LITTLE_ENDIAN);
        buf.put(txId);
        buf.putInt(outputIndex);
        return buf.array();
    }

    public byte[] getOutpoint(byte[] txId) {
        return getOutpoint(txId, 1);
    }

    /**
     * Creates a witness transaction that proves ownership of a token.
     *
     * <p>Produces a 1-output transaction: Witness (locked to current token holder).
     * Uses two-pass building with padding recalculation.
     */
    public Transaction createWitnessTxn(
            TransactionSigner fundingSigner,
            Transaction fundingTx,
            Transaction tokenTx,
            byte[] parentTokenTxBytes,
            PublicKey ownerPubkey,
            byte[] tokenChangePKH,
            TokenAction action,
            byte[] rabinN,
            byte[] rabinS,
            long rabinPadding,
            byte[] identityTxId,
            byte[] ed25519PubKey)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        ModP2PKHLockBuilder witnessLocker = new ModP2PKHLockBuilder(ownerPubkey.getPubKeyHash());
        PP2UnlockBuilder pp2Unlocker = PP2UnlockBuilder.forNormal(tokenTx.getTransactionIdBytes());
        DefaultUnlockBuilder fundingUnlocker = new DefaultUnlockBuilder();
        DefaultUnlockBuilder emptyUnlocker = new DefaultUnlockBuilder();

        // First pass: build with empty PP1 unlocker to get preimage
        Transaction preImageTxn = new TransactionBuilder()
                .spendFromTransaction(fundingSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingSigner, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
                .spendFromTransaction(tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, pp2Unlocker)
                .spendTo(witnessLocker, BigInteger.ONE)
                .build(false);

        Script subscript = tokenTx.getOutputs().get(1).getScript();
        byte[] preImagePP1 = new SigHash().getSighashPreimage(preImageTxn, sigHashAll, 1, subscript, BigInteger.ONE);

        TransactionUtils tsl1 = new TransactionUtils();
        byte[] tokenTxLHS = tsl1.getTxLHS(tokenTx);
        byte[] paddingBytes = new byte[1];
        byte[] pp2Output = tokenTx.getOutputs().get(2).serialize();
        long tokenChangeAmount = tokenTx.getOutputs().get(0).getAmount().longValue();

        UnlockingScriptBuilder pp1Unlocker = buildPP1NftUnlocker(
                action, preImagePP1, pp2Output, ownerPubkey, tokenChangePKH,
                tokenChangeAmount, tokenTxLHS, parentTokenTxBytes, paddingBytes,
                fundingTx.getTransactionIdBytes(),
                rabinN, rabinS, rabinPadding, identityTxId, ed25519PubKey);

        Transaction witnessTx = new TransactionBuilder()
                .spendFromTransaction(fundingSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingSigner, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, pp1Unlocker)
                .spendFromTransaction(tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, pp2Unlocker)
                .spendTo(witnessLocker, BigInteger.ONE)
                .build(false);

        // Recalculate padding
        paddingBytes = tsl1.calculatePaddingBytes(witnessTx);

        pp1Unlocker = buildPP1NftUnlocker(
                action, preImagePP1, pp2Output, ownerPubkey, tokenChangePKH,
                tokenChangeAmount, tokenTxLHS, parentTokenTxBytes, paddingBytes,
                fundingTx.getTransactionIdBytes(),
                rabinN, rabinS, rabinPadding, identityTxId, ed25519PubKey);

        witnessTx = new TransactionBuilder()
                .spendFromTransaction(fundingSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingSigner, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, pp1Unlocker)
                .spendFromTransaction(tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, pp2Unlocker)
                .spendTo(witnessLocker, BigInteger.ONE)
                .build(false);

        return witnessTx;
    }

    /**
     * Creates a token issuance transaction with 5-output structure:
     * Change, PP1, PP2, PartialWitness, Metadata.
     */
    public Transaction createTokenIssuanceTxn(
            Transaction tokenFundingTx,
            TransactionSigner fundingTxSigner,
            Address recipientAddress,
            byte[] witnessFundingTxId,
            byte[] rabinPubKeyHash,
            byte[] metadataBytes)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        DefaultUnlockBuilder fundingUnlocker = new DefaultUnlockBuilder();
        TransactionBuilder tokenTxBuilder = new TransactionBuilder();
        byte[] tokenId = tokenFundingTx.getTransactionIdBytes();
        byte[] recipientPKH = recipientAddress.getHash();

        tokenTxBuilder.spendFromTransaction(fundingTxSigner, tokenFundingTx, 1,
                TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker);
        tokenTxBuilder.withFeePerKb(1);

        // Output 1: PP1 NFT
        tokenTxBuilder.spendTo(new PP1NftLockBuilder(recipientPKH, tokenId, rabinPubKeyHash), BigInteger.ONE);

        // Output 2: PP2
        tokenTxBuilder.spendTo(new PP2LockBuilder(getOutpoint(witnessFundingTxId), recipientPKH, 1, recipientPKH), BigInteger.ONE);

        // Output 3: PartialWitness
        tokenTxBuilder.spendTo(new PartialWitnessLockBuilder(recipientPKH), BigInteger.ONE);

        // Output 4: Metadata OP_RETURN
        tokenTxBuilder.spendTo(new MetadataLockBuilder(metadataBytes), BigInteger.ZERO);

        tokenTxBuilder.sendChangeTo(recipientAddress);
        return tokenTxBuilder.build(false);
    }

    /**
     * Creates a token transfer transaction with 5-output structure:
     * Change, PP1, PP2, PartialWitness, Metadata.
     *
     * <p>Metadata is carried forward from the parent token transaction.
     */
    public Transaction createTokenTransferTxn(
            Transaction prevWitnessTx,
            Transaction prevTokenTx,
            PublicKey currentOwnerPubkey,
            Address recipientAddress,
            Transaction fundingTx,
            TransactionSigner fundingTxSigner,
            byte[] recipientWitnessFundingTxId,
            byte[] tokenId,
            byte[] rabinPubKeyHash)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        Address currentOwnerAddress = Address.fromKey(networkAddressType, currentOwnerPubkey);
        byte[] recipientPKH = recipientAddress.getHash();

        PP1NftLockBuilder pp1LockBuilder = new PP1NftLockBuilder(recipientPKH, tokenId, rabinPubKeyHash);
        PP2LockBuilder pp2Locker = new PP2LockBuilder(getOutpoint(recipientWitnessFundingTxId), recipientPKH, 1, recipientPKH);
        PartialWitnessLockBuilder shaLocker = new PartialWitnessLockBuilder(recipientPKH);

        // Carry forward metadata from parent token tx (output[4])
        DefaultLockBuilder metadataLocker = new DefaultLockBuilder(prevTokenTx.getOutputs().get(4).getScript());

        DefaultUnlockBuilder fundingUnlocker = new DefaultUnlockBuilder();
        ModP2PKHUnlockBuilder prevWitnessUnlocker = new ModP2PKHUnlockBuilder(currentOwnerPubkey);
        DefaultUnlockBuilder emptyUnlocker = new DefaultUnlockBuilder();

        // First pass: empty PP3 unlocker to get preimage
        Transaction childPreImageTxn = new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
                .spendFromTransaction(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
                .spendTo(pp1LockBuilder, BigInteger.ONE)
                .spendTo(pp2Locker, BigInteger.ONE)
                .spendTo(shaLocker, BigInteger.ONE)
                .spendTo(metadataLocker, BigInteger.ZERO)
                .sendChangeTo(currentOwnerAddress)
                .build(false);

        Script pp3Subscript = prevTokenTx.getOutputs().get(3).getScript();
        byte[] sigPreImage = new SigHash().getSighashPreimage(childPreImageTxn, sigHashAll, 2, pp3Subscript, BigInteger.ONE);

        TransactionUtils tsl1 = new TransactionUtils();
        byte[][] partialResult = tsl1.computePartialHash(prevWitnessTx.serialize(), 2);

        PartialWitnessUnlockBuilder sha256Unlocker = PartialWitnessUnlockBuilder.forUnlock(
                sigPreImage, partialResult[0], partialResult[1], fundingTx.getTransactionIdBytes());

        // Final build with PP3 unlocker
        return new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
                .spendFromTransaction(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, sha256Unlocker)
                .spendTo(pp1LockBuilder, BigInteger.ONE)
                .spendTo(pp2Locker, BigInteger.ONE)
                .spendTo(shaLocker, BigInteger.ONE)
                .spendTo(metadataLocker, BigInteger.ZERO)
                .sendChangeTo(currentOwnerAddress)
                .build(false);
    }

    /**
     * Creates a burn transaction that destroys a token by spending all its proof outputs.
     */
    public Transaction createBurnTokenTxn(
            Transaction tokenTx,
            TransactionSigner ownerSigner,
            PublicKey ownerPubkey,
            Transaction fundingTx,
            TransactionSigner fundingTxSigner)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        Address ownerAddress = Address.fromKey(networkAddressType, ownerPubkey);
        DefaultUnlockBuilder fundingUnlocker = new DefaultUnlockBuilder();

        return new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(ownerSigner, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, PP1NftUnlockBuilder.forBurn(ownerPubkey))
                .spendFromTransaction(ownerSigner, tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, PP2UnlockBuilder.forBurn(ownerPubkey))
                .spendFromTransaction(ownerSigner, tokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, PartialWitnessUnlockBuilder.forBurn(ownerPubkey))
                .sendChangeTo(ownerAddress)
                .build(false);
    }

    // --- Private helpers ---

    private UnlockingScriptBuilder buildPP1NftUnlocker(
            TokenAction action, byte[] preImage, byte[] pp2Output,
            PublicKey ownerPubkey, byte[] changePKH, long changeAmount,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] paddingBytes,
            byte[] fundingTxHash,
            byte[] rabinN, byte[] rabinS, long rabinPadding,
            byte[] identityTxId, byte[] ed25519PubKey) {

        if (action == TokenAction.ISSUANCE) {
            return PP1NftUnlockBuilder.forIssuance(
                    preImage, fundingTxHash, paddingBytes,
                    rabinN, rabinS, rabinPadding,
                    identityTxId, ed25519PubKey);
        } else {
            return PP1NftUnlockBuilder.forTransfer(
                    preImage, pp2Output, ownerPubkey,
                    changePKH, changeAmount,
                    tokenLHS, prevTokenTx, paddingBytes);
        }
    }
}
