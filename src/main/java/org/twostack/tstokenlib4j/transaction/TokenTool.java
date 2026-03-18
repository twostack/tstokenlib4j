package org.twostack.tstokenlib4j.transaction;

import org.twostack.bitcoin4j.Address;
import org.twostack.bitcoin4j.PublicKey;
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
 *
 * <p>All signing is performed via {@link SigningCallback}, which decouples
 * transaction construction from private key management. The callback receives
 * a sighash digest and returns a DER-encoded signature — compatible with
 * KMS, HSM, hardware wallets, or libspiffy4j's {@code CallbackTransactionSigner}.
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
     *
     * @param fundingSigner    callback that signs sighash digests for the funding key
     * @param fundingPubKey    public key corresponding to the funding signer
     * @param fundingTx        the funding transaction providing satoshis
     * @param tokenTx          the token transaction being witnessed
     * @param parentTokenTxBytes raw bytes of the parent token transaction
     * @param ownerPubkey      the token owner's public key
     * @param tokenChangePKH   PKH for token change output
     * @param action           ISSUANCE or TRANSFER
     * @param rabinN           Rabin public key N (for issuance identity)
     * @param rabinS           Rabin signature S (for issuance identity)
     * @param rabinPadding     Rabin signature padding
     * @param identityTxId     identity anchor transaction ID
     * @param ed25519PubKey    Ed25519 public key for identity
     * @return the witness transaction
     */
    public Transaction createWitnessTxn(
            SigningCallback fundingSigner,
            PublicKey fundingPubKey,
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

        TransactionSigner signer = SignerAdapter.fromCallback(fundingSigner, fundingPubKey, sigHashAll);

        ModP2PKHLockBuilder witnessLocker = new ModP2PKHLockBuilder(ownerPubkey.getPubKeyHash());
        PP2UnlockBuilder pp2Unlocker = PP2UnlockBuilder.forNormal(tokenTx.getTransactionIdBytes());
        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(fundingPubKey);
        DefaultUnlockBuilder emptyUnlocker = new DefaultUnlockBuilder();

        // First pass: build with empty PP1 unlocker to get preimage
        Transaction preImageTxn = new TransactionBuilder()
                .spendFromTransaction(signer, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(signer, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
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
                .spendFromTransaction(signer, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(signer, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, pp1Unlocker)
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
                .spendFromTransaction(signer, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(signer, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, pp1Unlocker)
                .spendFromTransaction(tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, pp2Unlocker)
                .spendTo(witnessLocker, BigInteger.ONE)
                .build(false);

        return witnessTx;
    }

    /**
     * Creates a token issuance transaction with 5-output structure:
     * Change, PP1, PP2, PartialWitness, Metadata.
     *
     * @param tokenFundingTx     the funding transaction
     * @param fundingSigner      callback that signs sighash digests
     * @param fundingPubKey      public key corresponding to the funding signer
     * @param recipientAddress   the token recipient's address
     * @param witnessFundingTxId transaction ID for the witness funding outpoint
     * @param rabinPubKeyHash    HASH160 of the issuer's Rabin public key N
     * @param metadataBytes      metadata payload for the OP_RETURN output
     * @return the issuance transaction (5 outputs)
     */
    public Transaction createTokenIssuanceTxn(
            Transaction tokenFundingTx,
            SigningCallback fundingSigner,
            PublicKey fundingPubKey,
            Address recipientAddress,
            byte[] witnessFundingTxId,
            byte[] rabinPubKeyHash,
            byte[] metadataBytes)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        TransactionSigner signer = SignerAdapter.fromCallback(fundingSigner, fundingPubKey, sigHashAll);

        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(fundingPubKey);
        TransactionBuilder tokenTxBuilder = new TransactionBuilder();
        byte[] tokenId = tokenFundingTx.getTransactionIdBytes();
        byte[] recipientPKH = recipientAddress.getHash();

        tokenTxBuilder.spendFromTransaction(signer, tokenFundingTx, 1,
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
     *
     * @param prevWitnessTx              the previous witness transaction
     * @param prevTokenTx                the previous token transaction
     * @param currentOwnerPubkey         the current owner's public key (signs witness input)
     * @param recipientAddress           the new owner's address
     * @param fundingTx                  the funding transaction
     * @param fundingSigner              callback that signs sighash digests for the funding key
     * @param fundingPubKey              public key corresponding to the funding signer
     * @param recipientWitnessFundingTxId txid for the recipient's witness funding outpoint
     * @param tokenId                    the token identifier (32 bytes)
     * @param rabinPubKeyHash            HASH160 of the issuer's Rabin public key N
     * @return the transfer transaction (5 outputs)
     */
    public Transaction createTokenTransferTxn(
            Transaction prevWitnessTx,
            Transaction prevTokenTx,
            PublicKey currentOwnerPubkey,
            Address recipientAddress,
            Transaction fundingTx,
            SigningCallback fundingSigner,
            PublicKey fundingPubKey,
            byte[] recipientWitnessFundingTxId,
            byte[] tokenId,
            byte[] rabinPubKeyHash)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        TransactionSigner signer = SignerAdapter.fromCallback(fundingSigner, fundingPubKey, sigHashAll);

        Address currentOwnerAddress = Address.fromKey(networkAddressType, currentOwnerPubkey);
        byte[] recipientPKH = recipientAddress.getHash();

        PP1NftLockBuilder pp1LockBuilder = new PP1NftLockBuilder(recipientPKH, tokenId, rabinPubKeyHash);
        PP2LockBuilder pp2Locker = new PP2LockBuilder(getOutpoint(recipientWitnessFundingTxId), recipientPKH, 1, recipientPKH);
        PartialWitnessLockBuilder shaLocker = new PartialWitnessLockBuilder(recipientPKH);

        // Carry forward metadata from parent token tx (output[4])
        DefaultLockBuilder metadataLocker = new DefaultLockBuilder(prevTokenTx.getOutputs().get(4).getScript());

        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(fundingPubKey);
        ModP2PKHUnlockBuilder prevWitnessUnlocker = new ModP2PKHUnlockBuilder(currentOwnerPubkey);
        DefaultUnlockBuilder emptyUnlocker = new DefaultUnlockBuilder();

        // First pass: empty PP3 unlocker to get preimage
        Transaction childPreImageTxn = new TransactionBuilder()
                .spendFromTransaction(signer, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(signer, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
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
                .spendFromTransaction(signer, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(signer, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
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
     *
     * @param tokenTx         the token transaction to burn
     * @param ownerSigner     callback that signs for the token owner
     * @param ownerPubkey     the token owner's public key
     * @param fundingTx       the funding transaction
     * @param fundingSigner   callback that signs for the funding key
     * @param fundingPubKey   public key corresponding to the funding signer
     * @return the burn transaction
     */
    public Transaction createBurnTokenTxn(
            Transaction tokenTx,
            SigningCallback ownerSigner,
            PublicKey ownerPubkey,
            Transaction fundingTx,
            SigningCallback fundingSigner,
            PublicKey fundingPubKey)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        TransactionSigner fundingSgn = SignerAdapter.fromCallback(fundingSigner, fundingPubKey, sigHashAll);
        TransactionSigner ownerSgn = SignerAdapter.fromCallback(ownerSigner, ownerPubkey, sigHashAll);

        Address ownerAddress = Address.fromKey(networkAddressType, ownerPubkey);
        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(fundingPubKey);

        return new TransactionBuilder()
                .spendFromTransaction(fundingSgn, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(ownerSgn, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, PP1NftUnlockBuilder.forBurn(ownerPubkey))
                .spendFromTransaction(ownerSgn, tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, PP2UnlockBuilder.forBurn(ownerPubkey))
                .spendFromTransaction(ownerSgn, tokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, PartialWitnessUnlockBuilder.forBurn(ownerPubkey))
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
