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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * High-level API for creating Appendable Token (PP1_AT) transactions.
 *
 * <p>Supports issuance, stamp, transfer, redeem, and burn operations.
 * Dual authority model: issuer signs issue/stamp, owner signs transfer/redeem/burn.
 *
 * <p>All signing is performed via {@link SigningCallback}, which decouples
 * transaction construction from private key management. The callback receives
 * a sighash digest and returns a DER-encoded signature — compatible with
 * KMS, HSM, hardware wallets, or libspiffy4j's {@code CallbackTransactionSigner}.
 */
public class AppendableTokenTool {

    private final NetworkAddressType networkAddressType;
    private final BigInteger defaultFee;
    private final int sigHashAll;

    public AppendableTokenTool(NetworkAddressType networkAddressType, BigInteger defaultFee) {
        this.networkAddressType = networkAddressType;
        this.defaultFee = defaultFee != null ? defaultFee : BigInteger.valueOf(135);
        this.sigHashAll = SigHashType.FORKID.value | SigHashType.ALL.value;
    }

    public AppendableTokenTool(NetworkAddressType networkAddressType) {
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
     * Creates a witness transaction for an AT token.
     *
     * <p>Produces a 1-output transaction: Witness (locked to current signer).
     * Uses two-pass building with padding recalculation.
     *
     * @param fundingSigner       callback that signs sighash digests for the funding key
     * @param fundingPubKey       public key corresponding to the funding signer
     * @param fundingTx           provides the funding UTXO at output[1]
     * @param tokenTx             the token transaction to witness
     * @param parentTokenTxBytes  raw bytes of the parent token transaction
     * @param pubkey              public key of the signer (issuer for issue/stamp, owner for transfer)
     * @param tokenChangePKH      pubkey hash for the token's change output
     * @param action              specifies the token action
     * @param stampMetadata       required for STAMP action, null otherwise
     */
    /**
     * @deprecated Use the overload with Rabin parameters for issuance witnesses.
     */
    public Transaction createWitnessTxn(
            SigningCallback fundingSigner,
            PublicKey fundingPubKey,
            Transaction fundingTx,
            Transaction tokenTx,
            byte[] parentTokenTxBytes,
            PublicKey pubkey,
            byte[] tokenChangePKH,
            AppendableTokenAction action,
            byte[] stampMetadata)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {
        return createWitnessTxn(fundingSigner, fundingPubKey, fundingTx, tokenTx,
                parentTokenTxBytes, pubkey, tokenChangePKH, action, stampMetadata,
                null, null, 0, null, null);
    }

    public Transaction createWitnessTxn(
            SigningCallback fundingSigner,
            PublicKey fundingPubKey,
            Transaction fundingTx,
            Transaction tokenTx,
            byte[] parentTokenTxBytes,
            PublicKey pubkey,
            byte[] tokenChangePKH,
            AppendableTokenAction action,
            byte[] stampMetadata,
            byte[] rabinN,
            byte[] rabinS,
            int rabinPadding,
            byte[] identityTxId,
            byte[] ed25519PubKey)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        TransactionSigner signer = SignerAdapter.fromCallback(fundingSigner, fundingPubKey, sigHashAll);

        ModP2PKHLockBuilder witnessLocker = new ModP2PKHLockBuilder(pubkey.getPubKeyHash());
        PP2UnlockBuilder pp2Unlocker = PP2UnlockBuilder.forNormal(tokenTx.getTransactionIdBytes());
        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(fundingPubKey);
        DefaultUnlockBuilder emptyUnlocker = new DefaultUnlockBuilder();

        // First pass: build with empty PP1 unlocker to get preimage
        TransactionBuilder preImageBuilder = new TransactionBuilder()
                .spendFromTransaction(signer, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(signer, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
                .spendFromTransaction(tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, pp2Unlocker)
                .spendTo(witnessLocker, BigInteger.ONE);
        preImageBuilder.setFee(BigInteger.valueOf(100));
        Transaction preImageTxn = preImageBuilder.build(false);

        Script subscript = tokenTx.getOutputs().get(1).getScript();
        byte[] preImagePP1 = new SigHash().getSighashPreimage(preImageTxn, sigHashAll, 1, subscript, BigInteger.ONE);

        TransactionUtils tsl1 = new TransactionUtils();
        byte[] tokenTxLHS = tsl1.getTxLHS(tokenTx);
        byte[] paddingBytes = new byte[1];
        byte[] pp2Output = tokenTx.getOutputs().get(2).serialize();
        long tokenChangeAmount = tokenTx.getOutputs().get(0).getAmount().longValue();

        UnlockingScriptBuilder pp1Unlocker = buildPP1AtUnlocker(
                action, preImagePP1, pp2Output, pubkey, tokenChangePKH,
                tokenChangeAmount, tokenTxLHS, parentTokenTxBytes, paddingBytes,
                fundingTx.getTransactionIdBytes(), stampMetadata,
                rabinN, rabinS, rabinPadding, identityTxId, ed25519PubKey);

        Transaction witnessTx = new TransactionBuilder()
                .spendFromTransaction(signer, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(signer, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, pp1Unlocker)
                .spendFromTransaction(tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, pp2Unlocker)
                .spendTo(witnessLocker, BigInteger.ONE)
                .build(false);

        // Recalculate padding
        paddingBytes = tsl1.calculatePaddingBytes(witnessTx);

        pp1Unlocker = buildPP1AtUnlocker(
                action, preImagePP1, pp2Output, pubkey, tokenChangePKH,
                tokenChangeAmount, tokenTxLHS, parentTokenTxBytes, paddingBytes,
                fundingTx.getTransactionIdBytes(), stampMetadata,
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
     * Creates an AT issuance transaction with 5-output structure:
     * Change, PP1_AT, PP2, PartialWitness, Metadata.
     *
     * @param tokenFundingTx       funds the issuance; its txid becomes the initial tokenId
     * @param fundingSigner        callback that signs sighash digests for the funding key
     * @param fundingPubKey        public key corresponding to the funding signer
     * @param recipientAddress     the initial card holder (customer) address
     * @param witnessFundingTxId   txid of the transaction that will fund the first witness
     * @param issuerPKH            20-byte HASH160 of the issuer's (shop) public key
     * @param threshold            stamps required for redemption
     * @param metadataBytes        optional raw metadata to embed in the OP_RETURN output (may be null)
     */
    public Transaction createTokenIssuanceTxn(
            Transaction tokenFundingTx,
            SigningCallback fundingSigner,
            PublicKey fundingPubKey,
            Address recipientAddress,
            byte[] witnessFundingTxId,
            byte[] issuerPKH,
            byte[] rabinPubKeyHash,
            int threshold,
            byte[] metadataBytes)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        TransactionSigner fundingTxSigner = SignerAdapter.fromCallback(fundingSigner, fundingPubKey, sigHashAll);

        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(fundingPubKey);
        TransactionBuilder tokenTxBuilder = new TransactionBuilder();
        byte[] tokenId = tokenFundingTx.getTransactionIdBytes();
        byte[] recipientPKH = recipientAddress.getHash();

        // Initial stamps hash is 32 zero bytes (empty chain)
        byte[] initialStampsHash = new byte[32];

        tokenTxBuilder.spendFromTransaction(fundingTxSigner, tokenFundingTx, 1,
                TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker);
        tokenTxBuilder.withFeePerKb(1);

        // Output 1: PP1_AT
        tokenTxBuilder.spendTo(new PP1AtLockBuilder(recipientPKH, tokenId, issuerPKH,
                rabinPubKeyHash, 0, threshold, initialStampsHash), BigInteger.ONE);

        // Output 2: PP2
        tokenTxBuilder.spendTo(new PP2LockBuilder(getOutpoint(witnessFundingTxId),
                recipientPKH, 1, recipientPKH), BigInteger.ONE);

        // Output 3: PartialWitness
        tokenTxBuilder.spendTo(new PartialWitnessLockBuilder(recipientPKH), BigInteger.ONE);

        // Output 4: Metadata OP_RETURN
        tokenTxBuilder.spendTo(new MetadataLockBuilder(metadataBytes), BigInteger.ZERO);

        tokenTxBuilder.sendChangeTo(recipientAddress);
        return tokenTxBuilder.build(false);
    }

    /**
     * Creates an AT transfer transaction with 5-output structure:
     * Change, PP1_AT, PP2, PartialWitness, Metadata.
     *
     * <p>Owner signs. Only ownerPKH changes in the PP1_AT output.
     * Carries forward issuerPKH, stampCount, threshold, and stampsHash from previous PP1_AT.
     *
     * @param prevWitnessTx               the previous witness transaction
     * @param prevTokenTx                 the parent token transaction
     * @param currentOwnerPubkey          current holder's public key
     * @param recipientAddress            new holder's address
     * @param fundingTx                   transaction that funds this transfer
     * @param fundingSigner               callback that signs sighash digests for the funding key
     * @param fundingPubKey               public key corresponding to the funding signer
     * @param recipientWitnessFundingTxId txid of the tx that will fund the new witness
     * @param tokenId                     persistent token identifier
     * @param issuerPKH                   20-byte HASH160 of the issuer's public key (carried forward)
     * @param stampCount                  current stamp count (carried forward)
     * @param threshold                   stamp threshold (carried forward)
     * @param stampsHash                  32-byte accumulated stamps hash (carried forward)
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
            byte[] issuerPKH,
            int stampCount,
            int threshold,
            byte[] stampsHash)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        TransactionSigner fundingTxSigner = SignerAdapter.fromCallback(fundingSigner, fundingPubKey, sigHashAll);

        Address currentOwnerAddress = Address.fromKey(networkAddressType, currentOwnerPubkey);
        byte[] recipientPKH = recipientAddress.getHash();

        // Extract rabinPubKeyHash from parent PP1_AT script at byte offset [76:96]
        byte[] parentPP1Bytes = prevTokenTx.getOutputs().get(1).getScript().getProgram();
        byte[] rabinPubKeyHash = new byte[20];
        System.arraycopy(parentPP1Bytes, 76, rabinPubKeyHash, 0, 20);

        PP1AtLockBuilder pp1LockBuilder = new PP1AtLockBuilder(recipientPKH, tokenId,
                issuerPKH, rabinPubKeyHash, stampCount, threshold, stampsHash);
        PP2LockBuilder pp2Locker = new PP2LockBuilder(getOutpoint(recipientWitnessFundingTxId),
                recipientPKH, 1, recipientPKH);
        PartialWitnessLockBuilder shaLocker = new PartialWitnessLockBuilder(recipientPKH);

        // Carry forward metadata from parent token tx (output[4])
        DefaultLockBuilder metadataLocker = new DefaultLockBuilder(prevTokenTx.getOutputs().get(4).getScript());

        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(fundingPubKey);
        ModP2PKHUnlockBuilder prevWitnessUnlocker = new ModP2PKHUnlockBuilder(currentOwnerPubkey);
        DefaultUnlockBuilder emptyUnlocker = new DefaultUnlockBuilder();

        // First pass: empty PP3 unlocker to get preimage
        TransactionBuilder childPreImageBuilder = new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
                .spendFromTransaction(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
                .spendTo(pp1LockBuilder, BigInteger.ONE)
                .spendTo(pp2Locker, BigInteger.ONE)
                .spendTo(shaLocker, BigInteger.ONE)
                .spendTo(metadataLocker, BigInteger.ZERO)
                .sendChangeTo(currentOwnerAddress);
        childPreImageBuilder.setFee(defaultFee);
        Transaction childPreImageTxn = childPreImageBuilder.build(false);

        Script pp3Subscript = prevTokenTx.getOutputs().get(3).getScript();
        byte[] sigPreImage = new SigHash().getSighashPreimage(childPreImageTxn, sigHashAll, 2, pp3Subscript, BigInteger.ONE);

        TransactionUtils tsl1 = new TransactionUtils();
        byte[][] partialResult = tsl1.computePartialHash(prevWitnessTx.serialize(), 2);

        PartialWitnessUnlockBuilder sha256Unlocker = PartialWitnessUnlockBuilder.forUnlock(
                sigPreImage, partialResult[0], partialResult[1], fundingTx.getTransactionIdBytes());

        // Final build with PP3 unlocker
        TransactionBuilder finalBuilder = new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
                .spendFromTransaction(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, sha256Unlocker)
                .spendTo(pp1LockBuilder, BigInteger.ONE)
                .spendTo(pp2Locker, BigInteger.ONE)
                .spendTo(shaLocker, BigInteger.ONE)
                .spendTo(metadataLocker, BigInteger.ZERO)
                .sendChangeTo(currentOwnerAddress);
        finalBuilder.setFee(defaultFee);
        return finalBuilder.build(false);
    }

    /**
     * Creates a stamp transaction that adds a stamp to the AT token.
     *
     * <p>Issuer signs. Updates stampCount (+1) and stampsHash (rolling SHA256):
     * <pre>
     *   newStamp = SHA256(stampMetadata)
     *   newStampsHash = SHA256(parentStampsHash || newStamp)
     * </pre>
     *
     * @param prevWitnessTx               the previous witness transaction
     * @param prevTokenTx                 the parent token transaction
     * @param issuerPubkey                the issuer (shop) public key
     * @param fundingTx                   funds the stamp transaction
     * @param fundingSigner               callback that signs sighash digests for the funding key
     * @param fundingPubKey               public key corresponding to the funding signer
     * @param issuerWitnessFundingTxId    txid of the tx that will fund the stamp witness
     * @param stampMetadata               arbitrary data for this stamp (e.g., receipt hash)
     * @param ownerPKH                    20-byte HASH160 of the current token owner (carried forward)
     * @param tokenId                     persistent token identifier (carried forward)
     * @param issuerPKH                   20-byte HASH160 of the issuer's public key (carried forward)
     * @param parentStampCount            current stamp count from previous PP1_AT
     * @param threshold                   stamp threshold (carried forward)
     * @param parentStampsHash            32-byte accumulated stamps hash from previous PP1_AT
     */
    public Transaction createTokenStampTxn(
            Transaction prevWitnessTx,
            Transaction prevTokenTx,
            PublicKey issuerPubkey,
            Transaction fundingTx,
            SigningCallback fundingSigner,
            PublicKey fundingPubKey,
            byte[] issuerWitnessFundingTxId,
            byte[] stampMetadata,
            byte[] ownerPKH,
            byte[] tokenId,
            byte[] issuerPKH,
            int parentStampCount,
            int threshold,
            byte[] parentStampsHash)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        TransactionSigner fundingTxSigner = SignerAdapter.fromCallback(fundingSigner, fundingPubKey, sigHashAll);

        Address issuerAddress = Address.fromKey(networkAddressType, issuerPubkey);

        // Compute new stamp values off-chain
        MessageDigest sha256 = getSha256();
        byte[] newStamp = sha256.digest(stampMetadata);
        sha256.reset();
        sha256.update(parentStampsHash);
        sha256.update(newStamp);
        byte[] newStampsHash = sha256.digest();
        int newStampCount = parentStampCount + 1;

        // Extract rabinPubKeyHash from parent PP1_AT script at byte offset [76:96]
        byte[] parentPP1Bytes = prevTokenTx.getOutputs().get(1).getScript().getProgram();
        byte[] rabinPubKeyHash = new byte[20];
        System.arraycopy(parentPP1Bytes, 76, rabinPubKeyHash, 0, 20);

        // Build new PP1_AT with updated stampCount and stampsHash (ownerPKH unchanged)
        PP1AtLockBuilder pp1LockBuilder = new PP1AtLockBuilder(ownerPKH, tokenId, issuerPKH,
                rabinPubKeyHash, newStampCount, threshold, newStampsHash);

        PP2LockBuilder pp2Locker = new PP2LockBuilder(getOutpoint(issuerWitnessFundingTxId),
                ownerPKH, 1, ownerPKH);
        PartialWitnessLockBuilder shaLocker = new PartialWitnessLockBuilder(ownerPKH);

        // Carry forward metadata from parent token tx (output[4])
        DefaultLockBuilder metadataLocker = new DefaultLockBuilder(prevTokenTx.getOutputs().get(4).getScript());

        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(fundingPubKey);
        ModP2PKHUnlockBuilder prevWitnessUnlocker = new ModP2PKHUnlockBuilder(issuerPubkey);
        DefaultUnlockBuilder emptyUnlocker = new DefaultUnlockBuilder();

        // First pass: empty PP3 unlocker to get preimage
        TransactionBuilder childPreImageBuilder = new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
                .spendFromTransaction(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
                .spendTo(pp1LockBuilder, BigInteger.ONE)
                .spendTo(pp2Locker, BigInteger.ONE)
                .spendTo(shaLocker, BigInteger.ONE)
                .spendTo(metadataLocker, BigInteger.ZERO)
                .sendChangeTo(issuerAddress);
        childPreImageBuilder.setFee(defaultFee);
        Transaction childPreImageTxn = childPreImageBuilder.build(false);

        Script pp3Subscript = prevTokenTx.getOutputs().get(3).getScript();
        byte[] sigPreImage = new SigHash().getSighashPreimage(childPreImageTxn, sigHashAll, 2, pp3Subscript, BigInteger.ONE);

        TransactionUtils tsl1 = new TransactionUtils();
        byte[][] partialResult = tsl1.computePartialHash(prevWitnessTx.serialize(), 2);

        PartialWitnessUnlockBuilder sha256Unlocker = PartialWitnessUnlockBuilder.forUnlock(
                sigPreImage, partialResult[0], partialResult[1], fundingTx.getTransactionIdBytes());

        // Final build with PP3 unlocker
        TransactionBuilder finalBuilder = new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
                .spendFromTransaction(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, sha256Unlocker)
                .spendTo(pp1LockBuilder, BigInteger.ONE)
                .spendTo(pp2Locker, BigInteger.ONE)
                .spendTo(shaLocker, BigInteger.ONE)
                .spendTo(metadataLocker, BigInteger.ZERO)
                .sendChangeTo(issuerAddress);
        finalBuilder.setFee(defaultFee);
        return finalBuilder.build(false);
    }

    /**
     * Creates a burn transaction that destroys an AT token.
     *
     * <p>Owner signs. Spends PP1_AT, PP2, and PartialWitness outputs.
     *
     * @param tokenTx          the token transaction to burn
     * @param ownerCallback    callback that signs sighash digests for the owner key
     * @param ownerPubkey      the owner's public key
     * @param fundingTx        the funding transaction
     * @param fundingCallback  callback that signs sighash digests for the funding key
     * @param fundingPubKey    public key corresponding to the funding signer
     */
    public Transaction createBurnTokenTxn(
            Transaction tokenTx,
            SigningCallback ownerCallback,
            PublicKey ownerPubkey,
            Transaction fundingTx,
            SigningCallback fundingCallback,
            PublicKey fundingPubKey)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        TransactionSigner ownerSigner = SignerAdapter.fromCallback(ownerCallback, ownerPubkey, sigHashAll);
        TransactionSigner fundingTxSigner = SignerAdapter.fromCallback(fundingCallback, fundingPubKey, sigHashAll);

        Address ownerAddress = Address.fromKey(networkAddressType, ownerPubkey);
        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(fundingPubKey);

        TransactionBuilder builder = new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(ownerSigner, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, PP1AtUnlockBuilder.forBurn(ownerPubkey))
                .spendFromTransaction(ownerSigner, tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, PP2UnlockBuilder.forBurn(ownerPubkey))
                .spendFromTransaction(ownerSigner, tokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, PartialWitnessUnlockBuilder.forBurn(ownerPubkey))
                .sendChangeTo(ownerAddress);
        builder.setFee(defaultFee);
        return builder.build(false);
    }

    /**
     * Creates a redeem transaction for an AT token.
     *
     * <p>Owner signs. Burns the token (threshold must be met).
     * Spends PP1_AT, PP2, and PartialWitness outputs.
     *
     * @param tokenTx          the token transaction to redeem
     * @param ownerCallback    callback that signs sighash digests for the owner key
     * @param ownerPubkey      the owner's public key
     * @param fundingTx        the funding transaction
     * @param fundingCallback  callback that signs sighash digests for the funding key
     * @param fundingPubKey    public key corresponding to the funding signer
     */
    public Transaction createRedeemTokenTxn(
            Transaction tokenTx,
            SigningCallback ownerCallback,
            PublicKey ownerPubkey,
            Transaction fundingTx,
            SigningCallback fundingCallback,
            PublicKey fundingPubKey)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        TransactionSigner ownerSigner = SignerAdapter.fromCallback(ownerCallback, ownerPubkey, sigHashAll);
        TransactionSigner fundingTxSigner = SignerAdapter.fromCallback(fundingCallback, fundingPubKey, sigHashAll);

        Address ownerAddress = Address.fromKey(networkAddressType, ownerPubkey);
        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(fundingPubKey);

        TransactionBuilder builder = new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(ownerSigner, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, PP1AtUnlockBuilder.forRedeem(ownerPubkey))
                .spendFromTransaction(ownerSigner, tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, PP2UnlockBuilder.forBurn(ownerPubkey))
                .spendFromTransaction(ownerSigner, tokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, PartialWitnessUnlockBuilder.forBurn(ownerPubkey))
                .sendChangeTo(ownerAddress);
        builder.setFee(defaultFee);
        return builder.build(false);
    }

    // --- Private helpers ---

    private UnlockingScriptBuilder buildPP1AtUnlocker(
            AppendableTokenAction action, byte[] preImage, byte[] pp2Output,
            PublicKey pubkey, byte[] changePKH, long changeAmount,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] paddingBytes,
            byte[] fundingTxHash, byte[] stampMetadata,
            byte[] rabinN, byte[] rabinS, int rabinPadding,
            byte[] identityTxId, byte[] ed25519PubKey) {

        switch (action) {
            case ISSUANCE:
                return PP1AtUnlockBuilder.forIssuance(
                        preImage, fundingTxHash, paddingBytes, pubkey,
                        rabinN != null ? rabinN : new byte[0],
                        rabinS != null ? rabinS : new byte[0],
                        rabinPadding,
                        identityTxId != null ? identityTxId : new byte[0],
                        ed25519PubKey != null ? ed25519PubKey : new byte[0]);
            case STAMP:
                return PP1AtUnlockBuilder.forStamp(
                        preImage, pp2Output, pubkey,
                        changePKH, changeAmount,
                        tokenLHS, prevTokenTx, paddingBytes,
                        stampMetadata);
            case TRANSFER:
                return PP1AtUnlockBuilder.forTransfer(
                        preImage, pp2Output, pubkey,
                        changePKH, changeAmount,
                        tokenLHS, prevTokenTx, paddingBytes);
            default:
                throw new IllegalArgumentException("Unsupported action for witness: " + action);
        }
    }

    private static MessageDigest getSha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}
