package org.twostack.tstokenlib4j.transaction;

import org.twostack.bitcoin4j.Address;
import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.exception.SigHashException;
import org.twostack.bitcoin4j.exception.SignatureDecodeException;
import org.twostack.bitcoin4j.exception.TransactionException;
import org.twostack.bitcoin4j.params.NetworkAddressType;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.transaction.*;

import org.twostack.tstokenlib4j.crypto.Rabin;
import org.twostack.tstokenlib4j.crypto.RabinKeyPair;
import org.twostack.tstokenlib4j.crypto.RabinSignature;
import org.twostack.tstokenlib4j.lock.*;
import org.twostack.tstokenlib4j.unlock.*;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * High-level API for creating Restricted Fungible Token (RFT) transactions
 * (mint, transfer, split, merge, witness, redeem, burn).
 *
 * <p>Encapsulates the construction of multi-output token transactions that conform
 * to the TSL1 protocol's proof-carrying transaction structure with restricted
 * transfer policy enforcement via the flags byte in the PP1_RFT locking script.
 *
 * <p>All signing is performed via {@link SigningCallback}, which decouples
 * transaction construction from private key management. The callback receives
 * a sighash digest and returns a DER-encoded signature — compatible with
 * KMS, HSM, hardware wallets, or libspiffy4j's {@code CallbackTransactionSigner}.
 */
public class RestrictedFungibleTokenTool {

    private final NetworkAddressType networkAddressType;
    private final BigInteger defaultFee;
    private final int sigHashAll;

    public RestrictedFungibleTokenTool(NetworkAddressType networkAddressType, BigInteger defaultFee) {
        this.networkAddressType = networkAddressType;
        this.defaultFee = defaultFee != null ? defaultFee : BigInteger.valueOf(135);
        this.sigHashAll = SigHashType.FORKID.value | SigHashType.ALL.value;
    }

    public RestrictedFungibleTokenTool(NetworkAddressType networkAddressType) {
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
     * Creates a 5-output RFT mint transaction.
     *
     * <p>Outputs: [Change, PP1_RFT, PP2-FT, PP3-FT, Metadata]
     *
     * @param tokenFundingTx     funds the mint; its txid becomes the tokenId
     * @param fundingSigner      callback that signs sighash digests for the funding key
     * @param fundingPubKey      public key corresponding to the funding signer
     * @param recipientAddress   address of the token recipient
     * @param witnessFundingTxId txid of the transaction funding the first witness
     * @param rabinPubKeyHash    20-byte HASH160 of the Rabin public key
     * @param flags              transfer policy flags
     * @param amount             initial token supply
     * @param metadataBytes      metadata for the OP_RETURN output
     * @return the mint transaction
     */
    public Transaction createFungibleMintTxn(
            Transaction tokenFundingTx,
            SigningCallback fundingSigner,
            PublicKey fundingPubKey,
            Address recipientAddress,
            byte[] witnessFundingTxId,
            byte[] rabinPubKeyHash,
            int flags,
            long amount,
            byte[] metadataBytes)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        TransactionSigner fundingTxSigner = SignerAdapter.fromCallback(fundingSigner, fundingPubKey, sigHashAll);

        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(fundingPubKey);
        TransactionBuilder tokenTxBuilder = new TransactionBuilder();
        byte[] tokenId = tokenFundingTx.getTransactionIdBytes();
        byte[] recipientPKH = recipientAddress.getHash();

        tokenTxBuilder.spendFromTransaction(fundingTxSigner, tokenFundingTx, 1,
                TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker);
        tokenTxBuilder.withFeePerKb(1);

        // Output 1: PP1_RFT
        tokenTxBuilder.spendTo(new PP1RftLockBuilder(recipientPKH, tokenId, rabinPubKeyHash, flags, amount), BigInteger.ONE);

        // Output 2: PP2-FT
        tokenTxBuilder.spendTo(new PP2FtLockBuilder(
                getOutpoint(witnessFundingTxId), recipientPKH, 1, recipientPKH, 1, 2), BigInteger.ONE);

        // Output 3: PP3-FT
        tokenTxBuilder.spendTo(new PartialWitnessFtLockBuilder(recipientPKH), BigInteger.ONE);

        // Output 4: Metadata OP_RETURN
        tokenTxBuilder.spendTo(new MetadataLockBuilder(metadataBytes), BigInteger.ZERO);

        tokenTxBuilder.sendChangeTo(recipientAddress);
        return tokenTxBuilder.build(false);
    }

    /**
     * Creates a burn transaction that destroys an RFT token.
     *
     * <p>Spends PP1_RFT (output[1]), PP2-FT (output[2]), and PP3-FT (output[3])
     * from the token transaction. Change is sent back to the owner.
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

        return new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(ownerSigner, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, PP1RftUnlockBuilder.forBurn(ownerPubkey))
                .spendFromTransaction(ownerSigner, tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, PP2FtUnlockBuilder.forBurn(ownerPubkey))
                .spendFromTransaction(ownerSigner, tokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, PartialWitnessFtUnlockBuilder.forBurn(ownerPubkey))
                .sendChangeTo(ownerAddress)
                .build(false);
    }

    /**
     * Creates a redeem transaction for an RFT token.
     *
     * <p>Spends PP1_RFT (output[1]), PP2-FT (output[2]), and PP3-FT (output[3])
     * from the token transaction. Change is sent back to the owner.
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

        return new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(ownerSigner, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, PP1RftUnlockBuilder.forRedeem(ownerPubkey))
                .spendFromTransaction(ownerSigner, tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, PP2FtUnlockBuilder.forBurn(ownerPubkey))
                .spendFromTransaction(ownerSigner, tokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, PartialWitnessFtUnlockBuilder.forBurn(ownerPubkey))
                .sendChangeTo(ownerAddress)
                .build(false);
    }

    /**
     * Creates a witness transaction for an RFT token.
     *
     * <p>Produces a 1-output transaction: Witness (locked to current token holder).
     * Spends PP1_RFT and PP2-FT from the token transaction.
     *
     * <p>For MINT: {@code rabinKeyPair}, {@code identityTxId}, {@code ed25519PubKey} are required.
     * For TRANSFER: {@code parentTokenTxBytes} and {@code parentOutputCount} are required.
     *
     * @param fundingSigner        callback that signs sighash digests for the funding key
     * @param fundingPubKey        public key corresponding to the funding signer
     * @param fundingTx            the funding transaction
     * @param tokenTx              the token transaction being witnessed
     * @param ownerPubkey          public key of the current token owner
     * @param tokenChangePKH       20-byte HASH160 for token change output
     * @param action               the witness action (MINT, TRANSFER, SPLIT_TRANSFER, MERGE)
     * @param parentTokenTxBytes   raw bytes of the parent token transaction (for TRANSFER/SPLIT/MERGE)
     * @param parentOutputCount    number of outputs in the parent transaction
     * @param tripletBaseIndex     base index of the token triplet (default 1)
     * @param parentPP1FtIndex     index of the PP1 FT output in the parent transaction
     * @param rabinKeyPair         Rabin key pair for MINT signing
     * @param identityTxId         identity transaction ID for MINT
     * @param ed25519PubKey        Ed25519 public key for MINT
     * @param parentTokenTxBytesB  raw bytes of the second parent token transaction (for MERGE)
     * @param parentOutputCountB   number of outputs in the second parent transaction (for MERGE)
     * @param parentPP1FtIndexB    index of the PP1 FT output in the second parent (for MERGE)
     * @param recipientAmount      recipient token amount (for SPLIT_TRANSFER)
     * @param tokenChangeAmount    token change amount (for SPLIT_TRANSFER)
     * @param recipientPKH         recipient public key hash (for SPLIT_TRANSFER)
     * @return the witness transaction
     */
    public Transaction createRftWitnessTxn(
            SigningCallback fundingSigner,
            PublicKey fundingPubKey,
            Transaction fundingTx,
            Transaction tokenTx,
            PublicKey ownerPubkey,
            byte[] tokenChangePKH,
            RestrictedFungibleTokenAction action,
            byte[] parentTokenTxBytes,
            int parentOutputCount,
            int tripletBaseIndex,
            int parentPP1FtIndex,
            RabinKeyPair rabinKeyPair,
            byte[] identityTxId,
            byte[] ed25519PubKey,
            byte[] parentTokenTxBytesB,
            int parentOutputCountB,
            int parentPP1FtIndexB,
            long recipientAmount,
            long tokenChangeAmount,
            byte[] recipientPKH)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        TransactionSigner signer = SignerAdapter.fromCallback(fundingSigner, fundingPubKey, sigHashAll);

        int pp1FtIndex = tripletBaseIndex;
        int pp2Index = tripletBaseIndex + 1;

        ModP2PKHLockBuilder witnessLocker = new ModP2PKHLockBuilder(ownerPubkey.getPubKeyHash());
        PP2FtUnlockBuilder pp2FtUnlocker = PP2FtUnlockBuilder.forNormal(tokenTx.getTransactionIdBytes());
        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(fundingPubKey);
        DefaultUnlockBuilder emptyUnlocker = new DefaultUnlockBuilder();

        // First pass: build with empty PP1_RFT unlocker to get preimage
        Transaction preImageTxn = new TransactionBuilder()
                .spendFromTransaction(signer, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(signer, tokenTx, pp1FtIndex, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
                .spendFromTransaction(tokenTx, pp2Index, TransactionInput.MAX_SEQ_NUMBER, pp2FtUnlocker)
                .spendTo(witnessLocker, BigInteger.ONE)
                .build(false);

        Script subscript = tokenTx.getOutputs().get(pp1FtIndex).getScript();
        byte[] preImage = new SigHash().getSighashPreimage(preImageTxn, sigHashAll, 1, subscript, BigInteger.ONE);

        TransactionUtils tsl1 = new TransactionUtils();
        byte[] tokenTxLHS = tsl1.getTxLHS(tokenTx);
        byte[] paddingBytes = new byte[1];

        // Build PP1_RFT unlocker and rebuild with padding (two passes)
        UnlockingScriptBuilder pp1RftUnlocker = buildPP1RftUnlocker(
                action, preImage, tokenTx, ownerPubkey, tokenChangePKH,
                tokenTxLHS, parentTokenTxBytes, paddingBytes,
                parentOutputCount, tripletBaseIndex, fundingTx.getTransactionIdBytes(),
                parentPP1FtIndex, rabinKeyPair, identityTxId, ed25519PubKey,
                parentTokenTxBytesB, parentOutputCountB, parentPP1FtIndexB,
                recipientAmount, tokenChangeAmount, recipientPKH);

        Transaction witnessTx = buildWitnessTxn(signer, fundingTx, tokenTx,
                pp1FtIndex, pp2Index, ownerPubkey, pp1RftUnlocker, pp2FtUnlocker, witnessLocker);

        // Recalculate padding
        paddingBytes = tsl1.calculatePaddingBytes(witnessTx);

        pp1RftUnlocker = buildPP1RftUnlocker(
                action, preImage, tokenTx, ownerPubkey, tokenChangePKH,
                tokenTxLHS, parentTokenTxBytes, paddingBytes,
                parentOutputCount, tripletBaseIndex, fundingTx.getTransactionIdBytes(),
                parentPP1FtIndex, rabinKeyPair, identityTxId, ed25519PubKey,
                parentTokenTxBytesB, parentOutputCountB, parentPP1FtIndexB,
                recipientAmount, tokenChangeAmount, recipientPKH);

        witnessTx = buildWitnessTxn(signer, fundingTx, tokenTx,
                pp1FtIndex, pp2Index, ownerPubkey, pp1RftUnlocker, pp2FtUnlocker, witnessLocker);

        return witnessTx;
    }

    /**
     * Creates an RFT transfer transaction (5 outputs, full balance transfer).
     *
     * <p>Outputs: [Change, PP1_RFT, PP2-FT, PP3-FT, Metadata]
     *
     * <p>Spends: FundingUTXO, previous Witness output, and PP3-FT from the previous token transaction.
     * Metadata is carried forward from the parent token transaction (last output).
     *
     * @param prevWitnessTx              the previous witness transaction
     * @param prevTokenTx                the previous token transaction
     * @param currentOwnerPubkey         public key of the current token owner
     * @param recipientAddress           address of the token recipient
     * @param fundingTx                  the funding transaction
     * @param fundingSigner              callback that signs sighash digests for the funding key
     * @param fundingPubKey              public key corresponding to the funding signer
     * @param recipientWitnessFundingTxId txid of the transaction funding the recipient's witness
     * @param tokenId                    32-byte token identifier
     * @param rabinPubKeyHash            20-byte HASH160 of the Rabin public key
     * @param flags                      transfer policy flags
     * @param amount                     full token balance being transferred
     * @param prevTripletBaseIndex       base index of the previous token triplet (default 1)
     * @return the transfer transaction
     */
    public Transaction createRftTransferTxn(
            Transaction prevWitnessTx,
            Transaction prevTokenTx,
            PublicKey currentOwnerPubkey,
            Address recipientAddress,
            Transaction fundingTx,
            SigningCallback fundingSigner,
            PublicKey fundingPubKey,
            byte[] recipientWitnessFundingTxId,
            byte[] tokenId,
            byte[] rabinPubKeyHash,
            int flags,
            long amount,
            int prevTripletBaseIndex)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        TransactionSigner fundingTxSigner = SignerAdapter.fromCallback(fundingSigner, fundingPubKey, sigHashAll);

        Address currentOwnerAddress = Address.fromKey(networkAddressType, currentOwnerPubkey);
        byte[] recipientPKH = recipientAddress.getHash();
        int prevPP3Index = prevTripletBaseIndex + 2;

        // Build output lockers
        PP1RftLockBuilder pp1RftLocker = new PP1RftLockBuilder(recipientPKH, tokenId, rabinPubKeyHash, flags, amount);
        PP2FtLockBuilder pp2FtLocker = new PP2FtLockBuilder(
                getOutpoint(recipientWitnessFundingTxId), recipientPKH, 1, recipientPKH, 1, 2);
        PartialWitnessFtLockBuilder pp3FtLocker = new PartialWitnessFtLockBuilder(recipientPKH);

        // Carry forward metadata from parent token tx (last output)
        DefaultLockBuilder metadataLocker = new DefaultLockBuilder(
                prevTokenTx.getOutputs().get(prevTokenTx.getOutputs().size() - 1).getScript());

        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(fundingPubKey);
        ModP2PKHUnlockBuilder prevWitnessUnlocker = new ModP2PKHUnlockBuilder(currentOwnerPubkey);
        DefaultUnlockBuilder emptyUnlocker = new DefaultUnlockBuilder();

        // First pass: build with empty PP3-FT unlocker to get preimage
        Transaction childPreImageTxn = new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
                .spendFromTransaction(prevTokenTx, prevPP3Index, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
                .spendTo(pp1RftLocker, BigInteger.ONE)
                .spendTo(pp2FtLocker, BigInteger.ONE)
                .spendTo(pp3FtLocker, BigInteger.ONE)
                .spendTo(metadataLocker, BigInteger.ZERO)
                .sendChangeTo(currentOwnerAddress)
                .build(false);

        Script pp3Subscript = prevTokenTx.getOutputs().get(prevPP3Index).getScript();
        byte[] sigPreImage = new SigHash().getSighashPreimage(childPreImageTxn, sigHashAll, 2, pp3Subscript, BigInteger.ONE);

        TransactionUtils tsl1 = new TransactionUtils();
        byte[][] partialResult = tsl1.computePartialHash(prevWitnessTx.serialize(), 2);

        PartialWitnessFtUnlockBuilder pp3FtUnlocker = PartialWitnessFtUnlockBuilder.forUnlock(
                sigPreImage, partialResult[0], partialResult[1], fundingTx.getTransactionIdBytes());

        // Final build with PP3-FT unlocker
        return new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
                .spendFromTransaction(prevTokenTx, prevPP3Index, TransactionInput.MAX_SEQ_NUMBER, pp3FtUnlocker)
                .spendTo(pp1RftLocker, BigInteger.ONE)
                .spendTo(pp2FtLocker, BigInteger.ONE)
                .spendTo(pp3FtLocker, BigInteger.ONE)
                .spendTo(metadataLocker, BigInteger.ZERO)
                .sendChangeTo(currentOwnerAddress)
                .build(false);
    }

    /**
     * Creates an 8-output RFT split transfer transaction.
     *
     * <p>Outputs: [Change, PP1_RFT-recv, PP2FT-recv, PP3FT-recv, PP1_RFT-change, PP2FT-change, PP3FT-change, Metadata]
     *
     * <p>{@code sendAmount} tokens go to the recipient, remainder stays with the sender.
     * {@code totalAmount} is the full token balance being split (must equal sendAmount + change).
     *
     * @param prevWitnessTx               the previous witness transaction
     * @param prevTokenTx                 the previous token transaction
     * @param currentOwnerPubkey          public key of the current token owner
     * @param recipientAddress            address of the token recipient
     * @param sendAmount                  token amount being sent to the recipient
     * @param fundingTx                   the funding transaction
     * @param fundingSigner               callback that signs sighash digests for the funding key
     * @param fundingPubKey               public key corresponding to the funding signer
     * @param recipientWitnessFundingTxId txid of the transaction funding the recipient's witness
     * @param changeWitnessFundingTxId    txid of the transaction funding the sender's change witness
     * @param tokenId                     32-byte token identifier
     * @param rabinPubKeyHash             20-byte HASH160 of the Rabin public key
     * @param flags                       transfer policy flags
     * @param totalAmount                 full token balance being split
     * @param prevTripletBaseIndex        base index of the previous token triplet (default 1)
     * @return the split transfer transaction
     */
    public Transaction createRftSplitTxn(
            Transaction prevWitnessTx,
            Transaction prevTokenTx,
            PublicKey currentOwnerPubkey,
            Address recipientAddress,
            long sendAmount,
            Transaction fundingTx,
            SigningCallback fundingSigner,
            PublicKey fundingPubKey,
            byte[] recipientWitnessFundingTxId,
            byte[] changeWitnessFundingTxId,
            byte[] tokenId,
            byte[] rabinPubKeyHash,
            int flags,
            long totalAmount,
            int prevTripletBaseIndex)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        TransactionSigner fundingTxSigner = SignerAdapter.fromCallback(fundingSigner, fundingPubKey, sigHashAll);

        Address currentOwnerAddress = Address.fromKey(networkAddressType, currentOwnerPubkey);
        byte[] recipientPKH = recipientAddress.getHash();
        byte[] senderPKH = currentOwnerAddress.getHash();
        long changeTokenAmount = totalAmount - sendAmount;
        int prevPP3Index = prevTripletBaseIndex + 2;

        // Recipient triplet (outputs 1,2,3)
        PP1RftLockBuilder pp1RftRecipientLocker = new PP1RftLockBuilder(recipientPKH, tokenId, rabinPubKeyHash, flags, sendAmount);
        PP2FtLockBuilder pp2FtRecipientLocker = new PP2FtLockBuilder(
                getOutpoint(recipientWitnessFundingTxId), recipientPKH, 1, recipientPKH, 1, 2);
        PartialWitnessFtLockBuilder pp3FtRecipientLocker = new PartialWitnessFtLockBuilder(recipientPKH);

        // Change triplet (outputs 4,5,6)
        PP1RftLockBuilder pp1RftChangeLocker = new PP1RftLockBuilder(senderPKH, tokenId, rabinPubKeyHash, flags, changeTokenAmount);
        PP2FtLockBuilder pp2FtChangeLocker = new PP2FtLockBuilder(
                getOutpoint(changeWitnessFundingTxId), senderPKH, 1, senderPKH, 4, 5);
        PartialWitnessFtLockBuilder pp3FtChangeLocker = new PartialWitnessFtLockBuilder(senderPKH);

        // Metadata (carried forward from parent, last output)
        DefaultLockBuilder metadataLocker = new DefaultLockBuilder(
                prevTokenTx.getOutputs().get(prevTokenTx.getOutputs().size() - 1).getScript());

        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(fundingPubKey);
        ModP2PKHUnlockBuilder prevWitnessUnlocker = new ModP2PKHUnlockBuilder(currentOwnerPubkey);
        DefaultUnlockBuilder emptyUnlocker = new DefaultUnlockBuilder();

        // First pass: empty PP3-FT unlocker to get preimage
        Transaction childPreImageTxn = new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
                .spendFromTransaction(prevTokenTx, prevPP3Index, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
                .spendTo(pp1RftRecipientLocker, BigInteger.ONE)
                .spendTo(pp2FtRecipientLocker, BigInteger.ONE)
                .spendTo(pp3FtRecipientLocker, BigInteger.ONE)
                .spendTo(pp1RftChangeLocker, BigInteger.ONE)
                .spendTo(pp2FtChangeLocker, BigInteger.ONE)
                .spendTo(pp3FtChangeLocker, BigInteger.ONE)
                .spendTo(metadataLocker, BigInteger.ZERO)
                .sendChangeTo(currentOwnerAddress)
                .build(false);

        Script pp3Subscript = prevTokenTx.getOutputs().get(prevPP3Index).getScript();
        byte[] sigPreImage = new SigHash().getSighashPreimage(childPreImageTxn, sigHashAll, 2, pp3Subscript, BigInteger.ONE);

        TransactionUtils tsl1 = new TransactionUtils();
        byte[][] partialResult = tsl1.computePartialHash(prevWitnessTx.serialize(), 2);

        PartialWitnessFtUnlockBuilder pp3FtUnlocker = PartialWitnessFtUnlockBuilder.forUnlock(
                sigPreImage, partialResult[0], partialResult[1], fundingTx.getTransactionIdBytes());

        // Final build with PP3-FT unlocker
        return new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
                .spendFromTransaction(prevTokenTx, prevPP3Index, TransactionInput.MAX_SEQ_NUMBER, pp3FtUnlocker)
                .spendTo(pp1RftRecipientLocker, BigInteger.ONE)
                .spendTo(pp2FtRecipientLocker, BigInteger.ONE)
                .spendTo(pp3FtRecipientLocker, BigInteger.ONE)
                .spendTo(pp1RftChangeLocker, BigInteger.ONE)
                .spendTo(pp2FtChangeLocker, BigInteger.ONE)
                .spendTo(pp3FtChangeLocker, BigInteger.ONE)
                .spendTo(metadataLocker, BigInteger.ZERO)
                .sendChangeTo(currentOwnerAddress)
                .build(false);
    }

    /**
     * Creates a 5-output RFT merge transaction combining two token triplets.
     *
     * <p>Inputs: [funding(0), witnessA(1), witnessB(2), PP3_A_burn(3), PP3_B_burn(4)]
     * <p>Outputs: [Change, PP1_RFT_merged, PP2-FT, PP3-FT, Metadata]
     *
     * <p>Both triplets must be owned by the same key and have the same tokenId.
     *
     * @param prevWitnessTxA          the first previous witness transaction
     * @param prevTokenTxA            the first previous token transaction
     * @param prevWitnessTxB          the second previous witness transaction
     * @param prevTokenTxB            the second previous token transaction
     * @param currentOwnerPubkey      public key of the current token owner
     * @param ownerCallback           callback that signs sighash digests for the owner key
     * @param fundingTx               the funding transaction
     * @param fundingCallback         callback that signs sighash digests for the funding key
     * @param fundingPubKey           public key corresponding to the funding signer
     * @param mergedWitnessFundingTxId txid of the transaction funding the merged witness
     * @param tokenId                 32-byte token identifier
     * @param rabinPubKeyHash         20-byte HASH160 of the Rabin public key
     * @param flags                   transfer policy flags
     * @param totalAmount             combined token amount from both triplets
     * @param prevTripletBaseIndexA   base index of the first token triplet (default 1)
     * @param prevTripletBaseIndexB   base index of the second token triplet (default 1)
     * @return the merge transaction
     */
    public Transaction createRftMergeTxn(
            Transaction prevWitnessTxA,
            Transaction prevTokenTxA,
            Transaction prevWitnessTxB,
            Transaction prevTokenTxB,
            PublicKey currentOwnerPubkey,
            SigningCallback ownerCallback,
            Transaction fundingTx,
            SigningCallback fundingCallback,
            PublicKey fundingPubKey,
            byte[] mergedWitnessFundingTxId,
            byte[] tokenId,
            byte[] rabinPubKeyHash,
            int flags,
            long totalAmount,
            int prevTripletBaseIndexA,
            int prevTripletBaseIndexB)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        TransactionSigner ownerSigner = SignerAdapter.fromCallback(ownerCallback, currentOwnerPubkey, sigHashAll);
        TransactionSigner fundingTxSigner = SignerAdapter.fromCallback(fundingCallback, fundingPubKey, sigHashAll);

        Address currentOwnerAddress = Address.fromKey(networkAddressType, currentOwnerPubkey);
        byte[] ownerPKH = currentOwnerAddress.getHash();
        int prevPP3IndexA = prevTripletBaseIndexA + 2;
        int prevPP3IndexB = prevTripletBaseIndexB + 2;

        // Build output lockers (single merged triplet)
        PP1RftLockBuilder pp1RftLocker = new PP1RftLockBuilder(ownerPKH, tokenId, rabinPubKeyHash, flags, totalAmount);
        PP2FtLockBuilder pp2FtLocker = new PP2FtLockBuilder(
                getOutpoint(mergedWitnessFundingTxId), ownerPKH, 1, ownerPKH, 1, 2);
        PartialWitnessFtLockBuilder pp3FtLocker = new PartialWitnessFtLockBuilder(ownerPKH);

        // Carry forward metadata from parent A (last output)
        DefaultLockBuilder metadataLocker = new DefaultLockBuilder(
                prevTokenTxA.getOutputs().get(prevTokenTxA.getOutputs().size() - 1).getScript());

        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(fundingPubKey);
        ModP2PKHUnlockBuilder prevWitnessAUnlocker = new ModP2PKHUnlockBuilder(currentOwnerPubkey);
        ModP2PKHUnlockBuilder prevWitnessBUnlocker = new ModP2PKHUnlockBuilder(currentOwnerPubkey);
        PartialWitnessFtUnlockBuilder pp3BurnUnlockerA = PartialWitnessFtUnlockBuilder.forBurn(currentOwnerPubkey);
        PartialWitnessFtUnlockBuilder pp3BurnUnlockerB = PartialWitnessFtUnlockBuilder.forBurn(currentOwnerPubkey);

        return new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingTxSigner, prevWitnessTxA, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessAUnlocker)
                .spendFromTransaction(fundingTxSigner, prevWitnessTxB, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessBUnlocker)
                .spendFromTransaction(ownerSigner, prevTokenTxA, prevPP3IndexA, TransactionInput.MAX_SEQ_NUMBER, pp3BurnUnlockerA)
                .spendFromTransaction(ownerSigner, prevTokenTxB, prevPP3IndexB, TransactionInput.MAX_SEQ_NUMBER, pp3BurnUnlockerB)
                .spendTo(pp1RftLocker, BigInteger.ONE)
                .spendTo(pp2FtLocker, BigInteger.ONE)
                .spendTo(pp3FtLocker, BigInteger.ONE)
                .spendTo(metadataLocker, BigInteger.ZERO)
                .sendChangeTo(currentOwnerAddress)
                .build(false);
    }

    // --- Private helpers ---

    /**
     * Computes SHA-256 of the input data.
     */
    private byte[] sha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Builds the PP1_RFT unlock builder for the given action.
     */
    private UnlockingScriptBuilder buildPP1RftUnlocker(
            RestrictedFungibleTokenAction action,
            byte[] preImage,
            Transaction tokenTx,
            PublicKey ownerPubkey,
            byte[] tokenChangePKH,
            byte[] tokenTxLHS,
            byte[] parentTokenTxBytes,
            byte[] paddingBytes,
            int parentOutputCount,
            int tripletBaseIndex,
            byte[] fundingTxHash,
            int parentPP1FtIndex,
            RabinKeyPair rabinKeyPair,
            byte[] identityTxId,
            byte[] ed25519PubKey,
            byte[] parentTokenTxBytesB,
            int parentOutputCountB,
            int parentPP1FtIndexB,
            long recipientAmount,
            long tokenChangeAmount,
            byte[] recipientPKH) throws IOException {

        int pp2Index = tripletBaseIndex + 1;
        long changeAmount = tokenTx.getOutputs().get(0).getAmount().longValue();

        if (action == RestrictedFungibleTokenAction.MINT) {
            // Rabin signing: messageHash = sha256ToScriptInt(concat(identityTxId, ed25519PubKey, tokenId))
            // tokenId binding prevents replay attacks across tokens
            byte[] pp1Program = tokenTx.getOutputs().get(tripletBaseIndex).getScript().getProgram();
            byte[] tokenId = new byte[32];
            System.arraycopy(pp1Program, 22, tokenId, 0, 32);
            byte[] concat = new byte[identityTxId.length + ed25519PubKey.length + tokenId.length];
            System.arraycopy(identityTxId, 0, concat, 0, identityTxId.length);
            System.arraycopy(ed25519PubKey, 0, concat, identityTxId.length, ed25519PubKey.length);
            System.arraycopy(tokenId, 0, concat, identityTxId.length + ed25519PubKey.length, tokenId.length);
            byte[] hashBytes = sha256(concat);
            BigInteger messageHash = Rabin.hashBytesToScriptInt(hashBytes);
            RabinSignature sig = Rabin.sign(messageHash, rabinKeyPair.p(), rabinKeyPair.q());

            byte[] rabinN = Rabin.bigIntToScriptNum(rabinKeyPair.n());
            byte[] rabinS = Rabin.bigIntToScriptNum(sig.s());

            return PP1RftUnlockBuilder.forMint(
                    preImage, fundingTxHash, paddingBytes,
                    rabinN, rabinS, sig.padding(),
                    identityTxId, ed25519PubKey);

        } else if (action == RestrictedFungibleTokenAction.TRANSFER) {
            byte[] pp2Output = tokenTx.getOutputs().get(pp2Index).serialize();
            return PP1RftUnlockBuilder.forTransfer(
                    preImage, pp2Output, ownerPubkey, tokenChangePKH,
                    changeAmount, tokenTxLHS, parentTokenTxBytes,
                    paddingBytes, parentOutputCount, parentPP1FtIndex);

        } else if (action == RestrictedFungibleTokenAction.SPLIT_TRANSFER) {
            byte[] pp2RecipientOutput = tokenTx.getOutputs().get(2).serialize();
            byte[] pp2ChangeOutput = tokenTx.getOutputs().get(5).serialize();

            return PP1RftUnlockBuilder.forSplitTransfer(
                    preImage, pp2RecipientOutput, pp2ChangeOutput, ownerPubkey,
                    tokenChangePKH, changeAmount, tokenTxLHS,
                    parentTokenTxBytes, paddingBytes,
                    recipientAmount, tokenChangeAmount,
                    recipientPKH, tripletBaseIndex, parentOutputCount,
                    parentPP1FtIndex);

        } else if (action == RestrictedFungibleTokenAction.MERGE) {
            byte[] pp2Output = tokenTx.getOutputs().get(pp2Index).serialize();
            return PP1RftUnlockBuilder.forMerge(
                    preImage, pp2Output, ownerPubkey, tokenChangePKH,
                    changeAmount, tokenTxLHS, parentTokenTxBytes,
                    parentTokenTxBytesB, paddingBytes,
                    parentOutputCount, parentOutputCountB,
                    parentPP1FtIndex, parentPP1FtIndexB);

        } else {
            throw new IllegalArgumentException("Unsupported action for witness: " + action);
        }
    }

    /**
     * Builds the witness transaction structure.
     */
    private Transaction buildWitnessTxn(
            TransactionSigner fundingSigner,
            Transaction fundingTx,
            Transaction tokenTx,
            int pp1FtIndex,
            int pp2Index,
            PublicKey ownerPubkey,
            UnlockingScriptBuilder pp1RftUnlocker,
            PP2FtUnlockBuilder pp2FtUnlocker,
            ModP2PKHLockBuilder witnessLocker)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(ownerPubkey);
        return new TransactionBuilder()
                .spendFromTransaction(fundingSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingSigner, tokenTx, pp1FtIndex, TransactionInput.MAX_SEQ_NUMBER, pp1RftUnlocker)
                .spendFromTransaction(tokenTx, pp2Index, TransactionInput.MAX_SEQ_NUMBER, pp2FtUnlocker)
                .spendTo(witnessLocker, BigInteger.ONE)
                .build(false);
    }
}
