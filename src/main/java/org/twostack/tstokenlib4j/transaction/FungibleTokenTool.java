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
 * High-level API for creating fungible token (FT) transactions (mint, transfer, split, merge, witness, burn).
 *
 * <p>Encapsulates the construction of multi-output token transactions that conform
 * to the TSL1 protocol's proof-carrying transaction structure with balance conservation.
 *
 * <p>All signing is performed via {@link SigningCallback}, which decouples
 * transaction construction from private key management. The callback receives
 * a sighash digest and returns a DER-encoded signature — compatible with
 * KMS, HSM, hardware wallets, or libspiffy4j's {@code CallbackTransactionSigner}.
 *
 * <p>Transaction output structures:
 * <ul>
 *   <li>Mint/Transfer/Merge: 5 outputs [Change, PP1_FT, PP2-FT, PP3-FT, Metadata]</li>
 *   <li>Split: 8 outputs [Change, PP1_FT-recv, PP2FT-recv, PP3FT-recv, PP1_FT-change, PP2FT-change, PP3FT-change, Metadata]</li>
 *   <li>Witness: 1 output [Witness]</li>
 *   <li>Burn: 1 output [Change]</li>
 * </ul>
 */
public class FungibleTokenTool {

    private final NetworkAddressType networkAddressType;
    private final BigInteger defaultFee;
    private final int sigHashAll;

    public FungibleTokenTool(NetworkAddressType networkAddressType, BigInteger defaultFee) {
        this.networkAddressType = networkAddressType;
        this.defaultFee = defaultFee != null ? defaultFee : BigInteger.valueOf(135);
        this.sigHashAll = SigHashType.FORKID.value | SigHashType.ALL.value;
    }

    public FungibleTokenTool(NetworkAddressType networkAddressType) {
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
     * Decodes the fungible token amount from a PP1_FT locking script.
     * The amount is an 8-byte LE sign-magnitude integer at bytes 76..83.
     */
    private static long decodePP1FtAmount(byte[] pp1Script) {
        long value = 0;
        for (int i = 0; i < 8; i++) {
            value |= ((long) (pp1Script[76 + i] & 0xFF)) << (8 * i);
        }
        // Sign-magnitude: if highest bit is set, the number is negative
        if ((value & (1L << 63)) != 0) {
            value = -(value & ~(1L << 63));
        }
        return value;
    }

    /**
     * Creates a 5-output fungible token mint transaction.
     *
     * <p>Outputs: [Change, PP1_FT, PP2-FT, PP3-FT, Metadata]
     *
     * @param tokenFundingTx       funds the mint; its txid becomes the tokenId
     * @param fundingSigner        callback that signs sighash digests for the funding key
     * @param fundingPubKey        public key corresponding to the funding signer
     * @param recipientAddress     address of the token recipient
     * @param witnessFundingTxId   txid of the transaction that will fund the first witness
     * @param amount               initial token supply
     * @param metadataBytes        optional metadata bytes for OP_RETURN output (may be null)
     */
    public Transaction createFungibleMintTxn(
            Transaction tokenFundingTx,
            SigningCallback fundingSigner,
            PublicKey fundingPubKey,
            Address recipientAddress,
            byte[] witnessFundingTxId,
            byte[] rabinPubKeyHash,
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

        // Output 1: PP1_FT (fungible token state)
        tokenTxBuilder.spendTo(new PP1FtLockBuilder(recipientPKH, tokenId, rabinPubKeyHash, amount), BigInteger.ONE);

        // Output 2: PP2-FT (witness bridge)
        tokenTxBuilder.spendTo(new PP2FtLockBuilder(
                getOutpoint(witnessFundingTxId), recipientPKH, 1, recipientPKH, 1, 2), BigInteger.ONE);

        // Output 3: PP3-FT (partial SHA256 witness verifier)
        tokenTxBuilder.spendTo(new PartialWitnessFtLockBuilder(recipientPKH, 2), BigInteger.ONE);

        // Output 4: Metadata (OP_RETURN)
        tokenTxBuilder.spendTo(new MetadataLockBuilder(metadataBytes), BigInteger.ZERO);

        tokenTxBuilder.sendChangeTo(recipientAddress);
        return tokenTxBuilder.build(false);
    }

    /**
     * Creates a fungible token transfer transaction (5 outputs, full balance transfer).
     *
     * <p>Outputs: [Change, PP1_FT, PP2-FT, PP3-FT, Metadata]
     *
     * <p>Spends the previous witness output and PP3-FT from the previous token transaction.
     * Metadata is carried forward from the parent token transaction.
     *
     * @param prevWitnessTx              previous witness transaction
     * @param prevTokenTx                previous token transaction
     * @param currentOwnerPubkey         public key of the current token owner
     * @param recipientAddress           address of the new token recipient
     * @param fundingTx                  transaction providing funding
     * @param fundingSigner              callback that signs sighash digests for the funding key
     * @param fundingPubKey              public key corresponding to the funding signer
     * @param recipientWitnessFundingTxId txid of the witness funding for the recipient
     * @param tokenId                    the token identifier
     * @param amount                     the full token balance being transferred
     * @param prevTripletBaseIndex       base index of the triplet in the previous token tx (1 for standard, 4 for change)
     */
    public Transaction createFungibleTransferTxn(
            Transaction prevWitnessTx,
            Transaction prevTokenTx,
            PublicKey currentOwnerPubkey,
            Address recipientAddress,
            Transaction fundingTx,
            SigningCallback fundingSigner,
            PublicKey fundingPubKey,
            byte[] recipientWitnessFundingTxId,
            byte[] tokenId,
            long amount,
            int prevTripletBaseIndex)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        TransactionSigner fundingTxSigner = SignerAdapter.fromCallback(fundingSigner, fundingPubKey, sigHashAll);

        Address currentOwnerAddress = Address.fromKey(networkAddressType, currentOwnerPubkey);
        byte[] recipientPKH = recipientAddress.getHash();
        int prevPP3Index = prevTripletBaseIndex + 2;

        // Extract rabinPubKeyHash from parent PP1 script at byte offset [55:75]
        byte[] parentPP1Bytes = prevTokenTx.getOutputs().get(prevTripletBaseIndex).getScript().getProgram();
        byte[] rabinPubKeyHash = new byte[20];
        System.arraycopy(parentPP1Bytes, 55, rabinPubKeyHash, 0, 20);

        // Build output lockers
        PP1FtLockBuilder pp1FtLocker = new PP1FtLockBuilder(recipientPKH, tokenId, rabinPubKeyHash, amount);
        PP2FtLockBuilder pp2FtLocker = new PP2FtLockBuilder(
                getOutpoint(recipientWitnessFundingTxId), recipientPKH, 1, recipientPKH, 1, 2);
        PartialWitnessFtLockBuilder pp3FtLocker = new PartialWitnessFtLockBuilder(recipientPKH, 2);

        // Carry forward metadata from parent token tx (last output)
        Script metadataScript = prevTokenTx.getOutputs().get(prevTokenTx.getOutputs().size() - 1).getScript();
        DefaultLockBuilder metadataLocker = new DefaultLockBuilder(metadataScript);

        // Input unlockers
        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(fundingPubKey);
        ModP2PKHUnlockBuilder prevWitnessUnlocker = new ModP2PKHUnlockBuilder(currentOwnerPubkey);
        DefaultUnlockBuilder emptyUnlocker = new DefaultUnlockBuilder();

        // First pass: empty PP3-FT unlocker to get preimage
        TransactionBuilder preImageBuilder = new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
                .spendFromTransaction(prevTokenTx, prevPP3Index, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
                .spendTo(pp1FtLocker, BigInteger.ONE)
                .spendTo(pp2FtLocker, BigInteger.ONE)
                .spendTo(pp3FtLocker, BigInteger.ONE)
                .spendTo(metadataLocker, BigInteger.ZERO)
                .sendChangeTo(currentOwnerAddress);
        preImageBuilder.setFee(defaultFee);
        Transaction childPreImageTxn = preImageBuilder.build(false);

        Script pp3Subscript = prevTokenTx.getOutputs().get(prevPP3Index).getScript();
        byte[] sigPreImage = new SigHash().getSighashPreimage(childPreImageTxn, sigHashAll, 2, pp3Subscript, BigInteger.ONE);

        TransactionUtils tsl1 = new TransactionUtils();
        byte[][] partialResult = tsl1.computePartialHash(prevWitnessTx.serialize(), 2);

        PartialWitnessFtUnlockBuilder pp3FtUnlocker = PartialWitnessFtUnlockBuilder.forUnlock(
                sigPreImage, partialResult[0], partialResult[1], getOutpoint(fundingTx.getTransactionIdBytes()));

        // Final build with PP3-FT unlocker
        TransactionBuilder finalBuilder = new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
                .spendFromTransaction(prevTokenTx, prevPP3Index, TransactionInput.MAX_SEQ_NUMBER, pp3FtUnlocker)
                .spendTo(pp1FtLocker, BigInteger.ONE)
                .spendTo(pp2FtLocker, BigInteger.ONE)
                .spendTo(pp3FtLocker, BigInteger.ONE)
                .spendTo(metadataLocker, BigInteger.ZERO)
                .sendChangeTo(currentOwnerAddress);
        finalBuilder.setFee(defaultFee);
        return finalBuilder.build(false);
    }

    /**
     * Creates an 8-output split transfer transaction.
     *
     * <p>Outputs: [Change, PP1_FT-recv, PP2FT-recv, PP3FT-recv, PP1_FT-change, PP2FT-change, PP3FT-change, Metadata]
     *
     * @param prevWitnessTx              previous witness transaction
     * @param prevTokenTx                previous token transaction
     * @param currentOwnerPubkey         public key of the current token owner
     * @param recipientAddress           address of the token recipient
     * @param sendAmount                 token amount to send to recipient
     * @param fundingTx                  transaction providing funding
     * @param fundingSigner              callback that signs sighash digests for the funding key
     * @param fundingPubKey              public key corresponding to the funding signer
     * @param recipientWitnessFundingTxId txid of the witness funding for the recipient
     * @param changeWitnessFundingTxId   txid of the witness funding for the sender's change
     * @param tokenId                    the token identifier
     * @param totalAmount                the full token balance being split (must equal sendAmount + change)
     * @param prevTripletBaseIndex       base index of the triplet in the previous token tx (1 for standard, 4 for change)
     */
    public Transaction createFungibleSplitTxn(
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
            long totalAmount,
            int prevTripletBaseIndex)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        TransactionSigner fundingTxSigner = SignerAdapter.fromCallback(fundingSigner, fundingPubKey, sigHashAll);

        Address currentOwnerAddress = Address.fromKey(networkAddressType, currentOwnerPubkey);
        byte[] recipientPKH = recipientAddress.getHash();
        byte[] senderPKH = currentOwnerAddress.getHash();
        long changeTokenAmount = totalAmount - sendAmount;
        int prevPP3Index = prevTripletBaseIndex + 2;

        // Extract rabinPubKeyHash from parent PP1 script at byte offset [55:75]
        byte[] parentPP1Bytes = prevTokenTx.getOutputs().get(prevTripletBaseIndex).getScript().getProgram();
        byte[] rabinPubKeyHash = new byte[20];
        System.arraycopy(parentPP1Bytes, 55, rabinPubKeyHash, 0, 20);

        // Recipient triplet (outputs 1,2,3)
        PP1FtLockBuilder pp1FtRecipientLocker = new PP1FtLockBuilder(recipientPKH, tokenId, rabinPubKeyHash, sendAmount);
        PP2FtLockBuilder pp2FtRecipientLocker = new PP2FtLockBuilder(
                getOutpoint(recipientWitnessFundingTxId), recipientPKH, 1, recipientPKH, 1, 2);
        PartialWitnessFtLockBuilder pp3FtRecipientLocker = new PartialWitnessFtLockBuilder(recipientPKH, 2);

        // Change triplet (outputs 4,5,6)
        PP1FtLockBuilder pp1FtChangeLocker = new PP1FtLockBuilder(senderPKH, tokenId, rabinPubKeyHash, changeTokenAmount);
        PP2FtLockBuilder pp2FtChangeLocker = new PP2FtLockBuilder(
                getOutpoint(changeWitnessFundingTxId), senderPKH, 1, senderPKH, 4, 5);
        PartialWitnessFtLockBuilder pp3FtChangeLocker = new PartialWitnessFtLockBuilder(senderPKH, 5);

        // Metadata (carried forward from parent, last output)
        Script metadataScript = prevTokenTx.getOutputs().get(prevTokenTx.getOutputs().size() - 1).getScript();
        DefaultLockBuilder metadataLocker = new DefaultLockBuilder(metadataScript);

        // Input unlockers
        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(fundingPubKey);
        ModP2PKHUnlockBuilder prevWitnessUnlocker = new ModP2PKHUnlockBuilder(currentOwnerPubkey);
        DefaultUnlockBuilder emptyUnlocker = new DefaultUnlockBuilder();

        // First pass: empty PP3-FT unlocker to get preimage
        TransactionBuilder preImageBuilder = new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
                .spendFromTransaction(prevTokenTx, prevPP3Index, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
                .spendTo(pp1FtRecipientLocker, BigInteger.ONE)
                .spendTo(pp2FtRecipientLocker, BigInteger.ONE)
                .spendTo(pp3FtRecipientLocker, BigInteger.ONE)
                .spendTo(pp1FtChangeLocker, BigInteger.ONE)
                .spendTo(pp2FtChangeLocker, BigInteger.ONE)
                .spendTo(pp3FtChangeLocker, BigInteger.ONE)
                .spendTo(metadataLocker, BigInteger.ZERO)
                .sendChangeTo(currentOwnerAddress);
        preImageBuilder.setFee(defaultFee);
        Transaction childPreImageTxn = preImageBuilder.build(false);

        Script pp3Subscript = prevTokenTx.getOutputs().get(prevPP3Index).getScript();
        byte[] sigPreImage = new SigHash().getSighashPreimage(childPreImageTxn, sigHashAll, 2, pp3Subscript, BigInteger.ONE);

        TransactionUtils tsl1 = new TransactionUtils();
        byte[][] partialResult = tsl1.computePartialHash(prevWitnessTx.serialize(), 2);

        PartialWitnessFtUnlockBuilder pp3FtUnlocker = PartialWitnessFtUnlockBuilder.forUnlock(
                sigPreImage, partialResult[0], partialResult[1], getOutpoint(fundingTx.getTransactionIdBytes()));

        // Final build with PP3-FT unlocker
        TransactionBuilder finalBuilder = new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
                .spendFromTransaction(prevTokenTx, prevPP3Index, TransactionInput.MAX_SEQ_NUMBER, pp3FtUnlocker)
                .spendTo(pp1FtRecipientLocker, BigInteger.ONE)
                .spendTo(pp2FtRecipientLocker, BigInteger.ONE)
                .spendTo(pp3FtRecipientLocker, BigInteger.ONE)
                .spendTo(pp1FtChangeLocker, BigInteger.ONE)
                .spendTo(pp2FtChangeLocker, BigInteger.ONE)
                .spendTo(pp3FtChangeLocker, BigInteger.ONE)
                .spendTo(metadataLocker, BigInteger.ZERO)
                .sendChangeTo(currentOwnerAddress);
        finalBuilder.setFee(defaultFee);
        return finalBuilder.build(false);
    }

    /**
     * Creates a 5-output merge transaction combining two token UTXOs.
     *
     * <p>Inputs: [funding(0), witnessA(1), witnessB(2), PP3_A_burn(3), PP3_B_burn(4)]
     * <p>Outputs: [Change, PP1_FT_merged, PP2-FT, PP3-FT, Metadata]
     *
     * <p>PP3 inputs are burned (P2PKH only) rather than unlocked, because PP3-FT's
     * hashPrevOuts verification hardcodes 3 inputs and cannot work with 5.
     *
     * @param prevWitnessTxA           first parent's witness transaction
     * @param prevTokenTxA             first parent's token transaction
     * @param prevWitnessTxB           second parent's witness transaction
     * @param prevTokenTxB             second parent's token transaction
     * @param currentOwnerPubkey       public key of the current token owner
     * @param ownerCallback            callback that signs sighash digests for the owner key
     * @param fundingTx                transaction providing funding
     * @param fundingCallback          callback that signs sighash digests for the funding key
     * @param fundingPubKey            public key corresponding to the funding signer
     * @param mergedWitnessFundingTxId txid of the witness funding for the merged output
     * @param tokenId                  the token identifier
     * @param totalAmount              combined token balance (amountA + amountB)
     * @param prevTripletBaseIndexA    base index of the triplet in parent A (1 for standard, 4 for change)
     * @param prevTripletBaseIndexB    base index of the triplet in parent B (1 for standard, 4 for change)
     */
    public Transaction createFungibleMergeTxn(
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

        // Extract rabinPubKeyHash from parent A's PP1 script at byte offset [55:75]
        byte[] parentPP1Bytes = prevTokenTxA.getOutputs().get(prevTripletBaseIndexA).getScript().getProgram();
        byte[] rabinPubKeyHash = new byte[20];
        System.arraycopy(parentPP1Bytes, 55, rabinPubKeyHash, 0, 20);

        // Build output lockers (single merged triplet)
        PP1FtLockBuilder pp1FtLocker = new PP1FtLockBuilder(ownerPKH, tokenId, rabinPubKeyHash, totalAmount);
        PP2FtLockBuilder pp2FtLocker = new PP2FtLockBuilder(
                getOutpoint(mergedWitnessFundingTxId), ownerPKH, 1, ownerPKH, 1, 2);
        PartialWitnessFtLockBuilder pp3FtLocker = new PartialWitnessFtLockBuilder(ownerPKH, 2);

        // Carry forward metadata from parent A (last output)
        Script metadataScript = prevTokenTxA.getOutputs().get(prevTokenTxA.getOutputs().size() - 1).getScript();
        DefaultLockBuilder metadataLocker = new DefaultLockBuilder(metadataScript);

        // Input unlockers
        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(fundingPubKey);
        ModP2PKHUnlockBuilder prevWitnessAUnlocker = new ModP2PKHUnlockBuilder(currentOwnerPubkey);
        ModP2PKHUnlockBuilder prevWitnessBUnlocker = new ModP2PKHUnlockBuilder(currentOwnerPubkey);
        PartialWitnessFtUnlockBuilder pp3BurnUnlockerA = PartialWitnessFtUnlockBuilder.forBurn(currentOwnerPubkey);
        PartialWitnessFtUnlockBuilder pp3BurnUnlockerB = PartialWitnessFtUnlockBuilder.forBurn(currentOwnerPubkey);

        TransactionBuilder builder = new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingTxSigner, prevWitnessTxA, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessAUnlocker)
                .spendFromTransaction(fundingTxSigner, prevWitnessTxB, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessBUnlocker)
                .spendFromTransaction(ownerSigner, prevTokenTxA, prevPP3IndexA, TransactionInput.MAX_SEQ_NUMBER, pp3BurnUnlockerA)
                .spendFromTransaction(ownerSigner, prevTokenTxB, prevPP3IndexB, TransactionInput.MAX_SEQ_NUMBER, pp3BurnUnlockerB)
                .spendTo(pp1FtLocker, BigInteger.ONE)
                .spendTo(pp2FtLocker, BigInteger.ONE)
                .spendTo(pp3FtLocker, BigInteger.ONE)
                .spendTo(metadataLocker, BigInteger.ZERO)
                .sendChangeTo(currentOwnerAddress);
        builder.setFee(defaultFee);
        return builder.build(false);
    }

    /**
     * Creates a witness transaction for a fungible token.
     *
     * <p>Produces a 1-output transaction: Witness (locked to current token holder).
     * Uses two-pass building with padding recalculation.
     *
     * @param fundingSigner          callback that signs sighash digests for the funding key
     * @param fundingPubKey          public key corresponding to the funding signer
     * @param fundingTx              transaction providing funding
     * @param tokenTx                the token transaction being witnessed
     * @param ownerPubkey            public key of the current token owner
     * @param tokenChangePKH         20-byte HASH160 for token change output
     * @param action                 the fungible token action determining the PP1_FT function selector
     * @param parentTokenTxBytes     raw bytes of the parent token transaction (required for TRANSFER, SPLIT_TRANSFER, MERGE)
     * @param parentOutputCount      number of outputs in the parent transaction
     * @param tripletBaseIndex       base index of the triplet (1 for standard, 4 for change after split)
     * @param parentTokenTxBytesB    raw bytes of the second parent token transaction (for MERGE)
     * @param parentOutputCountB     number of outputs in the second parent transaction (for MERGE)
     * @param parentPP1FtIndexA      PP1 FT output index in the first parent (for MERGE)
     * @param parentPP1FtIndexB      PP1 FT output index in the second parent (for MERGE)
     * @param sendAmount             recipient token amount (for SPLIT_TRANSFER)
     * @param changeAmount           change token amount (for SPLIT_TRANSFER)
     * @param recipientPKH           recipient's 20-byte HASH160 (for SPLIT_TRANSFER)
     */
    public Transaction createFungibleWitnessTxn(
            SigningCallback fundingSigner,
            PublicKey fundingPubKey,
            Transaction fundingTx,
            Transaction tokenTx,
            PublicKey ownerPubkey,
            byte[] tokenChangePKH,
            FungibleTokenAction action,
            byte[] parentTokenTxBytes,
            int parentOutputCount,
            int tripletBaseIndex,
            byte[] parentTokenTxBytesB,
            int parentOutputCountB,
            int parentPP1FtIndexA,
            int parentPP1FtIndexB,
            long sendAmount,
            long changeAmount,
            byte[] recipientPKH,
            byte[] rabinN,
            byte[] rabinS,
            int rabinPadding,
            byte[] identityTxId,
            byte[] ed25519PubKey)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        TransactionSigner signer = SignerAdapter.fromCallback(fundingSigner, fundingPubKey, sigHashAll);

        int pp1FtIndex = tripletBaseIndex;
        int pp2Index = tripletBaseIndex + 1;

        PP2FtUnlockBuilder pp2FtUnlocker = PP2FtUnlockBuilder.forNormal(tokenTx.getTransactionIdBytes());
        ModP2PKHLockBuilder witnessLocker = new ModP2PKHLockBuilder(ownerPubkey.getPubKeyHash());
        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(fundingPubKey);
        DefaultUnlockBuilder emptyUnlocker = new DefaultUnlockBuilder();

        // First pass: build with empty PP1_FT unlocker to get preimage
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

        // Build PP1_FT unlocker and rebuild with padding (two passes)
        UnlockingScriptBuilder pp1FtUnlocker = buildPP1FtUnlocker(
                action, preImage, tokenTx, ownerPubkey, tokenChangePKH,
                tokenTxLHS, parentTokenTxBytes, paddingBytes,
                parentOutputCount, tripletBaseIndex, getOutpoint(fundingTx.getTransactionIdBytes()),
                parentTokenTxBytesB, parentOutputCountB, parentPP1FtIndexA, parentPP1FtIndexB,
                sendAmount, changeAmount, recipientPKH,
                rabinN, rabinS, rabinPadding, identityTxId, ed25519PubKey);

        Transaction witnessTx = buildWitnessTxn(signer, fundingTx, tokenTx,
                pp1FtIndex, pp2Index, ownerPubkey, pp1FtUnlocker, pp2FtUnlocker, witnessLocker);

        // Recalculate padding
        paddingBytes = tsl1.calculatePaddingBytes(witnessTx);

        pp1FtUnlocker = buildPP1FtUnlocker(
                action, preImage, tokenTx, ownerPubkey, tokenChangePKH,
                tokenTxLHS, parentTokenTxBytes, paddingBytes,
                parentOutputCount, tripletBaseIndex, getOutpoint(fundingTx.getTransactionIdBytes()),
                parentTokenTxBytesB, parentOutputCountB, parentPP1FtIndexA, parentPP1FtIndexB,
                sendAmount, changeAmount, recipientPKH,
                rabinN, rabinS, rabinPadding, identityTxId, ed25519PubKey);

        witnessTx = buildWitnessTxn(signer, fundingTx, tokenTx,
                pp1FtIndex, pp2Index, ownerPubkey, pp1FtUnlocker, pp2FtUnlocker, witnessLocker);

        return witnessTx;
    }

    /**
     * Burns a fungible token by spending all proof outputs (PP1_FT, PP2-FT, PP3-FT).
     *
     * @param tokenTx           the token transaction to burn
     * @param ownerCallback     callback that signs sighash digests for the owner key
     * @param ownerPubkey       public key of the current token owner
     * @param fundingTx         transaction providing funding
     * @param fundingCallback   callback that signs sighash digests for the funding key
     * @param fundingPubKey     public key corresponding to the funding signer
     * @param tripletBaseIndex  base index of the triplet (1 for standard, 4 for change after split)
     */
    public Transaction createFungibleBurnTxn(
            Transaction tokenTx,
            SigningCallback ownerCallback,
            PublicKey ownerPubkey,
            Transaction fundingTx,
            SigningCallback fundingCallback,
            PublicKey fundingPubKey,
            int tripletBaseIndex)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        TransactionSigner ownerSigner = SignerAdapter.fromCallback(ownerCallback, ownerPubkey, sigHashAll);
        TransactionSigner fundingTxSigner = SignerAdapter.fromCallback(fundingCallback, fundingPubKey, sigHashAll);

        Address ownerAddress = Address.fromKey(networkAddressType, ownerPubkey);
        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(fundingPubKey);

        TransactionBuilder builder = new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(ownerSigner, tokenTx, tripletBaseIndex, TransactionInput.MAX_SEQ_NUMBER, PP1FtUnlockBuilder.forBurn(ownerPubkey))
                .spendFromTransaction(ownerSigner, tokenTx, tripletBaseIndex + 1, TransactionInput.MAX_SEQ_NUMBER, PP2FtUnlockBuilder.forBurn(ownerPubkey))
                .spendFromTransaction(ownerSigner, tokenTx, tripletBaseIndex + 2, TransactionInput.MAX_SEQ_NUMBER, PartialWitnessFtUnlockBuilder.forBurn(ownerPubkey))
                .sendChangeTo(ownerAddress);
        builder.setFee(defaultFee);
        return builder.build(false);
    }

    // --- Private helpers ---

    /**
     * Builds the PP1_FT unlock builder for the given action.
     */
    private UnlockingScriptBuilder buildPP1FtUnlocker(
            FungibleTokenAction action,
            byte[] preImage,
            Transaction tokenTx,
            PublicKey ownerPubkey,
            byte[] tokenChangePKH,
            byte[] tokenTxLHS,
            byte[] parentTokenTxBytes,
            byte[] paddingBytes,
            int parentOutputCount,
            int tripletBaseIndex,
            byte[] fundingOutpoint,
            byte[] parentTokenTxBytesB,
            int parentOutputCountB,
            int parentPP1FtIndexA,
            int parentPP1FtIndexB,
            long sendAmount,
            long changeAmount,
            byte[] recipientPKH,
            byte[] rabinN,
            byte[] rabinS,
            int rabinPadding,
            byte[] identityTxId,
            byte[] ed25519PubKey) throws IOException {

        int pp2Index = tripletBaseIndex + 1;
        long tokenChangeAmount = tokenTx.getOutputs().get(0).getAmount().longValue();

        if (action == FungibleTokenAction.MINT) {
            return PP1FtUnlockBuilder.forMint(preImage, fundingOutpoint, paddingBytes,
                    rabinN != null ? rabinN : new byte[0],
                    rabinS != null ? rabinS : new byte[0],
                    rabinPadding,
                    identityTxId != null ? identityTxId : new byte[0],
                    ed25519PubKey != null ? ed25519PubKey : new byte[0]);
        } else if (action == FungibleTokenAction.TRANSFER) {
            byte[] pp2Output = tokenTx.getOutputs().get(pp2Index).serialize();
            return PP1FtUnlockBuilder.forTransfer(
                    preImage, pp2Output, ownerPubkey, tokenChangePKH,
                    tokenChangeAmount, tokenTxLHS, parentTokenTxBytes,
                    paddingBytes, parentOutputCount, parentPP1FtIndexA);
        } else if (action == FungibleTokenAction.SPLIT_TRANSFER) {
            byte[] pp2RecipientOutput = tokenTx.getOutputs().get(2).serialize();
            byte[] pp2ChangeOutput = tokenTx.getOutputs().get(5).serialize();

            // Derive split amounts and recipientPKH from the token TX's PP1 outputs
            // (matching Dart _buildPP1FtUnlocker which calls PP1FtLockBuilder.fromScript)
            byte[] recipientPP1Script = tokenTx.getOutputs().get(1).getScript().getProgram();
            byte[] changePP1Script = tokenTx.getOutputs().get(4).getScript().getProgram();
            long derivedSendAmount = decodePP1FtAmount(recipientPP1Script);
            long derivedChangeAmount = decodePP1FtAmount(changePP1Script);
            byte[] derivedRecipientPKH = new byte[20];
            System.arraycopy(recipientPP1Script, 1, derivedRecipientPKH, 0, 20);

            return PP1FtUnlockBuilder.forSplitTransfer(
                    preImage, pp2RecipientOutput, pp2ChangeOutput, ownerPubkey,
                    tokenChangePKH, tokenChangeAmount, tokenTxLHS,
                    parentTokenTxBytes, paddingBytes,
                    derivedSendAmount, derivedChangeAmount,
                    derivedRecipientPKH, tripletBaseIndex, parentOutputCount,
                    parentPP1FtIndexA);
        } else if (action == FungibleTokenAction.MERGE) {
            byte[] pp2Output = tokenTx.getOutputs().get(2).serialize();
            return PP1FtUnlockBuilder.forMerge(
                    preImage, pp2Output, ownerPubkey, tokenChangePKH,
                    tokenChangeAmount, tokenTxLHS,
                    parentTokenTxBytes, parentTokenTxBytesB,
                    paddingBytes, parentOutputCount, parentOutputCountB,
                    parentPP1FtIndexA, parentPP1FtIndexB);
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
            UnlockingScriptBuilder pp1FtUnlocker,
            PP2FtUnlockBuilder pp2FtUnlocker,
            ModP2PKHLockBuilder witnessLocker)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(ownerPubkey);
        return new TransactionBuilder()
                .spendFromTransaction(fundingSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingSigner, tokenTx, pp1FtIndex, TransactionInput.MAX_SEQ_NUMBER, pp1FtUnlocker)
                .spendFromTransaction(tokenTx, pp2Index, TransactionInput.MAX_SEQ_NUMBER, pp2FtUnlocker)
                .spendTo(witnessLocker, BigInteger.ONE)
                .build(false);
    }
}
