package org.twostack.tstokenlib4j.transaction;

import org.twostack.bitcoin4j.Address;
import org.twostack.bitcoin4j.PrivateKey;
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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * High-level API for creating State Machine (SM) token transactions.
 *
 * <p>Supports: create (issuance), enroll, confirm, convert, settle, timeout, burn.
 * Dual authority model: operator signs enroll/settle/timeout; both operator and counterparty
 * sign confirm/convert. Owner (whoever is the next expected actor) signs burn.
 *
 * <p>All signing is performed via {@link SigningCallback}, which decouples
 * transaction construction from private key management. The callback receives
 * a sighash digest and returns a DER-encoded signature — compatible with
 * KMS, HSM, hardware wallets, or libspiffy4j's {@code CallbackTransactionSigner}.
 *
 * <p>Transaction output structures:
 * <ul>
 *   <li>Issuance/Enroll/Transition: 5 outputs [Change, PP1_SM, PP2, PP3, Metadata]</li>
 *   <li>Settle: 7 outputs [Change, CounterpartyShare, OperatorShare, PP1_SM, PP2, PP3, Metadata]</li>
 *   <li>Timeout: 6 outputs [Change, OperatorRecovery, PP1_SM, PP2, PP3, Metadata]</li>
 *   <li>Witness: 1 output [Witness]</li>
 *   <li>Burn: spends PP1_SM, PP2, PP3 to change</li>
 * </ul>
 */
public class StateMachineTool {

    private final NetworkAddressType networkAddressType;
    private final BigInteger defaultFee;
    private final int sigHashAll;

    public StateMachineTool(NetworkAddressType networkAddressType, BigInteger defaultFee) {
        this.networkAddressType = networkAddressType;
        this.defaultFee = defaultFee != null ? defaultFee : BigInteger.valueOf(135);
        this.sigHashAll = SigHashType.FORKID.value | SigHashType.ALL.value;
    }

    public StateMachineTool(NetworkAddressType networkAddressType) {
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
     * Creates an SM issuance transaction with 5-output structure:
     * Change, PP1_SM, PP2, PartialWitness, Metadata.
     *
     * @param tokenFundingTx      funds the issuance; its txid becomes the initial tokenId
     * @param fundingSigner       callback that signs sighash digests for the funding key
     * @param fundingPubKey       public key corresponding to the funding signer
     * @param operatorAddress     the initial owner address (operator creates the state machine)
     * @param operatorPKH         20-byte HASH160 of the operator's public key
     * @param counterpartyPKH     20-byte HASH160 of the counterparty's public key
     * @param transitionBitmask   bitmask controlling which transitions are enabled
     * @param timeoutDelta        timeout delta in seconds
     * @param witnessFundingTxId  txid of the tx that will fund the first witness
     * @param metadataBytes       optional metadata bytes (may be null)
     */
    public Transaction createTokenIssuanceTxn(
            Transaction tokenFundingTx,
            SigningCallback fundingSigner,
            PublicKey fundingPubKey,
            Address operatorAddress,
            byte[] operatorPKH,
            byte[] counterpartyPKH,
            int transitionBitmask,
            int timeoutDelta,
            byte[] witnessFundingTxId,
            byte[] rabinPubKeyHash,
            byte[] metadataBytes)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        TransactionSigner fundingTxSigner = SignerAdapter.fromCallback(fundingSigner, fundingPubKey, sigHashAll);

        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(fundingPubKey);
        TransactionBuilder tokenTxBuilder = new TransactionBuilder();
        byte[] tokenId = tokenFundingTx.getTransactionIdBytes();

        byte[] initialCommitmentHash = new byte[32];

        tokenTxBuilder.spendFromTransaction(fundingTxSigner, tokenFundingTx, 1,
                TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker);
        tokenTxBuilder.withFeePerKb(1);

        // Output 1: PP1_SM
        PP1SmLockBuilder pp1Locker = new PP1SmLockBuilder(
                operatorPKH, tokenId, operatorPKH, counterpartyPKH, rabinPubKeyHash,
                0, 0, initialCommitmentHash, transitionBitmask, timeoutDelta);
        tokenTxBuilder.spendTo(pp1Locker, BigInteger.ONE);

        // Output 2: PP2
        tokenTxBuilder.spendTo(new PP2LockBuilder(
                getOutpoint(witnessFundingTxId), operatorAddress.getHash(), 1,
                operatorAddress.getHash()), BigInteger.ONE);

        // Output 3: PartialWitness
        tokenTxBuilder.spendTo(new PartialWitnessLockBuilder(operatorAddress.getHash()), BigInteger.ONE);

        // Output 4: Metadata OP_RETURN
        tokenTxBuilder.spendTo(new MetadataLockBuilder(metadataBytes), BigInteger.ZERO);

        tokenTxBuilder.sendChangeTo(operatorAddress);
        return tokenTxBuilder.build(false);
    }

    /**
     * Creates a witness transaction for a single-sig SM operation (ENROLL, SETTLE, TIMEOUT).
     *
     * <p>Uses two-pass building with padding recalculation.
     *
     * @param signerCallback      callback that signs sighash digests for the operator key
     * @param signerPubKey        public key corresponding to the operator signer
     * @param fundingTx           funding transaction
     * @param tokenTx             the token transaction being witnessed
     * @param parentTokenTxBytes  raw bytes of the parent token transaction
     * @param operatorPubkey      operator's public key
     * @param tokenChangePKH      20-byte HASH160 for witness change output
     * @param action              must be ENROLL, SETTLE, or TIMEOUT
     * @param eventData           operation-specific event data (may be null)
     * @param counterpartyShareAmount    counterparty share amount (required for SETTLE, 0 otherwise)
     * @param operatorShareAmount       operator share amount (required for SETTLE, 0 otherwise)
     * @param recoveryAmount            recovery amount (required for TIMEOUT, 0 otherwise)
     * @param nLockTime           lock time for TIMEOUT (-1 or 0 if not applicable)
     * @param pp1OutputIndex      index of PP1 output in tokenTx (default 1)
     * @param pp2OutputIndex      index of PP2 output in tokenTx (default 2)
     */
    public Transaction createWitnessTxn(
            SigningCallback signerCallback,
            PublicKey signerPubKey,
            Transaction fundingTx,
            Transaction tokenTx,
            byte[] parentTokenTxBytes,
            PublicKey operatorPubkey,
            byte[] tokenChangePKH,
            StateMachineAction action,
            byte[] eventData,
            long counterpartyShareAmount,
            long operatorShareAmount,
            long recoveryAmount,
            int nLockTime,
            int pp1OutputIndex,
            int pp2OutputIndex,
            byte[] rabinN,
            byte[] rabinS,
            int rabinPadding,
            byte[] identityTxId,
            byte[] ed25519PubKey)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        TransactionSigner signer = SignerAdapter.fromCallback(signerCallback, signerPubKey, sigHashAll);

        ModP2PKHLockBuilder witnessLocker = new ModP2PKHLockBuilder(operatorPubkey.getPubKeyHash());
        PP2UnlockBuilder pp2Unlocker = PP2UnlockBuilder.forNormal(tokenTx.getTransactionIdBytes());
        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(signerPubKey);
        DefaultUnlockBuilder emptyUnlocker = new DefaultUnlockBuilder();

        // For TIMEOUT, nSequence must be < MAX to enable nLockTime
        long seqNum = nLockTime > 0
                ? TransactionInput.MAX_SEQ_NUMBER - 1
                : TransactionInput.MAX_SEQ_NUMBER;

        // First pass: build with empty PP1 unlocker to get preimage
        TransactionBuilder preImageBuilder = new TransactionBuilder()
                .spendFromTransaction(signer, fundingTx, 1, seqNum, fundingUnlocker)
                .spendFromTransaction(signer, tokenTx, pp1OutputIndex, seqNum, emptyUnlocker)
                .spendFromTransaction(tokenTx, pp2OutputIndex, seqNum, pp2Unlocker)
                .spendTo(witnessLocker, BigInteger.ONE);
        preImageBuilder.setFee(BigInteger.valueOf(100));
        if (nLockTime > 0) {
            preImageBuilder.lockUntilBlockHeight(nLockTime);
        }
        Transaction preImageTxn = preImageBuilder.build(false);

        Script subscript = tokenTx.getOutputs().get(pp1OutputIndex).getScript();
        byte[] preImagePP1 = new SigHash().getSighashPreimage(preImageTxn, sigHashAll, 1, subscript, BigInteger.ONE);

        TransactionUtils tsl1 = new TransactionUtils();
        byte[] tokenTxLHS = tsl1.getTxLHS(tokenTx);
        byte[] paddingBytes = new byte[1];
        byte[] pp2Output = tokenTx.getOutputs().get(pp2OutputIndex).serialize();
        long tokenChangeAmount = tokenTx.getOutputs().get(0).getAmount().longValue();

        UnlockingScriptBuilder pp1Unlocker = buildPP1SmUnlocker(
                action, preImagePP1, pp2Output, operatorPubkey, tokenChangePKH,
                tokenChangeAmount, tokenTxLHS, parentTokenTxBytes, paddingBytes,
                getOutpoint(fundingTx.getTransactionIdBytes()), eventData,
                counterpartyShareAmount, operatorShareAmount, recoveryAmount,
                null, null,
                rabinN, rabinS, rabinPadding, identityTxId, ed25519PubKey);

        TransactionBuilder witnessBuilder1 = new TransactionBuilder()
                .spendFromTransaction(signer, fundingTx, 1, seqNum, fundingUnlocker)
                .spendFromTransaction(signer, tokenTx, pp1OutputIndex, seqNum, pp1Unlocker)
                .spendFromTransaction(tokenTx, pp2OutputIndex, seqNum, pp2Unlocker)
                .spendTo(witnessLocker, BigInteger.ONE);
        if (nLockTime > 0) {
            witnessBuilder1.lockUntilBlockHeight(nLockTime);
        }
        Transaction witnessTx = witnessBuilder1.build(false);

        // Recalculate padding
        paddingBytes = tsl1.calculatePaddingBytes(witnessTx);

        pp1Unlocker = buildPP1SmUnlocker(
                action, preImagePP1, pp2Output, operatorPubkey, tokenChangePKH,
                tokenChangeAmount, tokenTxLHS, parentTokenTxBytes, paddingBytes,
                getOutpoint(fundingTx.getTransactionIdBytes()), eventData,
                counterpartyShareAmount, operatorShareAmount, recoveryAmount,
                null, null,
                rabinN, rabinS, rabinPadding, identityTxId, ed25519PubKey);

        TransactionBuilder witnessBuilder2 = new TransactionBuilder()
                .spendFromTransaction(signer, fundingTx, 1, seqNum, fundingUnlocker)
                .spendFromTransaction(signer, tokenTx, pp1OutputIndex, seqNum, pp1Unlocker)
                .spendFromTransaction(tokenTx, pp2OutputIndex, seqNum, pp2Unlocker)
                .spendTo(witnessLocker, BigInteger.ONE);
        if (nLockTime > 0) {
            witnessBuilder2.lockUntilBlockHeight(nLockTime);
        }
        witnessTx = witnessBuilder2.build(false);

        return witnessTx;
    }

    /**
     * Creates a witness transaction for a dual-sig SM operation (CONFIRM, CONVERT).
     *
     * <p>Two-pass: builds tx to compute sighash, signs with both keys, rebuilds.
     *
     * @param operatorCallback    callback that signs sighash digests for the operator key
     * @param operatorPubKeyForSigning public key corresponding to the operator signer
     * @param counterpartyPrivateKey  counterparty's private key for dual-signature
     * @param fundingTx           funding transaction
     * @param tokenTx             the token transaction being witnessed
     * @param parentTokenTxBytes  raw bytes of the parent token transaction
     * @param operatorPubkey      operator's public key
     * @param counterpartyPubkey  counterparty's public key
     * @param tokenChangePKH      20-byte HASH160 for witness change output
     * @param action              must be CONFIRM or CONVERT
     * @param eventData           event data bytes for state machine transitions
     */
    public Transaction createDualWitnessTxn(
            SigningCallback operatorCallback,
            PublicKey operatorPubKeyForSigning,
            PrivateKey counterpartyPrivateKey,
            Transaction fundingTx,
            Transaction tokenTx,
            byte[] parentTokenTxBytes,
            PublicKey operatorPubkey,
            PublicKey counterpartyPubkey,
            byte[] tokenChangePKH,
            StateMachineAction action,
            byte[] eventData)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        TransactionSigner operatorSigner = SignerAdapter.fromCallback(operatorCallback, operatorPubKeyForSigning, sigHashAll);

        ModP2PKHLockBuilder witnessLocker = new ModP2PKHLockBuilder(operatorPubkey.getPubKeyHash());
        PP2UnlockBuilder pp2Unlocker = PP2UnlockBuilder.forNormal(tokenTx.getTransactionIdBytes());
        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(operatorPubKeyForSigning);
        DefaultUnlockBuilder emptyUnlocker = new DefaultUnlockBuilder();

        // First pass: build tx to get sighash preimage
        TransactionBuilder preImageBuilder = new TransactionBuilder()
                .spendFromTransaction(operatorSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(operatorSigner, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
                .spendFromTransaction(tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, pp2Unlocker)
                .spendTo(witnessLocker, BigInteger.ONE);
        preImageBuilder.setFee(BigInteger.valueOf(100));
        Transaction preImageTxn = preImageBuilder.build(false);

        Script subscript = tokenTx.getOutputs().get(1).getScript();
        byte[] preImagePP1 = new SigHash().getSighashPreimage(preImageTxn, sigHashAll, 1, subscript, BigInteger.ONE);

        // Compute counterparty signature off-chain (same sighash preimage)
        TransactionSignature counterpartySig = new TransactionSigner(sigHashAll, counterpartyPrivateKey)
                .signPreimage(counterpartyPrivateKey, preImagePP1, sigHashAll);
        byte[] counterpartySigBytes = counterpartySig.toTxFormat();

        TransactionUtils tsl1 = new TransactionUtils();
        byte[] tokenTxLHS = tsl1.getTxLHS(tokenTx);
        byte[] paddingBytes = new byte[1];
        byte[] pp2Output = tokenTx.getOutputs().get(2).serialize();
        long tokenChangeAmount = tokenTx.getOutputs().get(0).getAmount().longValue();

        UnlockingScriptBuilder pp1Unlocker = buildPP1SmUnlocker(
                action, preImagePP1, pp2Output, operatorPubkey, tokenChangePKH,
                tokenChangeAmount, tokenTxLHS, parentTokenTxBytes, paddingBytes,
                getOutpoint(fundingTx.getTransactionIdBytes()), eventData,
                0, 0, 0,
                counterpartyPubkey, counterpartySigBytes,
                null, null, 0, null, null);

        Transaction witnessTx = new TransactionBuilder()
                .spendFromTransaction(operatorSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(operatorSigner, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, pp1Unlocker)
                .spendFromTransaction(tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, pp2Unlocker)
                .spendTo(witnessLocker, BigInteger.ONE)
                .build(false);

        // Recalculate padding
        paddingBytes = tsl1.calculatePaddingBytes(witnessTx);

        pp1Unlocker = buildPP1SmUnlocker(
                action, preImagePP1, pp2Output, operatorPubkey, tokenChangePKH,
                tokenChangeAmount, tokenTxLHS, parentTokenTxBytes, paddingBytes,
                getOutpoint(fundingTx.getTransactionIdBytes()), eventData,
                0, 0, 0,
                counterpartyPubkey, counterpartySigBytes,
                null, null, 0, null, null);

        witnessTx = new TransactionBuilder()
                .spendFromTransaction(operatorSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(operatorSigner, tokenTx, 1, TransactionInput.MAX_SEQ_NUMBER, pp1Unlocker)
                .spendFromTransaction(tokenTx, 2, TransactionInput.MAX_SEQ_NUMBER, pp2Unlocker)
                .spendTo(witnessLocker, BigInteger.ONE)
                .build(false);

        return witnessTx;
    }

    /**
     * Creates an enroll token transaction (INIT to ACTIVE).
     *
     * <p>Operator signs. 5-output structure: Change, PP1_SM, PP2, PP3, Metadata.
     * ownerPKH updates to counterpartyPKH (counterparty acts next).
     *
     * @param prevWitnessTx       the previous witness transaction
     * @param prevTokenTx         the previous token transaction
     * @param operatorPubkey      operator's public key
     * @param fundingTx           funding transaction
     * @param fundingSigner       callback that signs sighash digests for the funding key
     * @param fundingPubKey       public key corresponding to the funding signer
     * @param witnessFundingTxId  txid for the next witness funding
     * @param eventData           enrollment event data
     * @param tokenId             the token identifier (32 bytes)
     * @param operatorPKH         20-byte HASH160 of the operator
     * @param counterpartyPKH     20-byte HASH160 of the counterparty
     * @param state               current state value from previous PP1_SM
     * @param checkpointCount     current checkpoint count from previous PP1_SM
     * @param commitmentHash      current commitment hash from previous PP1_SM (32 bytes)
     * @param transitionBitmask   transition bitmask from previous PP1_SM
     * @param timeoutDelta        timeout delta from previous PP1_SM
     */
    public Transaction createEnrollTxn(
            Transaction prevWitnessTx,
            Transaction prevTokenTx,
            PublicKey operatorPubkey,
            Transaction fundingTx,
            SigningCallback fundingSigner,
            PublicKey fundingPubKey,
            byte[] witnessFundingTxId,
            byte[] eventData,
            byte[] tokenId,
            byte[] operatorPKH,
            byte[] counterpartyPKH,
            int state,
            int checkpointCount,
            byte[] commitmentHash,
            int transitionBitmask,
            int timeoutDelta)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        TransactionSigner fundingTxSigner = SignerAdapter.fromCallback(fundingSigner, fundingPubKey, sigHashAll);

        Address operatorAddress = Address.fromKey(networkAddressType, operatorPubkey);

        // New ownerPKH = counterpartyPKH (counterparty acts next)
        Address counterpartyAddress = LegacyAddress.fromPubKeyHash(networkAddressType, counterpartyPKH);

        // Compute new commitment hash:
        // eventDigest = SHA256(eventData)
        // newCommitHash = SHA256(parentCommitHash || eventDigest)
        byte[] eventDigest = sha256(eventData);
        byte[] combined = new byte[commitmentHash.length + eventDigest.length];
        System.arraycopy(commitmentHash, 0, combined, 0, commitmentHash.length);
        System.arraycopy(eventDigest, 0, combined, commitmentHash.length, eventDigest.length);
        byte[] newCommitHash = sha256(combined);

        // Extract rabinPubKeyHash from parent PP1_SM script at byte offset [97:117]
        byte[] parentPP1Bytes = prevTokenTx.getOutputs().get(1).getScript().getProgram();
        byte[] rabinPubKeyHash = new byte[20];
        System.arraycopy(parentPP1Bytes, 97, rabinPubKeyHash, 0, 20);

        PP1SmLockBuilder pp1Locker = new PP1SmLockBuilder(
                counterpartyPKH, tokenId, operatorPKH, counterpartyPKH, rabinPubKeyHash,
                1, checkpointCount, newCommitHash,
                transitionBitmask, timeoutDelta);

        PP2LockBuilder pp2Locker = new PP2LockBuilder(
                getOutpoint(witnessFundingTxId), counterpartyPKH, 1, counterpartyPKH);
        PartialWitnessLockBuilder shaLocker = new PartialWitnessLockBuilder(counterpartyPKH);

        DefaultLockBuilder metadataLocker = new DefaultLockBuilder(
                prevTokenTx.getOutputs().get(4).getScript());

        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(fundingPubKey);
        ModP2PKHUnlockBuilder prevWitnessUnlocker = new ModP2PKHUnlockBuilder(operatorPubkey);
        DefaultUnlockBuilder emptyUnlocker = new DefaultUnlockBuilder();

        // First build to compute PP3 spending sighash
        TransactionBuilder childPreImageBuilder = new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
                .spendFromTransaction(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
                .spendTo(pp1Locker, BigInteger.ONE)
                .spendTo(pp2Locker, BigInteger.ONE)
                .spendTo(shaLocker, BigInteger.ONE)
                .spendTo(metadataLocker, BigInteger.ZERO)
                .sendChangeTo(operatorAddress);
        childPreImageBuilder.setFee(defaultFee);
        Transaction childPreImageTxn = childPreImageBuilder.build(false);

        Script pp3Subscript = prevTokenTx.getOutputs().get(3).getScript();
        byte[] sigPreImage = new SigHash().getSighashPreimage(childPreImageTxn, sigHashAll, 2, pp3Subscript, BigInteger.ONE);

        TransactionUtils tsl1 = new TransactionUtils();
        byte[][] partialResult = tsl1.computePartialHash(prevWitnessTx.serialize(), 2);

        PartialWitnessUnlockBuilder sha256Unlocker = PartialWitnessUnlockBuilder.forUnlock(
                sigPreImage, partialResult[0], partialResult[1], getOutpoint(fundingTx.getTransactionIdBytes()));

        // Final build with PP3 unlocker
        TransactionBuilder childTxBuilder = new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
                .spendFromTransaction(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, sha256Unlocker)
                .spendTo(pp1Locker, BigInteger.ONE)
                .spendTo(pp2Locker, BigInteger.ONE)
                .spendTo(shaLocker, BigInteger.ONE)
                .spendTo(metadataLocker, BigInteger.ZERO)
                .sendChangeTo(operatorAddress);
        childTxBuilder.setFee(defaultFee);
        return childTxBuilder.build(false);
    }

    /**
     * Creates a generic state transition token transaction.
     *
     * <p>Used for confirm, convert, settle, timeout transitions.
     * Spends PP3 from prevTokenTx, creates 5-output structure:
     * Change, PP1_SM, PP2, PP3, Metadata.
     *
     * @param prevWitnessTx       the previous witness transaction
     * @param prevTokenTx         the previous token transaction
     * @param signerPubkey        public key of the signer (current actor)
     * @param fundingTx           funding transaction
     * @param fundingSigner       callback that signs sighash digests for the funding key
     * @param fundingPubKey       public key corresponding to the funding signer
     * @param witnessFundingTxId  txid for the next witness funding
     * @param newState            the post-transition state value
     * @param newOwnerPKH         20-byte PKH for the next expected actor
     * @param incrementCheckpoint  if true, checkpointCount is incremented
     * @param eventData           operation-specific data (null for timeout)
     * @param tokenId             the token identifier (32 bytes)
     * @param operatorPKH         20-byte HASH160 of the operator
     * @param counterpartyPKH     20-byte HASH160 of the counterparty
     * @param state               current state value from previous PP1_SM (unused but kept for context)
     * @param checkpointCount     current checkpoint count from previous PP1_SM
     * @param commitmentHash      current commitment hash from previous PP1_SM (32 bytes)
     * @param transitionBitmask   transition bitmask from previous PP1_SM
     * @param timeoutDelta        timeout delta from previous PP1_SM
     */
    public Transaction createTransitionTxn(
            Transaction prevWitnessTx,
            Transaction prevTokenTx,
            PublicKey signerPubkey,
            Transaction fundingTx,
            SigningCallback fundingSigner,
            PublicKey fundingPubKey,
            byte[] witnessFundingTxId,
            int newState,
            byte[] newOwnerPKH,
            boolean incrementCheckpoint,
            byte[] eventData,
            byte[] tokenId,
            byte[] operatorPKH,
            byte[] counterpartyPKH,
            int state,
            int checkpointCount,
            byte[] commitmentHash,
            int transitionBitmask,
            int timeoutDelta)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        TransactionSigner fundingTxSigner = SignerAdapter.fromCallback(fundingSigner, fundingPubKey, sigHashAll);

        Address signerAddress = Address.fromKey(networkAddressType, signerPubkey);
        Address newOwnerAddress = LegacyAddress.fromPubKeyHash(networkAddressType, newOwnerPKH);

        // Compute new commitment hash
        byte[] newCommitHash;
        if (eventData != null) {
            byte[] eventDigest = sha256(eventData);
            byte[] combined = new byte[commitmentHash.length + eventDigest.length];
            System.arraycopy(commitmentHash, 0, combined, 0, commitmentHash.length);
            System.arraycopy(eventDigest, 0, combined, commitmentHash.length, eventDigest.length);
            newCommitHash = sha256(combined);
        } else {
            newCommitHash = commitmentHash.clone();
        }

        int newMC = incrementCheckpoint ? checkpointCount + 1 : checkpointCount;

        // Extract rabinPubKeyHash from parent PP1_SM script at byte offset [97:117]
        byte[] parentPP1Bytes = prevTokenTx.getOutputs().get(1).getScript().getProgram();
        byte[] rabinPubKeyHash = new byte[20];
        System.arraycopy(parentPP1Bytes, 97, rabinPubKeyHash, 0, 20);

        PP1SmLockBuilder pp1Locker = new PP1SmLockBuilder(
                newOwnerPKH, tokenId, operatorPKH, counterpartyPKH, rabinPubKeyHash,
                newState, newMC, newCommitHash,
                transitionBitmask, timeoutDelta);

        PP2LockBuilder pp2Locker = new PP2LockBuilder(
                getOutpoint(witnessFundingTxId), newOwnerPKH, 1, newOwnerPKH);
        PartialWitnessLockBuilder shaLocker = new PartialWitnessLockBuilder(newOwnerPKH);

        DefaultLockBuilder metadataLocker = new DefaultLockBuilder(
                prevTokenTx.getOutputs().get(4).getScript());

        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(fundingPubKey);
        ModP2PKHUnlockBuilder prevWitnessUnlocker = new ModP2PKHUnlockBuilder(signerPubkey);
        DefaultUnlockBuilder emptyUnlocker = new DefaultUnlockBuilder();

        // First build to compute PP3 spending sighash
        TransactionBuilder childPreImageBuilder = new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
                .spendFromTransaction(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
                .spendTo(pp1Locker, BigInteger.ONE)
                .spendTo(pp2Locker, BigInteger.ONE)
                .spendTo(shaLocker, BigInteger.ONE)
                .spendTo(metadataLocker, BigInteger.ZERO)
                .sendChangeTo(signerAddress);
        childPreImageBuilder.setFee(defaultFee);
        Transaction childPreImageTxn = childPreImageBuilder.build(false);

        Script pp3Subscript = prevTokenTx.getOutputs().get(3).getScript();
        byte[] sigPreImage = new SigHash().getSighashPreimage(childPreImageTxn, sigHashAll, 2, pp3Subscript, BigInteger.ONE);

        TransactionUtils tsl1 = new TransactionUtils();
        byte[][] partialResult = tsl1.computePartialHash(prevWitnessTx.serialize(), 2);

        PartialWitnessUnlockBuilder sha256Unlocker = PartialWitnessUnlockBuilder.forUnlock(
                sigPreImage, partialResult[0], partialResult[1], getOutpoint(fundingTx.getTransactionIdBytes()));

        // Final build with PP3 unlocker
        TransactionBuilder childTxBuilder = new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
                .spendFromTransaction(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, sha256Unlocker)
                .spendTo(pp1Locker, BigInteger.ONE)
                .spendTo(pp2Locker, BigInteger.ONE)
                .spendTo(shaLocker, BigInteger.ONE)
                .spendTo(metadataLocker, BigInteger.ZERO)
                .sendChangeTo(signerAddress);
        childTxBuilder.setFee(defaultFee);
        return childTxBuilder.build(false);
    }

    /**
     * Creates a settle token transaction (CONVERTING to SETTLED, 7-output topology).
     *
     * <p>7-output structure: Change(0), CounterpartyShare(1), OperatorShare(2),
     * PP1_SM(3), PP2(4), PP3(5), Metadata(6).
     *
     * <p>Counterparty share and operator share are P2PKH outputs using the immutable
     * counterpartyPKH and operatorPKH from the PP1_SM header.
     *
     * @param prevWitnessTx       the previous witness transaction
     * @param prevTokenTx         the previous token transaction
     * @param signerPubkey        public key of the signer
     * @param fundingTx           funding transaction
     * @param fundingSigner       callback that signs sighash digests for the funding key
     * @param fundingPubKey       public key corresponding to the funding signer
     * @param witnessFundingTxId  txid for the next witness funding
     * @param counterpartyShareAmount    satoshi amount distributed to the counterparty
     * @param operatorShareAmount       satoshi amount distributed to the operator
     * @param eventData           optional event data (may be null)
     * @param tokenId             the token identifier (32 bytes)
     * @param operatorPKH         20-byte HASH160 of the operator
     * @param counterpartyPKH     20-byte HASH160 of the counterparty
     * @param state               current state value from previous PP1_SM
     * @param checkpointCount     current checkpoint count from previous PP1_SM
     * @param commitmentHash      current commitment hash from previous PP1_SM (32 bytes)
     * @param transitionBitmask   transition bitmask from previous PP1_SM
     * @param timeoutDelta        timeout delta from previous PP1_SM
     */
    public Transaction createSettleTxn(
            Transaction prevWitnessTx,
            Transaction prevTokenTx,
            PublicKey signerPubkey,
            Transaction fundingTx,
            SigningCallback fundingSigner,
            PublicKey fundingPubKey,
            byte[] witnessFundingTxId,
            BigInteger counterpartyShareAmount,
            BigInteger operatorShareAmount,
            byte[] eventData,
            byte[] tokenId,
            byte[] operatorPKH,
            byte[] counterpartyPKH,
            int state,
            int checkpointCount,
            byte[] commitmentHash,
            int transitionBitmask,
            int timeoutDelta)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        TransactionSigner fundingTxSigner = SignerAdapter.fromCallback(fundingSigner, fundingPubKey, sigHashAll);

        Address signerAddress = Address.fromKey(networkAddressType, signerPubkey);

        // Operator owns settled token (terminal state)
        byte[] newOwnerPKH = operatorPKH;
        Address newOwnerAddress = LegacyAddress.fromPubKeyHash(networkAddressType, newOwnerPKH);

        // Compute new commitment hash
        byte[] newCommitHash;
        if (eventData != null) {
            byte[] eventDigest = sha256(eventData);
            byte[] combined = new byte[commitmentHash.length + eventDigest.length];
            System.arraycopy(commitmentHash, 0, combined, 0, commitmentHash.length);
            System.arraycopy(eventDigest, 0, combined, commitmentHash.length, eventDigest.length);
            newCommitHash = sha256(combined);
        } else {
            newCommitHash = commitmentHash.clone();
        }

        // P2PKH outputs for counterparty share and operator share
        Address counterpartyShareAddress = LegacyAddress.fromPubKeyHash(networkAddressType, counterpartyPKH);
        Address operatorShareAddress = LegacyAddress.fromPubKeyHash(networkAddressType, operatorPKH);
        P2PKHLockBuilder counterpartyShareLocker = new P2PKHLockBuilder(counterpartyShareAddress);
        P2PKHLockBuilder operatorShareLocker = new P2PKHLockBuilder(operatorShareAddress);

        // Extract rabinPubKeyHash from parent PP1_SM script at byte offset [97:117]
        byte[] parentPP1Bytes = prevTokenTx.getOutputs().get(1).getScript().getProgram();
        byte[] rabinPubKeyHash = new byte[20];
        System.arraycopy(parentPP1Bytes, 97, rabinPubKeyHash, 0, 20);

        PP1SmLockBuilder pp1Locker = new PP1SmLockBuilder(
                newOwnerPKH, tokenId, operatorPKH, counterpartyPKH, rabinPubKeyHash,
                4, checkpointCount, newCommitHash,
                transitionBitmask, timeoutDelta);

        PP2LockBuilder pp2Locker = new PP2LockBuilder(
                getOutpoint(witnessFundingTxId), newOwnerPKH, 1, newOwnerPKH);
        PartialWitnessLockBuilder shaLocker = new PartialWitnessLockBuilder(newOwnerPKH);

        DefaultLockBuilder metadataLocker = new DefaultLockBuilder(
                prevTokenTx.getOutputs().get(4).getScript());

        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(fundingPubKey);
        ModP2PKHUnlockBuilder prevWitnessUnlocker = new ModP2PKHUnlockBuilder(signerPubkey);
        DefaultUnlockBuilder emptyUnlocker = new DefaultUnlockBuilder();

        // First build to compute PP3 spending sighash
        TransactionBuilder childPreImageBuilder = new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
                .spendFromTransaction(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, emptyUnlocker)
                .spendTo(counterpartyShareLocker, counterpartyShareAmount)
                .spendTo(operatorShareLocker, operatorShareAmount)
                .spendTo(pp1Locker, BigInteger.ONE)
                .spendTo(pp2Locker, BigInteger.ONE)
                .spendTo(shaLocker, BigInteger.ONE)
                .spendTo(metadataLocker, BigInteger.ZERO)
                .sendChangeTo(signerAddress);
        childPreImageBuilder.setFee(defaultFee);
        Transaction childPreImageTxn = childPreImageBuilder.build(false);

        Script pp3Subscript = prevTokenTx.getOutputs().get(3).getScript();
        byte[] sigPreImage = new SigHash().getSighashPreimage(childPreImageTxn, sigHashAll, 2, pp3Subscript, BigInteger.ONE);

        TransactionUtils tsl1 = new TransactionUtils();
        byte[][] partialResult = tsl1.computePartialHash(prevWitnessTx.serialize(), 2);

        PartialWitnessUnlockBuilder sha256Unlocker = PartialWitnessUnlockBuilder.forUnlock(
                sigPreImage, partialResult[0], partialResult[1], getOutpoint(fundingTx.getTransactionIdBytes()));

        // Final build with PP3 unlocker
        TransactionBuilder childTxBuilder = new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(fundingTxSigner, prevWitnessTx, 0, TransactionInput.MAX_SEQ_NUMBER, prevWitnessUnlocker)
                .spendFromTransaction(prevTokenTx, 3, TransactionInput.MAX_SEQ_NUMBER, sha256Unlocker)
                .spendTo(counterpartyShareLocker, counterpartyShareAmount)
                .spendTo(operatorShareLocker, operatorShareAmount)
                .spendTo(pp1Locker, BigInteger.ONE)
                .spendTo(pp2Locker, BigInteger.ONE)
                .spendTo(shaLocker, BigInteger.ONE)
                .spendTo(metadataLocker, BigInteger.ZERO)
                .sendChangeTo(signerAddress);
        childTxBuilder.setFee(defaultFee);
        return childTxBuilder.build(false);
    }

    /**
     * Creates a timeout token transaction (any non-terminal to EXPIRED, 6-output topology).
     *
     * <p>6-output structure: Change(0), OperatorRecovery(1), PP1_SM(2), PP2(3), PP3(4), Metadata(5).
     *
     * <p>Operator recovery is a P2PKH output using the immutable operatorPKH from the header.
     * nLockTime is set to enforce the timeout window.
     *
     * @param prevWitnessTx       the previous witness transaction
     * @param prevTokenTx         the previous token transaction
     * @param signerPubkey        public key of the signer
     * @param fundingTx           funding transaction
     * @param fundingSigner       callback that signs sighash digests for the funding key
     * @param fundingPubKey       public key corresponding to the funding signer
     * @param witnessFundingTxId  txid for the next witness funding
     * @param recoveryAmount        satoshi amount to recover to the operator
     * @param nLockTime           block height for nLockTime enforcement
     * @param tokenId             the token identifier (32 bytes)
     * @param operatorPKH         20-byte HASH160 of the operator
     * @param counterpartyPKH     20-byte HASH160 of the counterparty
     * @param state               current state value from previous PP1_SM
     * @param checkpointCount     current checkpoint count from previous PP1_SM
     * @param commitmentHash      current commitment hash from previous PP1_SM (32 bytes)
     * @param transitionBitmask   transition bitmask from previous PP1_SM
     * @param timeoutDelta        timeout delta from previous PP1_SM
     */
    public Transaction createTimeoutTxn(
            Transaction prevWitnessTx,
            Transaction prevTokenTx,
            PublicKey signerPubkey,
            Transaction fundingTx,
            SigningCallback fundingSigner,
            PublicKey fundingPubKey,
            byte[] witnessFundingTxId,
            BigInteger recoveryAmount,
            int nLockTime,
            byte[] tokenId,
            byte[] operatorPKH,
            byte[] counterpartyPKH,
            int state,
            int checkpointCount,
            byte[] commitmentHash,
            int transitionBitmask,
            int timeoutDelta)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        TransactionSigner fundingTxSigner = SignerAdapter.fromCallback(fundingSigner, fundingPubKey, sigHashAll);

        Address signerAddress = Address.fromKey(networkAddressType, signerPubkey);

        // Operator owns expired token (terminal state)
        byte[] newOwnerPKH = operatorPKH;
        Address newOwnerAddress = LegacyAddress.fromPubKeyHash(networkAddressType, newOwnerPKH);

        // Timeout preserves parent's commitment hash (no update)
        byte[] parentCommitHash = commitmentHash.clone();

        // Operator recovery P2PKH output
        Address operatorRecoveryAddress = LegacyAddress.fromPubKeyHash(networkAddressType, operatorPKH);
        P2PKHLockBuilder operatorRecoveryLocker = new P2PKHLockBuilder(operatorRecoveryAddress);

        // Extract rabinPubKeyHash from parent PP1_SM script at byte offset [97:117]
        byte[] parentPP1Bytes = prevTokenTx.getOutputs().get(1).getScript().getProgram();
        byte[] rabinPubKeyHash = new byte[20];
        System.arraycopy(parentPP1Bytes, 97, rabinPubKeyHash, 0, 20);

        PP1SmLockBuilder pp1Locker = new PP1SmLockBuilder(
                newOwnerPKH, tokenId, operatorPKH, counterpartyPKH, rabinPubKeyHash,
                5, checkpointCount, parentCommitHash,
                transitionBitmask, timeoutDelta);

        PP2LockBuilder pp2Locker = new PP2LockBuilder(
                getOutpoint(witnessFundingTxId), newOwnerPKH, 1, newOwnerPKH);
        PartialWitnessLockBuilder shaLocker = new PartialWitnessLockBuilder(newOwnerPKH);

        DefaultLockBuilder metadataLocker = new DefaultLockBuilder(
                prevTokenTx.getOutputs().get(4).getScript());

        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(fundingPubKey);
        ModP2PKHUnlockBuilder prevWitnessUnlocker = new ModP2PKHUnlockBuilder(signerPubkey);
        DefaultUnlockBuilder emptyUnlocker = new DefaultUnlockBuilder();

        // nSequence must be < MAX for nLockTime to be enforced
        long lockTimeSeq = TransactionInput.MAX_SEQ_NUMBER - 1;

        // First build to compute PP3 spending sighash
        TransactionBuilder childPreImageBuilder = new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, lockTimeSeq, fundingUnlocker)
                .spendFromTransaction(fundingTxSigner, prevWitnessTx, 0, lockTimeSeq, prevWitnessUnlocker)
                .spendFromTransaction(prevTokenTx, 3, lockTimeSeq, emptyUnlocker)
                .spendTo(operatorRecoveryLocker, recoveryAmount)
                .spendTo(pp1Locker, BigInteger.ONE)
                .spendTo(pp2Locker, BigInteger.ONE)
                .spendTo(shaLocker, BigInteger.ONE)
                .spendTo(metadataLocker, BigInteger.ZERO)
                .sendChangeTo(signerAddress)
                .lockUntilBlockHeight(nLockTime);
        childPreImageBuilder.setFee(defaultFee);
        Transaction childPreImageTxn = childPreImageBuilder.build(false);

        Script pp3Subscript = prevTokenTx.getOutputs().get(3).getScript();
        byte[] sigPreImage = new SigHash().getSighashPreimage(childPreImageTxn, sigHashAll, 2, pp3Subscript, BigInteger.ONE);

        TransactionUtils tsl1 = new TransactionUtils();
        byte[][] partialResult = tsl1.computePartialHash(prevWitnessTx.serialize(), 2);

        PartialWitnessUnlockBuilder sha256Unlocker = PartialWitnessUnlockBuilder.forUnlock(
                sigPreImage, partialResult[0], partialResult[1], getOutpoint(fundingTx.getTransactionIdBytes()));

        // Final build with PP3 unlocker
        TransactionBuilder childTxBuilder = new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, lockTimeSeq, fundingUnlocker)
                .spendFromTransaction(fundingTxSigner, prevWitnessTx, 0, lockTimeSeq, prevWitnessUnlocker)
                .spendFromTransaction(prevTokenTx, 3, lockTimeSeq, sha256Unlocker)
                .spendTo(operatorRecoveryLocker, recoveryAmount)
                .spendTo(pp1Locker, BigInteger.ONE)
                .spendTo(pp2Locker, BigInteger.ONE)
                .spendTo(shaLocker, BigInteger.ONE)
                .spendTo(metadataLocker, BigInteger.ZERO)
                .sendChangeTo(signerAddress)
                .lockUntilBlockHeight(nLockTime);
        childTxBuilder.setFee(defaultFee);
        return childTxBuilder.build(false);
    }

    /**
     * Creates a burn transaction for an SM token in terminal state (SETTLED or EXPIRED).
     *
     * <p>Owner signs. Spends PP1_SM, PP2, and PartialWitness outputs.
     *
     * @param tokenTx          the token transaction to burn
     * @param ownerCallback    callback that signs sighash digests for the owner key
     * @param ownerPubkey      owner's public key
     * @param fundingTx        funding transaction
     * @param fundingCallback  callback that signs sighash digests for the funding key
     * @param fundingPubKey    public key corresponding to the funding signer
     * @param pp1OutputIndex   index of PP1 output in tokenTx (default 1)
     * @param pp2OutputIndex   index of PP2 output in tokenTx (default 2)
     * @param pp3OutputIndex   index of PP3 output in tokenTx (default 3)
     */
    public Transaction createBurnTokenTxn(
            Transaction tokenTx,
            SigningCallback ownerCallback,
            PublicKey ownerPubkey,
            Transaction fundingTx,
            SigningCallback fundingCallback,
            PublicKey fundingPubKey,
            int pp1OutputIndex,
            int pp2OutputIndex,
            int pp3OutputIndex)
            throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        TransactionSigner ownerSigner = SignerAdapter.fromCallback(ownerCallback, ownerPubkey, sigHashAll);
        TransactionSigner fundingTxSigner = SignerAdapter.fromCallback(fundingCallback, fundingPubKey, sigHashAll);

        Address ownerAddress = Address.fromKey(networkAddressType, ownerPubkey);
        P2PKHUnlockBuilder fundingUnlocker = new P2PKHUnlockBuilder(fundingPubKey);

        TransactionBuilder burnBuilder = new TransactionBuilder()
                .spendFromTransaction(fundingTxSigner, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, fundingUnlocker)
                .spendFromTransaction(ownerSigner, tokenTx, pp1OutputIndex, TransactionInput.MAX_SEQ_NUMBER, PP1SmUnlockBuilder.forBurn(ownerPubkey))
                .spendFromTransaction(ownerSigner, tokenTx, pp2OutputIndex, TransactionInput.MAX_SEQ_NUMBER, PP2UnlockBuilder.forBurn(ownerPubkey))
                .spendFromTransaction(ownerSigner, tokenTx, pp3OutputIndex, TransactionInput.MAX_SEQ_NUMBER, PartialWitnessUnlockBuilder.forBurn(ownerPubkey))
                .sendChangeTo(ownerAddress);
        burnBuilder.setFee(defaultFee);
        return burnBuilder.build(false);
    }

    // --- Private helpers ---

    private UnlockingScriptBuilder buildPP1SmUnlocker(
            StateMachineAction action, byte[] preImage, byte[] pp2Output,
            PublicKey operatorPubkey, byte[] changePKH, long changeAmount,
            byte[] tokenLHS, byte[] prevTokenTx, byte[] paddingBytes,
            byte[] fundingOutpoint, byte[] eventData,
            long counterpartyShareAmount, long operatorShareAmount, long recoveryAmount,
            PublicKey counterpartyPubKey, byte[] counterpartySigBytes,
            byte[] rabinN, byte[] rabinS, int rabinPadding,
            byte[] identityTxId, byte[] ed25519PubKey) {

        switch (action) {
            case CREATE:
                return PP1SmUnlockBuilder.forCreate(preImage, fundingOutpoint, paddingBytes,
                        rabinN != null ? rabinN : new byte[0],
                        rabinS != null ? rabinS : new byte[0],
                        rabinPadding,
                        identityTxId != null ? identityTxId : new byte[0],
                        ed25519PubKey != null ? ed25519PubKey : new byte[0]);
            case ENROLL:
                return PP1SmUnlockBuilder.forEnroll(
                        preImage, pp2Output, operatorPubkey,
                        changePKH, changeAmount, eventData,
                        tokenLHS, prevTokenTx, paddingBytes);
            case CONFIRM:
                return PP1SmUnlockBuilder.forConfirm(
                        preImage, pp2Output, operatorPubkey,
                        changePKH, changeAmount,
                        counterpartyPubKey, counterpartySigBytes, eventData,
                        tokenLHS, prevTokenTx, paddingBytes);
            case CONVERT:
                return PP1SmUnlockBuilder.forConvert(
                        preImage, pp2Output, operatorPubkey,
                        changePKH, changeAmount,
                        counterpartyPubKey, counterpartySigBytes, eventData,
                        tokenLHS, prevTokenTx, paddingBytes);
            case SETTLE:
                return PP1SmUnlockBuilder.forSettle(
                        preImage, pp2Output, operatorPubkey,
                        changePKH, changeAmount,
                        counterpartyShareAmount, operatorShareAmount, eventData,
                        tokenLHS, prevTokenTx, paddingBytes);
            case TIMEOUT:
                return PP1SmUnlockBuilder.forTimeout(
                        preImage, pp2Output, operatorPubkey,
                        changePKH, changeAmount, recoveryAmount,
                        tokenLHS, prevTokenTx, paddingBytes);
            default:
                return PP1SmUnlockBuilder.forBurn(operatorPubkey);
        }
    }

    private static byte[] sha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}
