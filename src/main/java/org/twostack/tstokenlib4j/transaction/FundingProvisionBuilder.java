package org.twostack.tstokenlib4j.transaction;

import org.twostack.bitcoin4j.Address;
import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.exception.TransactionException;
import org.twostack.bitcoin4j.transaction.*;
import org.twostack.libspiffy4j.plugin.ProvisionedTransaction;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Builds a two-level fan-out of funding transactions from a single large UTXO.
 *
 * <p>Level 1 (split TX): fans the input into N earmark outputs + change.
 * Level 2 (earmark TXs): each earmark output produces a 2-output TX with
 * the target funding amount at vout=1 (satisfying PP1/PP3 hardcoded constraints).
 *
 * <p>All transactions are built in memory using chained spending — bitcoin4j
 * computes txids deterministically from serialization, so TX-B can reference
 * TX-A before either is broadcast.
 */
public final class FundingProvisionBuilder {

    // P2PKH transaction size constants (bytes)
    static final int TX_OVERHEAD = 10;       // 4 version + 1 inputCount + 1 outputCount + 4 locktime
    static final int P2PKH_INPUT = 148;      // 32 txid + 4 vout + 1 scriptLen + 107 scriptSig + 4 seq
    static final int P2PKH_OUTPUT = 34;      // 8 value + 1 scriptLen + 25 scriptPubKey
    static final int DUST_LIMIT = 546;       // BSV dust limit for P2PKH

    // Token transaction size estimates (bytes, verified on-chain)
    static final int ISSUANCE_WITNESS_SIZE = 3400;
    static final int TRANSFER_SIZE = 66600;
    static final int TRANSFER_WITNESS_SIZE = 70000;

    // Locked output amounts (sats)
    static final int WITNESS_LOCKED = 1;     // ModP2PKH output
    static final int TOKEN_TX_LOCKED = 3;    // PP1 + PP2 + PP3

    private FundingProvisionBuilder() {}

    /**
     * Provision funding for one or more token lifecycle steps.
     *
     * <p>Each lifecycle step (issue + witness + transfer + witness) requires
     * 3 earmark TXs. The issuance itself has no vout constraint and uses
     * the split TX change.
     *
     * @param fundingTx       the transaction providing the input UTXO
     * @param fundingVout     output index of the funding UTXO
     * @param fundingSigner   signs the split TX input (key that owns the funding UTXO)
     * @param fundingPubKey   public key for the funding UTXO
     * @param changeSigner    signs earmark TX inputs (key that owns changeAddress)
     * @param changePubKey    public key for changeAddress
     * @param changeAddress   destination for change and dust outputs
     * @param lifecycleSteps  number of issue+witness+transfer+witness cycles
     * @param feeRateSatsPerKb target fee rate in satoshis per kilobyte
     * @return ordered list of transactions for sequential broadcast (split first, then earmarks)
     */
    public static List<ProvisionedTransaction> provision(
            Transaction fundingTx, int fundingVout,
            SigningCallback fundingSigner, PublicKey fundingPubKey,
            SigningCallback changeSigner, PublicKey changePubKey,
            Address changeAddress,
            int lifecycleSteps, long feeRateSatsPerKb) {

        if (lifecycleSteps < 1) {
            throw new IllegalArgumentException("lifecycleSteps must be >= 1");
        }

        long issuanceWitnessFunding = computeFee(ISSUANCE_WITNESS_SIZE, feeRateSatsPerKb) + WITNESS_LOCKED;
        long transferFunding = computeFee(TRANSFER_SIZE, feeRateSatsPerKb) + TOKEN_TX_LOCKED;
        long transferWitnessFunding = computeFee(TRANSFER_WITNESS_SIZE, feeRateSatsPerKb) + WITNESS_LOCKED;

        int earmarkTxSize = TX_OVERHEAD + P2PKH_INPUT + 2 * P2PKH_OUTPUT;
        long earmarkFee = computeFee(earmarkTxSize, feeRateSatsPerKb);

        long splitOutIssuanceWitness = issuanceWitnessFunding + DUST_LIMIT + earmarkFee;
        long splitOutTransfer = transferFunding + DUST_LIMIT + earmarkFee;
        long splitOutTransferWitness = transferWitnessFunding + DUST_LIMIT + earmarkFee;

        int earmarkCount = 3 * lifecycleSteps;
        int splitOutputCount = earmarkCount + 1;
        int splitTxSize = TX_OVERHEAD + P2PKH_INPUT + splitOutputCount * P2PKH_OUTPUT;
        long splitFee = computeFee(splitTxSize, feeRateSatsPerKb);

        long totalEarmarkSats = lifecycleSteps * (splitOutIssuanceWitness + splitOutTransfer + splitOutTransferWitness);
        long inputSats = fundingTx.getOutputs().get(fundingVout).getAmount().longValue();
        long changeSats = inputSats - totalEarmarkSats - splitFee;

        if (changeSats < DUST_LIMIT) {
            throw new IllegalArgumentException(
                    "Insufficient funds: need " + (totalEarmarkSats + splitFee + DUST_LIMIT)
                    + " sats but input has " + inputSats);
        }

        try {
            return buildTree(fundingTx, fundingVout, fundingSigner, fundingPubKey,
                    changeSigner, changePubKey, changeAddress, lifecycleSteps,
                    earmarkFee, splitFee, changeSats,
                    splitOutIssuanceWitness, splitOutTransfer, splitOutTransferWitness,
                    issuanceWitnessFunding, transferFunding, transferWitnessFunding);
        } catch (Exception e) {
            throw new RuntimeException("Failed to build provision tree: " + e.getMessage(), e);
        }
    }

    private static List<ProvisionedTransaction> buildTree(
            Transaction fundingTx, int fundingVout,
            SigningCallback fundingSigner, PublicKey fundingPubKey,
            SigningCallback changeSigner, PublicKey changePubKey,
            Address changeAddress, int lifecycleSteps,
            long earmarkFee, long splitFee, long changeSats,
            long splitOutIssuanceWitness, long splitOutTransfer, long splitOutTransferWitness,
            long issuanceWitnessFunding, long transferFunding, long transferWitnessFunding)
            throws Exception {

        int sigHashAll = SigHashType.FORKID.value | SigHashType.ALL.value;
        TransactionSigner splitSigner = SignerAdapter.fromCallback(fundingSigner, fundingPubKey, sigHashAll);
        P2PKHUnlockBuilder splitUnlocker = new P2PKHUnlockBuilder(fundingPubKey);
        P2PKHLockBuilder changeLock = new P2PKHLockBuilder(changeAddress);

        // Level 1: Split TX
        TransactionBuilder splitBuilder = new TransactionBuilder();
        splitBuilder.spendFromTransaction(splitSigner, fundingTx, fundingVout,
                TransactionInput.MAX_SEQ_NUMBER, splitUnlocker);

        for (int step = 0; step < lifecycleSteps; step++) {
            splitBuilder.spendTo(changeLock, BigInteger.valueOf(splitOutIssuanceWitness));
            splitBuilder.spendTo(changeLock, BigInteger.valueOf(splitOutTransfer));
            splitBuilder.spendTo(changeLock, BigInteger.valueOf(splitOutTransferWitness));
        }
        splitBuilder.spendTo(changeLock, BigInteger.valueOf(changeSats));

        Transaction splitTx = splitBuilder.build(false);

        List<ProvisionedTransaction> results = new ArrayList<>();
        results.add(new ProvisionedTransaction(
                splitTx.getTransactionId(),
                Utils.HEX.encode(splitTx.serialize()),
                splitFee, "split", null, -1, -1));

        // Level 2: Earmark TXs
        String[] purposes = {"issuance-witness", "transfer", "transfer-witness"};
        long[] targets = {issuanceWitnessFunding, transferFunding, transferWitnessFunding};

        for (int step = 0; step < lifecycleSteps; step++) {
            for (int p = 0; p < 3; p++) {
                int splitOutputIndex = step * 3 + p;
                long targetSats = targets[p];
                long splitOutputSats = splitTx.getOutputs().get(splitOutputIndex).getAmount().longValue();
                long dustSats = splitOutputSats - targetSats - earmarkFee;

                // Fresh signer and unlocker per TX — TransactionBuilder mutates these during build
                TransactionSigner earmarkSigner = SignerAdapter.fromCallback(changeSigner, changePubKey, sigHashAll);
                P2PKHUnlockBuilder earmarkUnlocker = new P2PKHUnlockBuilder(changePubKey);

                TransactionBuilder earmarkBuilder = new TransactionBuilder();
                earmarkBuilder.spendFromTransaction(earmarkSigner, splitTx, splitOutputIndex,
                        TransactionInput.MAX_SEQ_NUMBER, earmarkUnlocker);

                earmarkBuilder.spendTo(changeLock, BigInteger.valueOf(dustSats));
                earmarkBuilder.spendTo(changeLock, BigInteger.valueOf(targetSats));

                Transaction earmarkTx = earmarkBuilder.build(false);

                results.add(new ProvisionedTransaction(
                        earmarkTx.getTransactionId(),
                        Utils.HEX.encode(earmarkTx.serialize()),
                        earmarkFee, "earmark", purposes[p], 1, targetSats));
            }
        }

        return results;
    }

    /**
     * Compute fee in satoshis for a given transaction size and fee rate.
     */
    static long computeFee(long txSizeBytes, long feeRateSatsPerKb) {
        long fee = (txSizeBytes * feeRateSatsPerKb + 999) / 1000; // ceil division
        return Math.max(fee, 1);
    }
}
