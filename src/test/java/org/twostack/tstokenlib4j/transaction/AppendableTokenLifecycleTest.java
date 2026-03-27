package org.twostack.tstokenlib4j.transaction;

import org.junit.BeforeClass;
import org.junit.Test;
import org.twostack.bitcoin4j.*;
import org.twostack.bitcoin4j.params.NetworkAddressType;
import org.twostack.bitcoin4j.script.Interpreter;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.transaction.SigHashType;
import org.twostack.bitcoin4j.transaction.Transaction;
import org.twostack.tstokenlib4j.crypto.Rabin;
import org.twostack.tstokenlib4j.crypto.RabinKeyPair;
import org.twostack.tstokenlib4j.crypto.RabinSignature;
import org.twostack.tstokenlib4j.parser.PP1TemplateRegistrar;
import org.twostack.tstokenlib4j.unlock.AppendableTokenAction;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.EnumSet;

import static org.junit.Assert.*;

/**
 * End-to-end lifecycle test for the Appendable Token (AT) archetype
 * with Bitcoin4J script interpreter validation.
 *
 * Validates the full permissioned AT flow:
 *   issue → witness → stamp #1 → witness → stamp #2 → witness
 *
 * Each step's PP1 input is verified via {@link Interpreter#correctlySpends}.
 */
public class AppendableTokenLifecycleTest {

    private static final String ISSUER_WIF = "cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS";
    private static PrivateKey issuerPrivateKey;
    private static PublicKey issuerPub;
    private static Address issuerAddress;

    private static final String FUNDING_TX_HEX =
            "0200000001cf5ae107ead0a5117ea2124aacb61d0d700de05a937ed3e48c9245bfab19dd8c000000004847304402206edac55dd4f791a611e05a6d946862ca45d914d0cdf391bfd982399c3d84ea4602205a196505d536b3646834051793acd5d9e820249979c94d0a4252298d0ffe9a7041feffffff0200196bee000000001976a914da217dfa3513d4224802556228d07b278af36b0388ac00ca9a3b000000001976a914650c4adb156f19e36a755c820d892cda108299c488ac65000000";

    private static final String FUNDING_TX_2_HEX =
            "0200000001be954a6129f555008a8678e9654ab14feb5b38c8cafa64c8aad29131a3c40f2e000000004948304502210092f4c484895bc20b938d109b871e7f860560e6dc72c684a41a28a9863645637202204f86ab76eb5ac67d678f6a426f917e356d5ec15f7f79c210fd4ac6d40644772641feffffff0200196bee000000001976a91490dca3b694773f8cbed80fe7634c6ee3807ca81588ac00ca9a3b000000001976a914f5d33ee198ad13840ce410ba96e149e463a6c35288ac6b000000";

    private static Transaction fundingTx;
    private static Transaction fundingTx2;
    private static AppendableTokenTool atTool;

    // Rabin identity material
    private static RabinKeyPair rabinKeyPair;
    private static byte[] rabinNBytes;
    private static byte[] rabinPubKeyHash;
    private static byte[] rabinSBytes;
    private static int rabinPaddingValue;
    private static byte[] dummyIdentityTxId;
    private static byte[] dummyEd25519PubKey;

    private static final int THRESHOLD = 10;

    private static final EnumSet<Script.VerifyFlag> VERIFY_FLAGS = EnumSet.of(
            Script.VerifyFlag.SIGHASH_FORKID,
            Script.VerifyFlag.UTXO_AFTER_GENESIS);

    @BeforeClass
    public static void setUpClass() throws Exception {
        PP1TemplateRegistrar.registerAll();

        issuerPrivateKey = PrivateKey.fromWIF(ISSUER_WIF);
        issuerPub = issuerPrivateKey.getPublicKey();
        issuerAddress = Address.fromKey(NetworkAddressType.TEST_PKH, issuerPub);

        fundingTx = Transaction.fromHex(FUNDING_TX_HEX);
        fundingTx2 = Transaction.fromHex(FUNDING_TX_2_HEX);

        atTool = new AppendableTokenTool(NetworkAddressType.TEST_PKH);

        // Rabin key setup
        rabinKeyPair = Rabin.generateKeyPair(1024);
        rabinNBytes = Rabin.bigIntToScriptNum(rabinKeyPair.n());
        rabinPubKeyHash = Utils.sha256hash160(rabinNBytes);

        // Dummy identity material
        dummyIdentityTxId = new byte[32];
        for (int i = 0; i < 32; i++) dummyIdentityTxId[i] = (byte) (i + 1);

        dummyEd25519PubKey = new byte[32];
        for (int i = 0; i < 32; i++) dummyEd25519PubKey[i] = (byte) (0x41 + i);

        // Rabin signature over identity + tokenId
        byte[] tokenId = fundingTx.getTransactionIdBytes();
        byte[] messageBytes = concat(dummyIdentityTxId, dummyEd25519PubKey, tokenId);
        byte[] sha256 = Sha256Hash.hash(messageBytes);
        BigInteger messageHash = Rabin.hashBytesToScriptInt(sha256);
        RabinSignature sig = Rabin.sign(messageHash, rabinKeyPair.p(), rabinKeyPair.q());
        rabinSBytes = Rabin.bigIntToScriptNum(sig.s());
        rabinPaddingValue = sig.padding();
    }

    private SigningCallback issuerSigner() {
        return sighash -> issuerPrivateKey.sign(sighash);
    }

    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] computeStampsHash(byte[] prevHash, byte[] stampMetadata) {
        byte[] metaHash = sha256(stampMetadata);
        byte[] combined = new byte[prevHash.length + metaHash.length];
        System.arraycopy(prevHash, 0, combined, 0, prevHash.length);
        System.arraycopy(metaHash, 0, combined, prevHash.length, metaHash.length);
        return sha256(combined);
    }

    private static byte[] concat(byte[]... arrays) {
        int len = 0;
        for (byte[] a : arrays) len += a.length;
        byte[] result = new byte[len];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, result, pos, a.length);
            pos += a.length;
        }
        return result;
    }

    private void verifySpend(Transaction spendingTx, int inputIndex,
                              Transaction parentTx, int parentVout) {
        Script scriptSig = spendingTx.getInputs().get(inputIndex).getScriptSig();
        Script scriptPubKey = parentTx.getOutputs().get(parentVout).getScript();
        long sats = parentTx.getOutputs().get(parentVout).getAmount().longValue();

        new Interpreter().correctlySpends(
                scriptSig, scriptPubKey, spendingTx, inputIndex,
                VERIFY_FLAGS, Coin.valueOf(sats));
    }

    /**
     * Full permissioned AT lifecycle:
     *   issue → issuance witness → stamp #1 → stamp witness #1 → stamp #2 → stamp witness #2
     *
     * Issuer holds the UTXO throughout. ownerPKH = issuerPKH.
     * Each step is validated through the Bitcoin4J script interpreter.
     */
    @Test
    public void testFullStampLifecycle() throws Exception {
        byte[] tokenId = fundingTx.getTransactionIdBytes();
        byte[] issuerPKH = issuerAddress.getHash();
        byte[] initialStampsHash = new byte[32]; // matches createTokenIssuanceTxn's initial value

        // ── Step 1: Issue ──
        Transaction issuanceTx = atTool.createTokenIssuanceTxn(
                fundingTx,
                issuerSigner(),
                issuerPub,
                issuerAddress,
                tokenId,
                issuerPKH,
                issuerPKH,
                rabinPubKeyHash,
                THRESHOLD,
                "test-token".getBytes());

        assertEquals(5, issuanceTx.getOutputs().size());

        // ── Step 2: Issuance Witness (with Rabin params) ──
        Transaction issuanceWitness = atTool.createWitnessTxn(
                issuerSigner(),
                issuerPub,
                fundingTx2,
                issuanceTx,
                new byte[0], // no parent for issuance
                issuerPub,
                issuerPKH,
                AppendableTokenAction.ISSUANCE,
                null,
                rabinNBytes,
                rabinSBytes,
                rabinPaddingValue,
                dummyIdentityTxId,
                dummyEd25519PubKey);

        assertEquals(1, issuanceWitness.getOutputs().size());

        // Verify witness PP1 spend (input 1 spends issuanceTx output 1)
        verifySpend(issuanceWitness, 1, issuanceTx, 1);

        // ── Step 3: Stamp #1 ──
        byte[] stamp1Metadata = "stamp-visit-1".getBytes();

        Transaction stamp1Tx = atTool.createTokenStampTxn(
                issuanceWitness,
                issuanceTx,
                issuerPub,
                fundingTx2,
                issuerSigner(),
                issuerPub,
                new byte[32], // issuerWitnessFundingTxId
                stamp1Metadata,
                issuerPKH,
                tokenId,
                issuerPKH,
                0,  // parentStampCount
                THRESHOLD,
                initialStampsHash);

        assertEquals(5, stamp1Tx.getOutputs().size());

        // Verify stamp PP3 spend (input 2 spends issuanceTx output 3)
        verifySpend(stamp1Tx, 2, issuanceTx, 3);

        // ── Step 4: Stamp #1 Witness ──
        byte[] stampsHash1 = computeStampsHash(initialStampsHash, stamp1Metadata);

        Transaction stamp1Witness = atTool.createWitnessTxn(
                issuerSigner(),
                issuerPub,
                fundingTx2,
                stamp1Tx,
                issuanceTx.serialize(),
                issuerPub,
                issuerPKH,
                AppendableTokenAction.STAMP,
                stamp1Metadata);

        assertEquals(1, stamp1Witness.getOutputs().size());

        // Verify witness PP1 spend (input 1 spends stamp1Tx output 1)
        verifySpend(stamp1Witness, 1, stamp1Tx, 1);

        // ── Step 5: Stamp #2 ──
        byte[] stamp2Metadata = "stamp-visit-2".getBytes();

        Transaction stamp2Tx = atTool.createTokenStampTxn(
                stamp1Witness,
                stamp1Tx,
                issuerPub,
                fundingTx2,
                issuerSigner(),
                issuerPub,
                new byte[32],
                stamp2Metadata,
                issuerPKH,
                tokenId,
                issuerPKH,
                1,  // parentStampCount (after stamp #1)
                THRESHOLD,
                stampsHash1);

        assertEquals(5, stamp2Tx.getOutputs().size());

        // Verify stamp #2 PP3 spend (input 2 spends stamp1Tx output 3)
        verifySpend(stamp2Tx, 2, stamp1Tx, 3);

        // ── Step 6: Stamp #2 Witness ──
        Transaction stamp2Witness = atTool.createWitnessTxn(
                issuerSigner(),
                issuerPub,
                fundingTx2,
                stamp2Tx,
                stamp1Tx.serialize(),
                issuerPub,
                issuerPKH,
                AppendableTokenAction.STAMP,
                stamp2Metadata);

        assertEquals(1, stamp2Witness.getOutputs().size());

        // Verify witness PP1 spend (input 1 spends stamp2Tx output 1)
        verifySpend(stamp2Witness, 1, stamp2Tx, 1);
    }
}
