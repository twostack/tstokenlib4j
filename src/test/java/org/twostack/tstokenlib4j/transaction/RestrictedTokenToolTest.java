package org.twostack.tstokenlib4j.transaction;

import org.junit.BeforeClass;
import org.junit.Test;
import org.twostack.bitcoin4j.Address;
import org.twostack.bitcoin4j.PrivateKey;
import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.Sha256Hash;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.params.NetworkAddressType;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.transaction.SigHashType;
import org.twostack.bitcoin4j.transaction.Transaction;
import org.twostack.tstokenlib4j.crypto.Rabin;
import org.twostack.tstokenlib4j.crypto.RabinKeyPair;
import org.twostack.tstokenlib4j.crypto.RabinSignature;
import org.twostack.tstokenlib4j.parser.PP1TokenScriptParser;
import org.twostack.tstokenlib4j.unlock.RestrictedTokenAction;

import java.math.BigInteger;
import java.util.Optional;

import static org.junit.Assert.*;

/**
 * Integration tests for {@link RestrictedTokenTool}, porting the Dart rnft_token_test.dart
 * patterns to Java. Validates the structural properties of restricted token transactions
 * (output counts, satoshi amounts, tokenId propagation, flag variants).
 */
public class RestrictedTokenToolTest {

    // --- Bob's keys ---
    private static final String BOB_WIF = "cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS";
    private static PrivateKey bobPrivateKey;
    private static PublicKey bobPub;
    private static Address bobAddress;

    // --- Alice's keys ---
    private static final String ALICE_WIF = "cRHYFwjjw2Xn2gjxdGw6RRgKJZqipZx7j8i64NdwzxcD6SezEZV5";
    private static PrivateKey alicePrivateKey;
    private static PublicKey alicePub;
    private static Address aliceAddress;

    // --- Funding transactions ---
    private static final String BOB_FUNDING_TX_HEX =
            "0200000001cf5ae107ead0a5117ea2124aacb61d0d700de05a937ed3e48c9245bfab19dd8c000000004847304402206edac55dd4f791a611e05a6d946862ca45d914d0cdf391bfd982399c3d84ea4602205a196505d536b3646834051793acd5d9e820249979c94d0a4252298d0ffe9a7041feffffff0200196bee000000001976a914da217dfa3513d4224802556228d07b278af36b0388ac00ca9a3b000000001976a914650c4adb156f19e36a755c820d892cda108299c488ac65000000";

    private static final String ALICE_FUNDING_TX_HEX =
            "0200000001be954a6129f555008a8678e9654ab14feb5b38c8cafa64c8aad29131a3c40f2e000000004948304502210092f4c484895bc20b938d109b871e7f860560e6dc72c684a41a28a9863645637202204f86ab76eb5ac67d678f6a426f917e356d5ec15f7f79c210fd4ac6d40644772641feffffff0200196bee000000001976a91490dca3b694773f8cbed80fe7634c6ee3807ca81588ac00ca9a3b000000001976a914f5d33ee198ad13840ce410ba96e149e463a6c35288ac6b000000";

    private static Transaction bobFundingTx;
    private static Transaction aliceFundingTx;

    private static int sigHashAll;

    // --- Rabin key material ---
    private static RabinKeyPair rabinKeyPair;
    private static byte[] rabinNBytes;
    private static byte[] rabinPubKeyHash;
    private static byte[] rabinSBytes;
    private static int rabinPaddingValue;

    // --- Identity material ---
    private static byte[] dummyIdentityTxId;
    private static byte[] dummyEd25519PubKey;

    // --- RestrictedTokenTool instance ---
    private static RestrictedTokenTool restrictedTokenTool;

    // --- Metadata ---
    private static final byte[] METADATA_BYTES = "hello token metadata".getBytes();

    @BeforeClass
    public static void setUpClass() throws Exception {
        // Keys
        bobPrivateKey = PrivateKey.fromWIF(BOB_WIF);
        bobPub = bobPrivateKey.getPublicKey();
        bobAddress = Address.fromKey(NetworkAddressType.TEST_PKH, bobPub);

        alicePrivateKey = PrivateKey.fromWIF(ALICE_WIF);
        alicePub = alicePrivateKey.getPublicKey();
        aliceAddress = Address.fromKey(NetworkAddressType.TEST_PKH, alicePub);

        // Funding transactions
        bobFundingTx = Transaction.fromHex(BOB_FUNDING_TX_HEX);
        aliceFundingTx = Transaction.fromHex(ALICE_FUNDING_TX_HEX);

        // SigHash type
        sigHashAll = SigHashType.FORKID.value | SigHashType.ALL.value;

        // Rabin key setup
        rabinKeyPair = Rabin.generateKeyPair(1024);
        rabinNBytes = Rabin.bigIntToScriptNum(rabinKeyPair.n());
        rabinPubKeyHash = Utils.sha256hash160(rabinNBytes);

        // Dummy identity material
        dummyIdentityTxId = new byte[32];
        for (int i = 0; i < 32; i++) {
            dummyIdentityTxId[i] = (byte) (i + 1);
        }

        dummyEd25519PubKey = new byte[32];
        for (int i = 0; i < 32; i++) {
            dummyEd25519PubKey[i] = (byte) (0x41 + i);
        }

        // Rabin signature over identity material
        byte[] messageBytes = concat(dummyIdentityTxId, dummyEd25519PubKey);
        byte[] sha256 = Sha256Hash.hash(messageBytes);
        BigInteger messageHash = Rabin.hashBytesToScriptInt(sha256);
        RabinSignature sig = Rabin.sign(messageHash, rabinKeyPair.p(), rabinKeyPair.q());
        rabinSBytes = Rabin.bigIntToScriptNum(sig.s());
        rabinPaddingValue = sig.padding();

        // RestrictedTokenTool
        restrictedTokenTool = new RestrictedTokenTool(NetworkAddressType.TEST_PKH);
    }

    // --- Helper methods ---

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private SigningCallback bobSigningCallback() {
        return sighash -> bobPrivateKey.sign(sighash);
    }

    private SigningCallback aliceSigningCallback() {
        return sighash -> alicePrivateKey.sign(sighash);
    }

    /**
     * Issues an RNFT to Bob using Bob's funding transaction with the given flags byte.
     */
    private Transaction issueRnftToBob(int flags) throws Exception {
        return restrictedTokenTool.createTokenIssuanceTxn(
                bobFundingTx,
                bobSigningCallback(),
                bobPub,
                bobAddress,
                bobFundingTx.getTransactionIdBytes(),
                rabinPubKeyHash,
                flags,
                METADATA_BYTES);
    }

    /**
     * Issues an RNFT to Bob with default flags (0x00).
     */
    private Transaction issueRnftToBob() throws Exception {
        return issueRnftToBob(0x00);
    }

    /**
     * Creates a witness transaction for a restricted token transaction.
     */
    private Transaction createWitness(
            SigningCallback fundingSigningCallback,
            PublicKey fundingPubKey,
            Transaction fundingTx,
            Transaction tokenTx,
            byte[] parentTokenTxBytes,
            PublicKey ownerPubkey,
            byte[] tokenChangePKH,
            RestrictedTokenAction action) throws Exception {

        return restrictedTokenTool.createWitnessTxn(
                fundingSigningCallback,
                fundingPubKey,
                fundingTx,
                tokenTx,
                parentTokenTxBytes,
                ownerPubkey,
                tokenChangePKH,
                action,
                rabinNBytes,
                rabinSBytes,
                rabinPaddingValue,
                dummyIdentityTxId,
                dummyEd25519PubKey);
    }

    // ---- Test 1: Issuance produces 5 outputs ----

    @Test
    public void testIssuanceProduces5Outputs() throws Exception {
        Transaction issuanceTx = issueRnftToBob();

        // 5 outputs: change, PP1_RNFT, PP2, PartialWitness, Metadata
        assertEquals("Issuance should have 5 outputs", 5, issuanceTx.getOutputs().size());

        // 1 input (funding)
        assertEquals("Issuance should have 1 input", 1, issuanceTx.getInputs().size());

        // Output[0] (change) should have positive satoshis
        assertTrue("Change output should have positive value",
                issuanceTx.getOutputs().get(0).getAmount().compareTo(BigInteger.ZERO) > 0);

        // Outputs[1-3] should each be 1 satoshi
        assertEquals("PP1_RNFT output should be 1 sat",
                BigInteger.ONE, issuanceTx.getOutputs().get(1).getAmount());
        assertEquals("PP2 output should be 1 sat",
                BigInteger.ONE, issuanceTx.getOutputs().get(2).getAmount());
        assertEquals("PartialWitness output should be 1 sat",
                BigInteger.ONE, issuanceTx.getOutputs().get(3).getAmount());

        // Output[4] (metadata OP_RETURN) should be 0 satoshis
        assertEquals("Metadata output should be 0 sats",
                BigInteger.ZERO, issuanceTx.getOutputs().get(4).getAmount());
    }

    // ---- Test 2: TokenId matches funding txid ----

    @Test
    public void testIssuanceTokenIdMatchesFundingTxId() throws Exception {
        Transaction issuanceTx = issueRnftToBob();

        // Parse the PP1 output (index 1) to extract the tokenId
        Script pp1Script = issuanceTx.getOutputs().get(1).getScript();
        Optional<PP1TokenScriptParser.TokenScriptInfo> infoOpt = PP1TokenScriptParser.parse(pp1Script);

        assertTrue("PP1 RNFT script should be parseable", infoOpt.isPresent());

        byte[] tokenId = infoOpt.get().tokenId();
        byte[] fundingTxId = bobFundingTx.getTransactionIdBytes();

        assertArrayEquals("TokenId should match funding transaction's txid",
                fundingTxId, tokenId);
    }

    // ---- Test 3: Witness produces 1 output ----

    @Test
    public void testWitnessProduces1Output() throws Exception {
        Transaction issuanceTx = issueRnftToBob();

        Transaction witnessTx = createWitness(
                bobSigningCallback(),
                bobPub,
                aliceFundingTx,
                issuanceTx,
                new byte[0],
                bobPub,
                bobAddress.getHash(),
                RestrictedTokenAction.ISSUANCE);

        assertEquals("Witness transaction should have 1 output", 1, witnessTx.getOutputs().size());
    }

    // ---- Test 4: Transfer produces 5 outputs ----

    @Test
    public void testTransferProduces5Outputs() throws Exception {
        // Step 1: Issue RNFT to Bob
        Transaction issuanceTx = issueRnftToBob();

        // Step 2: Create witness for issuance
        Transaction witnessTx = createWitness(
                bobSigningCallback(),
                bobPub,
                aliceFundingTx,
                issuanceTx,
                new byte[0],
                bobPub,
                bobAddress.getHash(),
                RestrictedTokenAction.ISSUANCE);

        // Step 3: Transfer from Bob to Alice
        Transaction aliceFunding2 = Transaction.fromHex(ALICE_FUNDING_TX_HEX);
        byte[] tokenId = bobFundingTx.getTransactionIdBytes();

        Transaction transferTx = restrictedTokenTool.createTokenTransferTxn(
                witnessTx,
                issuanceTx,
                bobPub,
                aliceAddress,
                aliceFunding2,
                bobSigningCallback(),
                bobPub,
                aliceFunding2.getTransactionIdBytes(),
                tokenId,
                rabinPubKeyHash,
                0x00);

        // Transfer should have 5 outputs: change, PP1_RNFT, PP2, PartialWitness, Metadata
        assertEquals("Transfer should have 5 outputs", 5, transferTx.getOutputs().size());
    }

    // ---- Test 5: Burn produces 1 output and 4 inputs ----

    @Test
    public void testBurnProduces1OutputAnd4Inputs() throws Exception {
        // Step 1: Issue RNFT to Bob
        Transaction issuanceTx = issueRnftToBob();

        // Step 2: Burn
        Transaction bobFunding2 = Transaction.fromHex(BOB_FUNDING_TX_HEX);

        Transaction burnTx = restrictedTokenTool.createBurnTokenTxn(
                issuanceTx,
                bobSigningCallback(),
                bobPub,
                bobFunding2,
                bobSigningCallback(),
                bobPub);

        // Burn should have 1 output (change) and 4 inputs (funding + PP1 + PP2 + PartialWitness)
        assertEquals("Burn should have 1 output", 1, burnTx.getOutputs().size());
        assertEquals("Burn should have 4 inputs", 4, burnTx.getInputs().size());
    }

    // ---- Test 6: Redeem produces 1 output and 4 inputs ----

    @Test
    public void testRedeemProduces1OutputAnd4Inputs() throws Exception {
        // Step 1: Issue RNFT to Bob
        Transaction issuanceTx = issueRnftToBob();

        // Step 2: Redeem
        Transaction bobFunding2 = Transaction.fromHex(BOB_FUNDING_TX_HEX);

        Transaction redeemTx = restrictedTokenTool.createRedeemTokenTxn(
                issuanceTx,
                bobSigningCallback(),
                bobPub,
                bobFunding2,
                bobSigningCallback(),
                bobPub);

        // Redeem should have 1 output (change) and 4 inputs (funding + PP1 + PP2 + PartialWitness)
        assertEquals("Redeem should have 1 output", 1, redeemTx.getOutputs().size());
        assertEquals("Redeem should have 4 inputs", 4, redeemTx.getInputs().size());
    }

    // ---- Test 7: Multiple flag values ----

    @Test
    public void testMultipleFlagValues() throws Exception {
        int[] flagValues = {0x00, 0x01, 0x02, 0x04};

        for (int flags : flagValues) {
            Transaction issuanceTx = issueRnftToBob(flags);

            assertEquals("Issuance with flags=0x" + Integer.toHexString(flags) + " should have 5 outputs",
                    5, issuanceTx.getOutputs().size());
        }
    }
}
