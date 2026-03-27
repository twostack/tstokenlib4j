package org.twostack.tstokenlib4j.transaction;

import org.junit.BeforeClass;
import org.junit.Test;
import org.twostack.bitcoin4j.Address;
import org.twostack.bitcoin4j.PrivateKey;
import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.params.NetworkAddressType;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.transaction.SigHashType;
import org.twostack.bitcoin4j.transaction.Transaction;
import org.twostack.tstokenlib4j.parser.PP1TemplateRegistrar;
import org.twostack.tstokenlib4j.unlock.AppendableTokenAction;

import java.math.BigInteger;
import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * Integration tests for {@link AppendableTokenTool}, validating the structural
 * properties of appendable token transactions (output counts, satoshi amounts,
 * tokenId propagation, stamp operations, burn and redeem).
 */
public class AppendableTokenToolTest {

    // --- Bob's keys (issuer) ---
    private static final String BOB_WIF = "cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS";
    private static PrivateKey bobPrivateKey;
    private static PublicKey bobPub;
    private static Address bobAddress;

    // --- Alice's keys (customer/owner) ---
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

    // --- Metadata ---
    private static final byte[] METADATA_BYTES = "hello token metadata".getBytes();
    private static final byte[] STAMP_METADATA = "stamp1".getBytes();
    private static final int THRESHOLD = 5;

    // --- AppendableTokenTool instance ---
    private static AppendableTokenTool atTool;

    @BeforeClass
    public static void setUpClass() throws Exception {
        PP1TemplateRegistrar.registerAll();

        bobPrivateKey = PrivateKey.fromWIF(BOB_WIF);
        bobPub = bobPrivateKey.getPublicKey();
        bobAddress = Address.fromKey(NetworkAddressType.TEST_PKH, bobPub);

        alicePrivateKey = PrivateKey.fromWIF(ALICE_WIF);
        alicePub = alicePrivateKey.getPublicKey();
        aliceAddress = Address.fromKey(NetworkAddressType.TEST_PKH, alicePub);

        bobFundingTx = Transaction.fromHex(BOB_FUNDING_TX_HEX);
        aliceFundingTx = Transaction.fromHex(ALICE_FUNDING_TX_HEX);

        sigHashAll = SigHashType.FORKID.value | SigHashType.ALL.value;

        atTool = new AppendableTokenTool(NetworkAddressType.TEST_PKH);
    }

    // --- Helper methods ---

    private SigningCallback bobSigningCallback() {
        return sighash -> bobPrivateKey.sign(sighash);
    }

    private SigningCallback aliceSigningCallback() {
        return sighash -> alicePrivateKey.sign(sighash);
    }

    /**
     * Issues an AT to Bob (as customer) with Bob as issuer.
     */
    private Transaction issueAtToBob() throws Exception {
        return atTool.createTokenIssuanceTxn(
                bobFundingTx,
                bobSigningCallback(),
                bobPub,
                bobAddress,
                bobFundingTx.getTransactionIdBytes(),
                bobPub.getPubKeyHash(),
                bobAddress.getHash(),
                new byte[20], // rabinPubKeyHash (dummy for tests)
                THRESHOLD,
                METADATA_BYTES);
    }

    /**
     * Creates a witness for an AT token transaction.
     */
    private Transaction createAtWitness(
            SigningCallback fundingSigningCallback,
            PublicKey fundingPubKey,
            Transaction fundingTx,
            Transaction tokenTx,
            byte[] parentTokenTxBytes,
            PublicKey pubkey,
            byte[] tokenChangePKH,
            AppendableTokenAction action,
            byte[] stampMetadata) throws Exception {

        return atTool.createWitnessTxn(
                fundingSigningCallback,
                fundingPubKey,
                fundingTx,
                tokenTx,
                parentTokenTxBytes,
                pubkey,
                tokenChangePKH,
                action,
                stampMetadata);
    }

    // ---- Test 1: Issuance produces 5 outputs ----

    @Test
    public void testIssuanceProduces5Outputs() throws Exception {
        Transaction issuanceTx = issueAtToBob();

        assertEquals("Issuance should have 5 outputs", 5, issuanceTx.getOutputs().size());
        assertEquals("Issuance should have 1 input", 1, issuanceTx.getInputs().size());

        // Output[0] (change) should have positive satoshis
        assertTrue("Change output should have positive value",
                issuanceTx.getOutputs().get(0).getAmount().compareTo(BigInteger.ZERO) > 0);

        // Outputs[1-3] should each be 1 satoshi
        assertEquals("PP1 output should be 1 sat",
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
        Transaction issuanceTx = issueAtToBob();

        Script pp1Script = issuanceTx.getOutputs().get(1).getScript();
        assertNotNull("PP1 AT script should be parseable", pp1Script);

        byte[] tokenId = Arrays.copyOfRange(pp1Script.getProgram(), 22, 54);
        byte[] fundingTxId = bobFundingTx.getTransactionIdBytes();

        assertArrayEquals("TokenId should match funding transaction's txid",
                fundingTxId, tokenId);
    }

    // ---- Test 3: Witness produces 1 output ----

    @Test
    public void testWitnessProduces1Output() throws Exception {
        Transaction issuanceTx = issueAtToBob();

        Transaction witnessTx = createAtWitness(
                bobSigningCallback(),
                bobPub,
                aliceFundingTx,
                issuanceTx,
                new byte[0],
                bobPub,
                bobAddress.getHash(),
                AppendableTokenAction.ISSUANCE,
                null);

        assertEquals("Witness transaction should have 1 output", 1, witnessTx.getOutputs().size());
    }

    // ---- Test 4: Transfer produces 5 outputs ----

    @Test
    public void testTransferProduces5Outputs() throws Exception {
        // Step 1: Issue AT to Bob
        Transaction issuanceTx = issueAtToBob();

        // Step 2: Witness for issuance
        Transaction witnessTx = createAtWitness(
                bobSigningCallback(),
                bobPub,
                aliceFundingTx,
                issuanceTx,
                new byte[0],
                bobPub,
                bobAddress.getHash(),
                AppendableTokenAction.ISSUANCE,
                null);

        // Step 3: Transfer from Bob to Alice
        Transaction aliceFunding2 = Transaction.fromHex(ALICE_FUNDING_TX_HEX);
        byte[] tokenId = bobFundingTx.getTransactionIdBytes();

        Transaction transferTx = atTool.createTokenTransferTxn(
                witnessTx,
                issuanceTx,
                bobPub,
                aliceAddress,
                aliceFunding2,
                bobSigningCallback(),
                bobPub,
                aliceFunding2.getTransactionIdBytes(),
                tokenId,
                bobAddress.getHash(),
                0,
                THRESHOLD,
                new byte[32]);

        assertEquals("Transfer should have 5 outputs", 5, transferTx.getOutputs().size());
    }

    // ---- Test 5: Stamp produces 5 outputs ----

    @Test
    public void testStampProduces5Outputs() throws Exception {
        // Step 1: Issue AT to Bob
        Transaction issuanceTx = issueAtToBob();

        // Step 2: Witness for issuance
        Transaction witnessTx = createAtWitness(
                bobSigningCallback(),
                bobPub,
                aliceFundingTx,
                issuanceTx,
                new byte[0],
                bobPub,
                bobAddress.getHash(),
                AppendableTokenAction.ISSUANCE,
                null);

        // Step 3: Stamp (issuer stamps the token)
        Transaction aliceFunding2 = Transaction.fromHex(ALICE_FUNDING_TX_HEX);
        byte[] tokenId = bobFundingTx.getTransactionIdBytes();

        Transaction stampTx = atTool.createTokenStampTxn(
                witnessTx,
                issuanceTx,
                bobPub,
                aliceFunding2,
                bobSigningCallback(),
                bobPub,
                aliceFunding2.getTransactionIdBytes(),
                STAMP_METADATA,
                bobAddress.getHash(),
                tokenId,
                bobAddress.getHash(),
                0,
                THRESHOLD,
                new byte[32]);

        assertEquals("Stamp should have 5 outputs", 5, stampTx.getOutputs().size());
    }

    // ---- Test 6: Burn produces 1 output and 4 inputs ----

    @Test
    public void testBurnProduces1OutputAnd4Inputs() throws Exception {
        Transaction issuanceTx = issueAtToBob();

        Transaction aliceFunding2 = Transaction.fromHex(ALICE_FUNDING_TX_HEX);

        Transaction burnTx = atTool.createBurnTokenTxn(
                issuanceTx,
                bobSigningCallback(),
                bobPub,
                aliceFunding2,
                bobSigningCallback(),
                bobPub);

        assertEquals("Burn should have 1 output", 1, burnTx.getOutputs().size());
        assertEquals("Burn should have 4 inputs", 4, burnTx.getInputs().size());
    }

    // ---- Test 7: Redeem produces 1 output and 4 inputs ----

    @Test
    public void testRedeemProduces1OutputAnd4Inputs() throws Exception {
        Transaction issuanceTx = issueAtToBob();

        Transaction aliceFunding2 = Transaction.fromHex(ALICE_FUNDING_TX_HEX);

        Transaction redeemTx = atTool.createRedeemTokenTxn(
                issuanceTx,
                bobSigningCallback(),
                bobPub,
                aliceFunding2,
                bobSigningCallback(),
                bobPub);

        assertEquals("Redeem should have 1 output", 1, redeemTx.getOutputs().size());
        assertEquals("Redeem should have 4 inputs", 4, redeemTx.getInputs().size());
    }
}
