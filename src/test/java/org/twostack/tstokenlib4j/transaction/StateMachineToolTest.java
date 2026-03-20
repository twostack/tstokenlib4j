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
import org.twostack.tstokenlib4j.unlock.StateMachineAction;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * Integration tests for {@link StateMachineTool}, porting the Dart sm_token_test.dart
 * patterns to Java. Bob acts as the merchant, Alice acts as the customer.
 * Validates structural properties of SM token transactions
 * (output counts, input counts, satoshi amounts, tokenId propagation).
 */
public class StateMachineToolTest {

    // --- Bob (merchant) keys ---
    private static final String BOB_WIF = "cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS";
    private static PrivateKey merchantPrivateKey;
    private static PublicKey merchantPub;
    private static Address merchantAddress;

    // --- Alice (customer) keys ---
    private static final String ALICE_WIF = "cRHYFwjjw2Xn2gjxdGw6RRgKJZqipZx7j8i64NdwzxcD6SezEZV5";
    private static PrivateKey customerPrivateKey;
    private static PublicKey customerPub;
    private static Address customerAddress;

    // --- Funding transactions ---
    private static final String BOB_FUNDING_TX_HEX =
            "0200000001cf5ae107ead0a5117ea2124aacb61d0d700de05a937ed3e48c9245bfab19dd8c000000004847304402206edac55dd4f791a611e05a6d946862ca45d914d0cdf391bfd982399c3d84ea4602205a196505d536b3646834051793acd5d9e820249979c94d0a4252298d0ffe9a7041feffffff0200196bee000000001976a914da217dfa3513d4224802556228d07b278af36b0388ac00ca9a3b000000001976a914650c4adb156f19e36a755c820d892cda108299c488ac65000000";

    private static final String ALICE_FUNDING_TX_HEX =
            "0200000001be954a6129f555008a8678e9654ab14feb5b38c8cafa64c8aad29131a3c40f2e000000004948304502210092f4c484895bc20b938d109b871e7f860560e6dc72c684a41a28a9863645637202204f86ab76eb5ac67d678f6a426f917e356d5ec15f7f79c210fd4ac6d40644772641feffffff0200196bee000000001976a91490dca3b694773f8cbed80fe7634c6ee3807ca81588ac00ca9a3b000000001976a914f5d33ee198ad13840ce410ba96e149e463a6c35288ac6b000000";

    private static Transaction merchantFundingTx;
    private static Transaction customerFundingTx;

    private static int sigHashAll;

    // --- SM-specific parameters ---
    private static final int TRANSITION_BITMASK = 0x3F;
    private static final int TIMEOUT_DELTA = 86400;
    private static final byte[] METADATA_BYTES = "hello sm metadata".getBytes();

    // --- StateMachineTool instance ---
    private static StateMachineTool smTool;

    @BeforeClass
    public static void setUpClass() throws Exception {
        PP1TemplateRegistrar.registerAll();

        // Merchant (Bob) keys
        merchantPrivateKey = PrivateKey.fromWIF(BOB_WIF);
        merchantPub = merchantPrivateKey.getPublicKey();
        merchantAddress = Address.fromKey(NetworkAddressType.TEST_PKH, merchantPub);

        // Customer (Alice) keys
        customerPrivateKey = PrivateKey.fromWIF(ALICE_WIF);
        customerPub = customerPrivateKey.getPublicKey();
        customerAddress = Address.fromKey(NetworkAddressType.TEST_PKH, customerPub);

        // Funding transactions
        merchantFundingTx = Transaction.fromHex(BOB_FUNDING_TX_HEX);
        customerFundingTx = Transaction.fromHex(ALICE_FUNDING_TX_HEX);

        // SigHash type
        sigHashAll = SigHashType.FORKID.value | SigHashType.ALL.value;

        // StateMachineTool
        smTool = new StateMachineTool(NetworkAddressType.TEST_PKH);
    }

    // --- Helper methods ---

    private SigningCallback merchantSigningCallback() {
        return sighash -> merchantPrivateKey.sign(sighash);
    }

    private SigningCallback customerSigningCallback() {
        return sighash -> customerPrivateKey.sign(sighash);
    }

    /**
     * Issues an SM token funded by the merchant.
     */
    private Transaction issueSmToken() throws Exception {
        return smTool.createTokenIssuanceTxn(
                merchantFundingTx,
                merchantSigningCallback(),
                merchantPub,
                merchantAddress,
                merchantAddress.getHash(),
                customerAddress.getHash(),
                TRANSITION_BITMASK,
                TIMEOUT_DELTA,
                merchantFundingTx.getTransactionIdBytes(),
                new byte[20], // rabinPubKeyHash (dummy for tests)
                METADATA_BYTES);
    }

    /**
     * Creates a single-sig witness for a CREATE action on an issuance transaction.
     */
    private Transaction createIssuanceWitness(Transaction issuanceTx) throws Exception {
        return smTool.createWitnessTxn(
                merchantSigningCallback(),
                merchantPub,
                customerFundingTx,
                issuanceTx,
                new byte[0],
                merchantPub,
                merchantAddress.getHash(),
                StateMachineAction.CREATE,
                null,
                0, 0, 0, -1,
                1, 2);
    }

    private static byte[] sha256(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }

    /**
     * Chains commitment hash: SHA256(parentCommit || SHA256(eventData)).
     */
    private static byte[] chainCommitment(byte[] parentCommit, byte[] eventData) throws Exception {
        byte[] eventDigest = sha256(eventData);
        byte[] combined = new byte[parentCommit.length + eventDigest.length];
        System.arraycopy(parentCommit, 0, combined, 0, parentCommit.length);
        System.arraycopy(eventDigest, 0, combined, parentCommit.length, eventDigest.length);
        return sha256(combined);
    }

    // ---- Test 1: Issuance produces 5 outputs ----

    @Test
    public void testIssuanceProduces5Outputs() throws Exception {
        Transaction issuanceTx = issueSmToken();

        assertEquals("Issuance should have 5 outputs", 5, issuanceTx.getOutputs().size());
        assertEquals("Issuance should have 1 input", 1, issuanceTx.getInputs().size());

        // Output[0] (change) should have positive satoshis
        assertTrue("Change output should have positive value",
                issuanceTx.getOutputs().get(0).getAmount().compareTo(BigInteger.ZERO) > 0);

        // Outputs[1-3] should each be 1 satoshi
        assertEquals("PP1_SM output should be 1 sat",
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
        Transaction issuanceTx = issueSmToken();

        Script pp1Script = issuanceTx.getOutputs().get(1).getScript();
        assertNotNull("PP1_SM script should be parseable", pp1Script);

        byte[] tokenId = Arrays.copyOfRange(pp1Script.getProgram(), 22, 54);
        byte[] fundingTxId = merchantFundingTx.getTransactionIdBytes();

        assertArrayEquals("TokenId should match funding transaction's txid",
                fundingTxId, tokenId);
    }

    // ---- Test 3: Witness produces 1 output ----

    @Test
    public void testWitnessProduces1Output() throws Exception {
        Transaction issuanceTx = issueSmToken();

        Transaction witnessTx = createIssuanceWitness(issuanceTx);

        assertEquals("Witness transaction should have 1 output", 1, witnessTx.getOutputs().size());
    }

    // ---- Test 4: Enroll produces 5 outputs ----

    @Test
    public void testEnrollProduces5Outputs() throws Exception {
        // Step 1: Issue SM token
        Transaction issuanceTx = issueSmToken();

        // Step 2: Create witness for issuance
        Transaction witnessTx = createIssuanceWitness(issuanceTx);

        // Step 3: Enroll
        byte[] tokenId = merchantFundingTx.getTransactionIdBytes();
        byte[] initialCommitmentHash = new byte[32];
        byte[] eventData = "enrollment".getBytes();

        Transaction enrollFunding = Transaction.fromHex(BOB_FUNDING_TX_HEX);

        Transaction enrollTx = smTool.createEnrollTxn(
                witnessTx,
                issuanceTx,
                merchantPub,
                enrollFunding,
                merchantSigningCallback(),
                merchantPub,
                enrollFunding.getTransactionIdBytes(),
                eventData,
                tokenId,
                merchantAddress.getHash(),
                customerAddress.getHash(),
                0,  // state = INIT
                0,  // milestoneCount
                initialCommitmentHash,
                TRANSITION_BITMASK,
                TIMEOUT_DELTA);

        assertEquals("Enroll should have 5 outputs", 5, enrollTx.getOutputs().size());
    }

    // ---- Test 5: Settle produces 7 outputs ----

    @Test
    public void testSettleProduces7Outputs() throws Exception {
        // Step 1: Issue SM token
        Transaction issuanceTx = issueSmToken();

        // Step 2: Create witness for issuance (CREATE)
        Transaction createWitnessTx = createIssuanceWitness(issuanceTx);

        // Step 3: Enroll
        byte[] tokenId = merchantFundingTx.getTransactionIdBytes();
        byte[] commitmentHash = new byte[32];
        byte[] enrollEventData = "enrollment".getBytes();

        Transaction enrollFunding = Transaction.fromHex(BOB_FUNDING_TX_HEX);
        Transaction enrollTx = smTool.createEnrollTxn(
                createWitnessTx,
                issuanceTx,
                merchantPub,
                enrollFunding,
                merchantSigningCallback(),
                merchantPub,
                enrollFunding.getTransactionIdBytes(),
                enrollEventData,
                tokenId,
                merchantAddress.getHash(),
                customerAddress.getHash(),
                0, 0, commitmentHash,
                TRANSITION_BITMASK, TIMEOUT_DELTA);

        commitmentHash = chainCommitment(commitmentHash, enrollEventData);

        // Step 4: Witness for enroll (ENROLL action, merchant signs)
        Transaction enrollWitnessFunding = Transaction.fromHex(ALICE_FUNDING_TX_HEX);
        Transaction enrollWitnessTx = smTool.createWitnessTxn(
                merchantSigningCallback(),
                merchantPub,
                enrollWitnessFunding,
                enrollTx,
                issuanceTx.serialize(),
                merchantPub,
                merchantAddress.getHash(),
                StateMachineAction.ENROLL,
                enrollEventData,
                0, 0, 0, -1,
                1, 2);

        // Step 5: Confirm transition (customer -> merchant, state 1 -> 2)
        byte[] confirmEventData = "confirm".getBytes();
        Transaction confirmFunding = Transaction.fromHex(ALICE_FUNDING_TX_HEX);
        Transaction confirmTx = smTool.createTransitionTxn(
                enrollWitnessTx,
                enrollTx,
                customerPub,
                confirmFunding,
                customerSigningCallback(),
                customerPub,
                confirmFunding.getTransactionIdBytes(),
                2,  // newState = CONFIRMED
                merchantAddress.getHash(),  // next actor is merchant
                true,  // increment milestone
                confirmEventData,
                tokenId,
                merchantAddress.getHash(),
                customerAddress.getHash(),
                1, 0, commitmentHash,
                TRANSITION_BITMASK, TIMEOUT_DELTA);

        commitmentHash = chainCommitment(commitmentHash, confirmEventData);

        // Step 6: Witness for confirm (CONFIRM - dual sig)
        // createDualWitnessTxn takes: merchantCallback, merchantPubKey, customerPrivateKey, ...
        Transaction confirmWitnessFunding = Transaction.fromHex(BOB_FUNDING_TX_HEX);
        Transaction confirmWitnessTx = smTool.createDualWitnessTxn(
                merchantSigningCallback(),
                merchantPub,
                customerPrivateKey,
                confirmWitnessFunding,
                confirmTx,
                enrollTx.serialize(),
                merchantPub,
                customerPub,
                customerAddress.getHash(),
                StateMachineAction.CONFIRM,
                confirmEventData);

        // Step 7: Convert transition (merchant -> customer, state 2 -> 3)
        byte[] convertEventData = "convert".getBytes();
        Transaction convertFunding = Transaction.fromHex(BOB_FUNDING_TX_HEX);
        Transaction convertTx = smTool.createTransitionTxn(
                confirmWitnessTx,
                confirmTx,
                merchantPub,
                convertFunding,
                merchantSigningCallback(),
                merchantPub,
                convertFunding.getTransactionIdBytes(),
                3,  // newState = CONVERTING
                customerAddress.getHash(),  // next actor is customer
                false,
                convertEventData,
                tokenId,
                merchantAddress.getHash(),
                customerAddress.getHash(),
                2, 1, commitmentHash,
                TRANSITION_BITMASK, TIMEOUT_DELTA);

        commitmentHash = chainCommitment(commitmentHash, convertEventData);

        // Step 8: Witness for convert (CONVERT - dual sig)
        Transaction convertWitnessFunding = Transaction.fromHex(ALICE_FUNDING_TX_HEX);
        Transaction convertWitnessTx = smTool.createDualWitnessTxn(
                merchantSigningCallback(),
                merchantPub,
                customerPrivateKey,
                convertWitnessFunding,
                convertTx,
                confirmTx.serialize(),
                merchantPub,
                customerPub,
                merchantAddress.getHash(),
                StateMachineAction.CONVERT,
                convertEventData);

        // Step 9: Settle (customer signs, state 3 -> 4)
        byte[] settleEventData = "settle".getBytes();
        Transaction settleFunding = Transaction.fromHex(ALICE_FUNDING_TX_HEX);
        Transaction settleTx = smTool.createSettleTxn(
                convertWitnessTx,
                convertTx,
                customerPub,
                settleFunding,
                customerSigningCallback(),
                customerPub,
                settleFunding.getTransactionIdBytes(),
                BigInteger.valueOf(1000),
                BigInteger.valueOf(2000),
                settleEventData,
                tokenId,
                merchantAddress.getHash(),
                customerAddress.getHash(),
                3, 1, commitmentHash,
                TRANSITION_BITMASK, TIMEOUT_DELTA);

        assertEquals("Settle should have 7 outputs", 7, settleTx.getOutputs().size());
    }

    // ---- Test 6: Timeout produces 6 outputs ----

    @Test
    public void testTimeoutProduces6Outputs() throws Exception {
        // Step 1: Issue SM token
        Transaction issuanceTx = issueSmToken();

        // Step 2: Create witness for issuance (CREATE)
        Transaction createWitnessTx = createIssuanceWitness(issuanceTx);

        // Step 3: Enroll
        byte[] tokenId = merchantFundingTx.getTransactionIdBytes();
        byte[] commitmentHash = new byte[32];
        byte[] enrollEventData = "enrollment".getBytes();

        Transaction enrollFunding = Transaction.fromHex(BOB_FUNDING_TX_HEX);
        Transaction enrollTx = smTool.createEnrollTxn(
                createWitnessTx,
                issuanceTx,
                merchantPub,
                enrollFunding,
                merchantSigningCallback(),
                merchantPub,
                enrollFunding.getTransactionIdBytes(),
                enrollEventData,
                tokenId,
                merchantAddress.getHash(),
                customerAddress.getHash(),
                0, 0, commitmentHash,
                TRANSITION_BITMASK, TIMEOUT_DELTA);

        commitmentHash = chainCommitment(commitmentHash, enrollEventData);

        // Step 4: Witness for enroll (ENROLL)
        Transaction enrollWitnessFunding = Transaction.fromHex(ALICE_FUNDING_TX_HEX);
        Transaction enrollWitnessTx = smTool.createWitnessTxn(
                merchantSigningCallback(),
                merchantPub,
                enrollWitnessFunding,
                enrollTx,
                issuanceTx.serialize(),
                merchantPub,
                merchantAddress.getHash(),
                StateMachineAction.ENROLL,
                enrollEventData,
                0, 0, 0, -1,
                1, 2);

        // Step 5: Timeout (customer signs from ACTIVE state)
        Transaction timeoutFunding = Transaction.fromHex(BOB_FUNDING_TX_HEX);
        Transaction timeoutTx = smTool.createTimeoutTxn(
                enrollWitnessTx,
                enrollTx,
                customerPub,
                timeoutFunding,
                customerSigningCallback(),
                customerPub,
                timeoutFunding.getTransactionIdBytes(),
                BigInteger.valueOf(500),
                100,  // nLockTime
                tokenId,
                merchantAddress.getHash(),
                customerAddress.getHash(),
                1, 0, commitmentHash,
                TRANSITION_BITMASK, TIMEOUT_DELTA);

        assertEquals("Timeout should have 6 outputs", 6, timeoutTx.getOutputs().size());
    }

    // ---- Test 7: Burn produces 1 output and 4 inputs ----

    @Test
    public void testBurnProduces1OutputAnd4Inputs() throws Exception {
        // Step 1: Issue SM token
        Transaction issuanceTx = issueSmToken();

        // Step 2: Burn (standard output indices 1, 2, 3)
        Transaction burnFunding = Transaction.fromHex(BOB_FUNDING_TX_HEX);
        Transaction burnTx = smTool.createBurnTokenTxn(
                issuanceTx,
                merchantSigningCallback(),
                merchantPub,
                burnFunding,
                merchantSigningCallback(),
                merchantPub,
                1, 2, 3);

        assertEquals("Burn should have 1 output", 1, burnTx.getOutputs().size());
        assertEquals("Burn should have 4 inputs", 4, burnTx.getInputs().size());
    }
}
