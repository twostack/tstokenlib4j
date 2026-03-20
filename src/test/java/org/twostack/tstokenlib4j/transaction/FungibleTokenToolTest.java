package org.twostack.tstokenlib4j.transaction;

import org.junit.Before;
import org.junit.Test;
import org.twostack.bitcoin4j.Address;
import org.twostack.bitcoin4j.PrivateKey;
import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.exception.InvalidKeyException;
import org.twostack.bitcoin4j.Coin;
import org.twostack.bitcoin4j.params.NetworkAddressType;
import org.twostack.bitcoin4j.script.Interpreter;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.transaction.SigHashType;
import org.twostack.bitcoin4j.transaction.Transaction;
import org.twostack.tstokenlib4j.parser.PP1TemplateRegistrar;
import org.twostack.tstokenlib4j.unlock.FungibleTokenAction;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.LinkedList;

import static org.junit.Assert.*;

/**
 * Integration tests for {@link FungibleTokenTool}, ported from the Dart fungible_token_test.dart.
 *
 * <p>Exercises the full fungible token lifecycle: mint, witness, transfer, split, merge, and burn.
 */
public class FungibleTokenToolTest {

    private static final String BOB_WIF = "cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS";
    private static final String ALICE_WIF = "cRHYFwjjw2Xn2gjxdGw6RRgKJZqipZx7j8i64NdwzxcD6SezEZV5";

    private static final String BOB_FUNDING_TX_HEX =
            "0200000001cf5ae107ead0a5117ea2124aacb61d0d700de05a937ed3e48c9245bfab19dd8c000000004847304402206edac55dd4f791a611e05a6d946862ca45d914d0cdf391bfd982399c3d84ea4602205a196505d536b3646834051793acd5d9e820249979c94d0a4252298d0ffe9a7041feffffff0200196bee000000001976a914da217dfa3513d4224802556228d07b278af36b0388ac00ca9a3b000000001976a914650c4adb156f19e36a755c820d892cda108299c488ac65000000";

    private static final String ALICE_FUNDING_TX_HEX =
            "0200000001be954a6129f555008a8678e9654ab14feb5b38c8cafa64c8aad29131a3c40f2e000000004948304502210092f4c484895bc20b938d109b871e7f860560e6dc72c684a41a28a9863645637202204f86ab76eb5ac67d678f6a426f917e356d5ec15f7f79c210fd4ac6d40644772641feffffff0200196bee000000001976a91490dca3b694773f8cbed80fe7634c6ee3807ca81588ac00ca9a3b000000001976a914f5d33ee198ad13840ce410ba96e149e463a6c35288ac6b000000";

    private int sigHashAll;
    private PrivateKey bobPrivateKey;
    private PrivateKey alicePrivateKey;
    private PublicKey bobPubKey;
    private PublicKey alicePubKey;
    private Address bobAddress;
    private Address aliceAddress;
    private FungibleTokenTool tool;
    private static final byte[] DUMMY_RABIN_PKH = new byte[20];

    @Before
    public void setUp() throws InvalidKeyException {
        PP1TemplateRegistrar.registerAll();

        sigHashAll = SigHashType.FORKID.value | SigHashType.ALL.value;

        bobPrivateKey = PrivateKey.fromWIF(BOB_WIF);
        alicePrivateKey = PrivateKey.fromWIF(ALICE_WIF);
        bobPubKey = bobPrivateKey.getPublicKey();
        alicePubKey = alicePrivateKey.getPublicKey();
        bobAddress = Address.fromKey(NetworkAddressType.TEST_PKH, bobPubKey);
        aliceAddress = Address.fromKey(NetworkAddressType.TEST_PKH, alicePubKey);

        tool = new FungibleTokenTool(NetworkAddressType.TEST_PKH);
    }

    private Transaction getBobFundingTx() {
        return Transaction.fromHex(BOB_FUNDING_TX_HEX);
    }

    private Transaction getAliceFundingTx() {
        return Transaction.fromHex(ALICE_FUNDING_TX_HEX);
    }

    private SigningCallback bobSigningCallback() {
        return sighash -> bobPrivateKey.sign(sighash);
    }

    private SigningCallback aliceSigningCallback() {
        return sighash -> alicePrivateKey.sign(sighash);
    }

    // -------------------------------------------------------------------------
    // 1. Mint produces 5 outputs
    // -------------------------------------------------------------------------

    @Test
    public void testMintProduces5Outputs() throws Exception {
        Transaction bobFundingTx = getBobFundingTx();

        Transaction mintTx = tool.createFungibleMintTxn(
                bobFundingTx,
                bobSigningCallback(),
                bobPubKey,
                bobAddress,
                bobFundingTx.getTransactionIdBytes(),
                DUMMY_RABIN_PKH,
                1000,
                null);

        assertEquals("Mint should produce 5 outputs", 5, mintTx.getOutputs().size());
        assertEquals("Mint should have 1 input", 1, mintTx.getInputs().size());

        // Output[0]: Change (satoshis > 0)
        assertTrue("Change output should have satoshis",
                mintTx.getOutputs().get(0).getAmount().compareTo(BigInteger.ZERO) > 0);

        // Outputs[1-3]: PP1_FT, PP2-FT, PP3-FT (1 sat each)
        assertEquals(BigInteger.ONE, mintTx.getOutputs().get(1).getAmount());
        assertEquals(BigInteger.ONE, mintTx.getOutputs().get(2).getAmount());
        assertEquals(BigInteger.ONE, mintTx.getOutputs().get(3).getAmount());

        // Output[4]: Metadata (0 sats)
        assertEquals(BigInteger.ZERO, mintTx.getOutputs().get(4).getAmount());
    }

    // -------------------------------------------------------------------------
    // 2. Mint PP1 contains correct amount and tokenId
    // -------------------------------------------------------------------------

    @Test
    public void testMintPP1ContainsCorrectAmountAndTokenId() throws Exception {
        Transaction bobFundingTx = getBobFundingTx();

        Transaction mintTx = tool.createFungibleMintTxn(
                bobFundingTx,
                bobSigningCallback(),
                bobPubKey,
                bobAddress,
                bobFundingTx.getTransactionIdBytes(),
                DUMMY_RABIN_PKH,
                5000,
                null);

        // Extract tokenId from PP1_FT output script at bytes 22-53
        Script pp1Script = mintTx.getOutputs().get(1).getScript();
        assertNotNull("PP1_FT script should be parseable", pp1Script);

        byte[] tokenId = Arrays.copyOfRange(pp1Script.getProgram(), 22, 54);

        // tokenId should match the funding tx id
        assertArrayEquals("tokenId should be funding tx hash",
                bobFundingTx.getTransactionIdBytes(), tokenId);
    }

    // -------------------------------------------------------------------------
    // 3. Witness produces 1 output
    // -------------------------------------------------------------------------

    @Test
    public void testWitnessProduces1Output() throws Exception {
        Transaction bobFundingTx = getBobFundingTx();

        Transaction mintTx = tool.createFungibleMintTxn(
                bobFundingTx,
                bobSigningCallback(),
                bobPubKey,
                bobAddress,
                bobFundingTx.getTransactionIdBytes(),
                DUMMY_RABIN_PKH,
                1000,
                null);

        Transaction witnessTx = tool.createFungibleWitnessTxn(
                bobSigningCallback(),
                bobPubKey,
                bobFundingTx,
                mintTx,
                bobPubKey,
                bobAddress.getHash(),
                FungibleTokenAction.MINT,
                null,  // parentTokenTxBytes
                0,     // parentOutputCount
                1,     // tripletBaseIndex
                null,  // parentTokenTxBytesB
                0,     // parentOutputCountB
                0,     // parentPP1FtIndexA
                0,     // parentPP1FtIndexB
                0,     // sendAmount
                0,     // changeAmount
                null   // recipientPKH
        );

        assertEquals("Witness should produce 1 output", 1, witnessTx.getOutputs().size());
    }

    // -------------------------------------------------------------------------
    // 4. Transfer produces 5 outputs
    // -------------------------------------------------------------------------

    @Test
    public void testTransferProduces5Outputs() throws Exception {
        Transaction bobFundingTx = getBobFundingTx();

        // Step 1: Mint
        Transaction mintTx = tool.createFungibleMintTxn(
                bobFundingTx,
                bobSigningCallback(),
                bobPubKey,
                bobAddress,
                bobFundingTx.getTransactionIdBytes(),
                DUMMY_RABIN_PKH,
                1000,
                null);

        byte[] tokenId = bobFundingTx.getTransactionIdBytes();

        // Step 2: Witness for mint
        Transaction mintWitnessTx = tool.createFungibleWitnessTxn(
                bobSigningCallback(),
                bobPubKey,
                bobFundingTx,
                mintTx,
                bobPubKey,
                bobAddress.getHash(),
                FungibleTokenAction.MINT,
                null, 0, 1, null, 0, 0, 0, 0, 0, null);

        // Step 3: Transfer to Alice
        Transaction transferFundingTx = getBobFundingTx();
        Transaction aliceFundingTx = getAliceFundingTx();

        Transaction transferTx = tool.createFungibleTransferTxn(
                mintWitnessTx,
                mintTx,
                bobPubKey,
                aliceAddress,
                transferFundingTx,
                bobSigningCallback(),
                bobPubKey,
                aliceFundingTx.getTransactionIdBytes(),
                tokenId,
                1000,
                1);

        assertEquals("Transfer should produce 5 outputs", 5, transferTx.getOutputs().size());
    }

    // -------------------------------------------------------------------------
    // 5. Split produces 8 outputs
    // -------------------------------------------------------------------------

    @Test
    public void testSplitProduces8Outputs() throws Exception {
        Transaction bobFundingTx = getBobFundingTx();

        // Mint 1000 tokens
        Transaction mintTx = tool.createFungibleMintTxn(
                bobFundingTx,
                bobSigningCallback(),
                bobPubKey,
                bobAddress,
                bobFundingTx.getTransactionIdBytes(),
                DUMMY_RABIN_PKH,
                1000,
                null);

        byte[] tokenId = bobFundingTx.getTransactionIdBytes();

        // Mint witness
        Transaction mintWitnessTx = tool.createFungibleWitnessTxn(
                bobSigningCallback(),
                bobPubKey,
                bobFundingTx,
                mintTx,
                bobPubKey,
                bobAddress.getHash(),
                FungibleTokenAction.MINT,
                null, 0, 1, null, 0, 0, 0, 0, 0, null);

        // Split: send 300 to Alice, 700 change to Bob
        Transaction splitFundingTx = getBobFundingTx();
        Transaction aliceFundingTx = getAliceFundingTx();
        Transaction changeFundingTx = getBobFundingTx();

        Transaction splitTx = tool.createFungibleSplitTxn(
                mintWitnessTx,
                mintTx,
                bobPubKey,
                aliceAddress,
                300,
                splitFundingTx,
                bobSigningCallback(),
                bobPubKey,
                aliceFundingTx.getTransactionIdBytes(),
                changeFundingTx.getTransactionIdBytes(),
                tokenId,
                1000,
                1);

        assertEquals("Split should produce 8 outputs", 8, splitTx.getOutputs().size());

        // Output[0]: Change (satoshis > 0)
        assertTrue("Change output should have satoshis",
                splitTx.getOutputs().get(0).getAmount().compareTo(BigInteger.ZERO) > 0);

        // Outputs[1-3]: Recipient triplet (1 sat each)
        assertEquals(BigInteger.ONE, splitTx.getOutputs().get(1).getAmount());
        assertEquals(BigInteger.ONE, splitTx.getOutputs().get(2).getAmount());
        assertEquals(BigInteger.ONE, splitTx.getOutputs().get(3).getAmount());

        // Outputs[4-6]: Change triplet (1 sat each)
        assertEquals(BigInteger.ONE, splitTx.getOutputs().get(4).getAmount());
        assertEquals(BigInteger.ONE, splitTx.getOutputs().get(5).getAmount());
        assertEquals(BigInteger.ONE, splitTx.getOutputs().get(6).getAmount());

        // Output[7]: Metadata (0 sats)
        assertEquals(BigInteger.ZERO, splitTx.getOutputs().get(7).getAmount());
    }

    // -------------------------------------------------------------------------
    // 6. Burn produces 1 output and 4 inputs
    // -------------------------------------------------------------------------

    @Test
    public void testBurnProduces1OutputAnd4Inputs() throws Exception {
        Transaction bobFundingTx = getBobFundingTx();

        // Mint
        Transaction mintTx = tool.createFungibleMintTxn(
                bobFundingTx,
                bobSigningCallback(),
                bobPubKey,
                bobAddress,
                bobFundingTx.getTransactionIdBytes(),
                DUMMY_RABIN_PKH,
                1000,
                null);

        byte[] tokenId = bobFundingTx.getTransactionIdBytes();

        // Witness
        Transaction mintWitnessTx = tool.createFungibleWitnessTxn(
                bobSigningCallback(),
                bobPubKey,
                bobFundingTx,
                mintTx,
                bobPubKey,
                bobAddress.getHash(),
                FungibleTokenAction.MINT,
                null, 0, 1, null, 0, 0, 0, 0, 0, null);

        // Transfer to Alice
        Transaction transferFundingTx = getBobFundingTx();
        Transaction aliceFundingTx = getAliceFundingTx();

        Transaction transferTx = tool.createFungibleTransferTxn(
                mintWitnessTx,
                mintTx,
                bobPubKey,
                aliceAddress,
                transferFundingTx,
                bobSigningCallback(),
                bobPubKey,
                aliceFundingTx.getTransactionIdBytes(),
                tokenId,
                1000,
                1);

        // Burn Alice's tokens
        Transaction burnFundingTx = getAliceFundingTx();

        Transaction burnTx = tool.createFungibleBurnTxn(
                transferTx,
                aliceSigningCallback(),
                alicePubKey,
                burnFundingTx,
                aliceSigningCallback(),
                alicePubKey,
                1);

        assertEquals("Burn should produce 1 output", 1, burnTx.getOutputs().size());
        assertEquals("Burn should have 4 inputs (funding + PP1 + PP2 + PP3)",
                4, burnTx.getInputs().size());
    }

    // -------------------------------------------------------------------------
    // 7. Merge produces 5 outputs and 5 inputs
    // -------------------------------------------------------------------------

    @Test
    public void testMergeProduces5Outputs() throws Exception {
        Transaction bobFundingTx = getBobFundingTx();

        // --- First mint: 600 tokens ---
        Transaction mintTxA = tool.createFungibleMintTxn(
                bobFundingTx,
                bobSigningCallback(),
                bobPubKey,
                bobAddress,
                bobFundingTx.getTransactionIdBytes(),
                DUMMY_RABIN_PKH,
                600,
                null);

        byte[] tokenId = bobFundingTx.getTransactionIdBytes();

        Transaction mintWitnessTxA = tool.createFungibleWitnessTxn(
                bobSigningCallback(),
                bobPubKey,
                bobFundingTx,
                mintTxA,
                bobPubKey,
                bobAddress.getHash(),
                FungibleTokenAction.MINT,
                null, 0, 1, null, 0, 0, 0, 0, 0, null);

        // --- Second mint: 400 tokens ---
        Transaction bobFundingTx2 = getBobFundingTx();

        Transaction mintTxB = tool.createFungibleMintTxn(
                bobFundingTx2,
                bobSigningCallback(),
                bobPubKey,
                bobAddress,
                bobFundingTx2.getTransactionIdBytes(),
                DUMMY_RABIN_PKH,
                400,
                null);

        Transaction mintWitnessTxB = tool.createFungibleWitnessTxn(
                bobSigningCallback(),
                bobPubKey,
                bobFundingTx2,
                mintTxB,
                bobPubKey,
                bobAddress.getHash(),
                FungibleTokenAction.MINT,
                null, 0, 1, null, 0, 0, 0, 0, 0, null);

        // --- Merge: 600 + 400 = 1000 ---
        Transaction mergeFundingTx = getBobFundingTx();

        Transaction mergeTx = tool.createFungibleMergeTxn(
                mintWitnessTxA,
                mintTxA,
                mintWitnessTxB,
                mintTxB,
                bobPubKey,
                bobSigningCallback(),
                mergeFundingTx,
                bobSigningCallback(),
                bobPubKey,
                mergeFundingTx.getTransactionIdBytes(),
                tokenId,
                1000,
                1,
                1);

        assertEquals("Merge should produce 5 outputs", 5, mergeTx.getOutputs().size());
        assertEquals("Merge should have 5 inputs (funding + witnessA + witnessB + PP3_A + PP3_B)",
                5, mergeTx.getInputs().size());
    }

    // -------------------------------------------------------------------------
    // 8. Transfer witness PP1 clean stack + interpreter verification
    // -------------------------------------------------------------------------

    @Test
    public void testTransferWitnessPP1CleanStack() throws Exception {
        Transaction bobFundingTx = getBobFundingTx();

        // Step 1: Mint 1000 tokens
        Transaction mintTx = tool.createFungibleMintTxn(
                bobFundingTx,
                bobSigningCallback(),
                bobPubKey,
                bobAddress,
                bobFundingTx.getTransactionIdBytes(),
                DUMMY_RABIN_PKH,
                1000,
                null);

        byte[] tokenId = bobFundingTx.getTransactionIdBytes();

        // Step 2: Mint witness
        Transaction mintWitnessTx = tool.createFungibleWitnessTxn(
                bobSigningCallback(),
                bobPubKey,
                bobFundingTx,
                mintTx,
                bobPubKey,
                bobAddress.getHash(),
                FungibleTokenAction.MINT,
                null, 0, 1, null, 0, 0, 0, 0, 0, null);

        // Step 3: Transfer to Alice
        Transaction transferFundingTx = getBobFundingTx();
        Transaction aliceFundingTx = getAliceFundingTx();

        Transaction transferTx = tool.createFungibleTransferTxn(
                mintWitnessTx,
                mintTx,
                bobPubKey,
                aliceAddress,
                transferFundingTx,
                bobSigningCallback(),
                bobPubKey,
                aliceFundingTx.getTransactionIdBytes(),
                tokenId,
                1000,
                1);

        // Step 4: Transfer witness
        // tokenChangePKH must be the PREVIOUS owner's PKH (Bob built the transfer)
        Transaction witnessAfterTransferFunding = getBobFundingTx();
        Transaction transferWitness = tool.createFungibleWitnessTxn(
                aliceSigningCallback(),
                alicePubKey,
                witnessAfterTransferFunding,
                transferTx,
                alicePubKey,
                bobAddress.getHash(),
                FungibleTokenAction.TRANSFER,
                mintTx.serialize(),
                5,
                1,
                null, 0, 1, 0, 0, 0, null);

        // Verify PP1 input (input[1]) passes consensus and leaves clean stack
        EnumSet<Script.VerifyFlag> flags = EnumSet.of(
                Script.VerifyFlag.SIGHASH_FORKID,
                Script.VerifyFlag.UTXO_AFTER_GENESIS);

        Script scriptSig = transferWitness.getInputs().get(1).getScriptSig();
        Script scriptPubKey = transferTx.getOutputs().get(1).getScript();
        long pp1Sats = transferTx.getOutputs().get(1).getAmount().longValue();

        Interpreter interp = new Interpreter();
        interp.correctlySpends(scriptSig, scriptPubKey, transferWitness, 1,
                flags, Coin.valueOf(pp1Sats));

        // Verify clean stack
        LinkedList<byte[]> stack = new LinkedList<>();
        Interpreter.executeScript(transferWitness, 1, scriptSig, stack,
                Coin.valueOf(pp1Sats), flags);
        Interpreter.executeScript(transferWitness, 1, scriptPubKey, stack,
                Coin.valueOf(pp1Sats), flags);
        assertEquals("PP1 FT transfer witness must leave clean stack", 1, stack.size());
    }
}
