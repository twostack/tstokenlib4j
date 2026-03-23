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
import org.twostack.tstokenlib4j.parser.PP1TemplateRegistrar;
import org.twostack.tstokenlib4j.unlock.RestrictedFungibleTokenAction;

import java.math.BigInteger;
import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * Integration tests for {@link RestrictedFungibleTokenTool}, ported from the Dart rft_token_test.dart.
 *
 * <p>Exercises the full restricted fungible token lifecycle: mint, witness, transfer, split, burn, and redeem.
 */
public class RestrictedFungibleTokenToolTest {

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

    private static int sigHashAll;

    // --- Rabin key material ---
    private static RabinKeyPair rabinKeyPair;
    private static byte[] rabinNBytes;
    private static byte[] rabinPubKeyHash;

    // --- Identity material ---
    private static byte[] dummyIdentityTxId;
    private static byte[] dummyEd25519PubKey;

    // --- RestrictedFungibleTokenTool instance ---
    private static RestrictedFungibleTokenTool tool;

    @BeforeClass
    public static void setUpClass() throws Exception {
        PP1TemplateRegistrar.registerAll();

        // Keys
        bobPrivateKey = PrivateKey.fromWIF(BOB_WIF);
        bobPub = bobPrivateKey.getPublicKey();
        bobAddress = Address.fromKey(NetworkAddressType.TEST_PKH, bobPub);

        alicePrivateKey = PrivateKey.fromWIF(ALICE_WIF);
        alicePub = alicePrivateKey.getPublicKey();
        aliceAddress = Address.fromKey(NetworkAddressType.TEST_PKH, alicePub);

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

        // RestrictedFungibleTokenTool
        tool = new RestrictedFungibleTokenTool(NetworkAddressType.TEST_PKH);
    }

    /**
     * Pre-compute Rabin signature for a given tokenId.
     * Message = sha256(identityTxId || ed25519PubKey || tokenId)
     */
    private static RabinSignature computeRabinSig(byte[] tokenId) {
        byte[] concat = new byte[dummyIdentityTxId.length + dummyEd25519PubKey.length + tokenId.length];
        System.arraycopy(dummyIdentityTxId, 0, concat, 0, dummyIdentityTxId.length);
        System.arraycopy(dummyEd25519PubKey, 0, concat, dummyIdentityTxId.length, dummyEd25519PubKey.length);
        System.arraycopy(tokenId, 0, concat, dummyIdentityTxId.length + dummyEd25519PubKey.length, tokenId.length);
        java.math.BigInteger messageHash = Rabin.hashBytesToScriptInt(sha256(concat));
        return Rabin.sign(messageHash, rabinKeyPair.p(), rabinKeyPair.q());
    }

    private static byte[] sha256(byte[] data) {
        try {
            return java.security.MessageDigest.getInstance("SHA-256").digest(data);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    // --- Helper methods ---

    private static Transaction getBobFundingTx() {
        return Transaction.fromHex(BOB_FUNDING_TX_HEX);
    }

    private static Transaction getAliceFundingTx() {
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
                bobPub,
                bobAddress,
                bobFundingTx.getTransactionIdBytes(),
                rabinPubKeyHash,
                0x00,
                1000,
                0, new byte[32],
                null);

        assertEquals("Mint should produce 5 outputs", 5, mintTx.getOutputs().size());
        assertEquals("Mint should have 1 input", 1, mintTx.getInputs().size());

        // Output[0]: Change (satoshis > 0)
        assertTrue("Change output should have satoshis",
                mintTx.getOutputs().get(0).getAmount().compareTo(BigInteger.ZERO) > 0);

        // Outputs[1-3]: PP1_RFT, PP2-FT, PP3-FT (1 sat each)
        assertEquals(BigInteger.ONE, mintTx.getOutputs().get(1).getAmount());
        assertEquals(BigInteger.ONE, mintTx.getOutputs().get(2).getAmount());
        assertEquals(BigInteger.ONE, mintTx.getOutputs().get(3).getAmount());

        // Output[4]: Metadata (0 sats)
        assertEquals(BigInteger.ZERO, mintTx.getOutputs().get(4).getAmount());
    }

    // -------------------------------------------------------------------------
    // 2. Mint PP1 contains correct tokenId
    // -------------------------------------------------------------------------

    @Test
    public void testMintPP1ContainsCorrectTokenId() throws Exception {
        Transaction bobFundingTx = getBobFundingTx();

        Transaction mintTx = tool.createFungibleMintTxn(
                bobFundingTx,
                bobSigningCallback(),
                bobPub,
                bobAddress,
                bobFundingTx.getTransactionIdBytes(),
                rabinPubKeyHash,
                0x00,
                1000,
                0, new byte[32],
                null);

        // Extract tokenId from PP1_RFT output script at bytes 22-53
        Script pp1Script = mintTx.getOutputs().get(1).getScript();
        assertNotNull("PP1_RFT script should be parseable", pp1Script);

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
                bobPub,
                bobAddress,
                bobFundingTx.getTransactionIdBytes(),
                rabinPubKeyHash,
                0x00,
                1000,
                0, new byte[32],
                null);

        Transaction witnessTx = tool.createRftWitnessTxn(
                bobSigningCallback(),
                bobPub,
                bobFundingTx,
                mintTx,
                bobPub,
                bobAddress.getHash(),
                RestrictedFungibleTokenAction.MINT,
                null,  // parentTokenTxBytes
                0,     // parentOutputCount
                1,     // tripletBaseIndex
                0,     // parentPP1FtIndex
                rabinNBytes,
                Rabin.bigIntToScriptNum(computeRabinSig(bobFundingTx.getTransactionIdBytes()).s()),
                computeRabinSig(bobFundingTx.getTransactionIdBytes()).padding(),
                dummyIdentityTxId,
                dummyEd25519PubKey,
                null,  // parentTokenTxBytesB
                0,     // parentOutputCountB
                0,     // parentPP1FtIndexB
                0,     // recipientAmount
                0,     // tokenChangeAmount
                null,  // recipientPKH
                null,  // merkleProof
                null   // merkleSides
        );

        assertEquals("Witness should produce 1 output", 1, witnessTx.getOutputs().size());
    }

    // -------------------------------------------------------------------------
    // 4. Transfer produces 5 outputs
    // -------------------------------------------------------------------------

    @Test
    public void testTransferProduces5Outputs() throws Exception {
        Transaction bobFundingTx = getBobFundingTx();
        byte[] tokenId = bobFundingTx.getTransactionIdBytes();

        // Step 1: Mint
        Transaction mintTx = tool.createFungibleMintTxn(
                bobFundingTx,
                bobSigningCallback(),
                bobPub,
                bobAddress,
                bobFundingTx.getTransactionIdBytes(),
                rabinPubKeyHash,
                0x00,
                1000,
                0, new byte[32],
                null);

        // Step 2: Witness for mint
        Transaction mintWitnessTx = tool.createRftWitnessTxn(
                bobSigningCallback(),
                bobPub,
                bobFundingTx,
                mintTx,
                bobPub,
                bobAddress.getHash(),
                RestrictedFungibleTokenAction.MINT,
                null, 0, 1, 0,
                rabinNBytes,
                Rabin.bigIntToScriptNum(computeRabinSig(bobFundingTx.getTransactionIdBytes()).s()),
                computeRabinSig(bobFundingTx.getTransactionIdBytes()).padding(),
                dummyIdentityTxId, dummyEd25519PubKey,
                null, 0, 0, 0, 0, null, null, null);

        // Step 3: Transfer to Alice
        Transaction transferFundingTx = getBobFundingTx();
        Transaction aliceFundingTx = getAliceFundingTx();

        Transaction transferTx = tool.createRftTransferTxn(
                mintWitnessTx,
                mintTx,
                bobPub,
                aliceAddress,
                transferFundingTx,
                bobSigningCallback(),
                bobPub,
                aliceFundingTx.getTransactionIdBytes(),
                tokenId,
                rabinPubKeyHash,
                0x00,
                1000,
                0, new byte[32],
                1);

        assertEquals("Transfer should produce 5 outputs", 5, transferTx.getOutputs().size());
    }

    // -------------------------------------------------------------------------
    // 5. Burn produces 1 output and 4 inputs
    // -------------------------------------------------------------------------

    @Test
    public void testBurnProduces1OutputAnd4Inputs() throws Exception {
        Transaction bobFundingTx = getBobFundingTx();

        // Mint
        Transaction mintTx = tool.createFungibleMintTxn(
                bobFundingTx,
                bobSigningCallback(),
                bobPub,
                bobAddress,
                bobFundingTx.getTransactionIdBytes(),
                rabinPubKeyHash,
                0x00,
                1000,
                0, new byte[32],
                null);

        // Burn
        Transaction burnFundingTx = getBobFundingTx();

        Transaction burnTx = tool.createBurnTokenTxn(
                mintTx,
                bobSigningCallback(),
                bobPub,
                burnFundingTx,
                bobSigningCallback(),
                bobPub);

        assertEquals("Burn should produce 1 output", 1, burnTx.getOutputs().size());
        assertEquals("Burn should have 4 inputs (funding + PP1 + PP2 + PP3)",
                4, burnTx.getInputs().size());
    }

    // -------------------------------------------------------------------------
    // 6. Redeem produces 1 output and 4 inputs
    // -------------------------------------------------------------------------

    @Test
    public void testRedeemProduces1OutputAnd4Inputs() throws Exception {
        Transaction bobFundingTx = getBobFundingTx();

        // Mint
        Transaction mintTx = tool.createFungibleMintTxn(
                bobFundingTx,
                bobSigningCallback(),
                bobPub,
                bobAddress,
                bobFundingTx.getTransactionIdBytes(),
                rabinPubKeyHash,
                0x00,
                1000,
                0, new byte[32],
                null);

        // Redeem
        Transaction redeemFundingTx = getBobFundingTx();

        Transaction redeemTx = tool.createRedeemTokenTxn(
                mintTx,
                bobSigningCallback(),
                bobPub,
                redeemFundingTx,
                bobSigningCallback(),
                bobPub);

        assertEquals("Redeem should produce 1 output", 1, redeemTx.getOutputs().size());
        assertEquals("Redeem should have 4 inputs (funding + PP1 + PP2 + PP3)",
                4, redeemTx.getInputs().size());
    }

    // -------------------------------------------------------------------------
    // 7. Split produces 8 outputs
    // -------------------------------------------------------------------------

    @Test
    public void testSplitProduces8Outputs() throws Exception {
        Transaction bobFundingTx = getBobFundingTx();
        byte[] tokenId = bobFundingTx.getTransactionIdBytes();

        // Mint 1000 tokens
        Transaction mintTx = tool.createFungibleMintTxn(
                bobFundingTx,
                bobSigningCallback(),
                bobPub,
                bobAddress,
                bobFundingTx.getTransactionIdBytes(),
                rabinPubKeyHash,
                0x00,
                1000,
                0, new byte[32],
                null);

        // Mint witness
        Transaction mintWitnessTx = tool.createRftWitnessTxn(
                bobSigningCallback(),
                bobPub,
                bobFundingTx,
                mintTx,
                bobPub,
                bobAddress.getHash(),
                RestrictedFungibleTokenAction.MINT,
                null, 0, 1, 0,
                rabinNBytes,
                Rabin.bigIntToScriptNum(computeRabinSig(bobFundingTx.getTransactionIdBytes()).s()),
                computeRabinSig(bobFundingTx.getTransactionIdBytes()).padding(),
                dummyIdentityTxId, dummyEd25519PubKey,
                null, 0, 0, 0, 0, null, null, null);

        // Split: send 300 to Alice, 700 change to Bob
        Transaction splitFundingTx = getBobFundingTx();
        Transaction aliceFundingTx = getAliceFundingTx();
        Transaction changeFundingTx = getBobFundingTx();

        Transaction splitTx = tool.createRftSplitTxn(
                mintWitnessTx,
                mintTx,
                bobPub,
                aliceAddress,
                300,
                splitFundingTx,
                bobSigningCallback(),
                bobPub,
                aliceFundingTx.getTransactionIdBytes(),
                changeFundingTx.getTransactionIdBytes(),
                tokenId,
                rabinPubKeyHash,
                0x00,
                1000,
                0, new byte[32],
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
}
