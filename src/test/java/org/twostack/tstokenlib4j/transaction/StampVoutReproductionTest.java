package org.twostack.tstokenlib4j.transaction;

import org.junit.BeforeClass;
import org.junit.Test;
import org.twostack.bitcoin4j.*;
import org.twostack.bitcoin4j.params.NetworkAddressType;
import org.twostack.bitcoin4j.transaction.Transaction;
import org.twostack.tstokenlib4j.parser.PP1TemplateRegistrar;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/**
 * Reproduces the production stamp failure (ARC 461 OP_EQUALVERIFY).
 *
 * Root cause: the coordinator selects a funding UTXO at vout=0 (a previous
 * token TX's change output), but AppendableTokenTool hardcodes
 * spendFromTransaction(fundingTx, 1, ...) — spending the PP1 output (1 sat,
 * 4457-byte template script) instead of the P2PKH change output.
 *
 * The P2PKH unlocker pushes [sig, pubkey] but the PP1 template expects
 * completely different stack elements → OP_EQUALVERIFY at the script level.
 *
 * Uses actual production TX hex dumped from the wallet database.
 */
public class StampVoutReproductionTest {

    private static final String SIGNER_WIF = "cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS";
    private static PrivateKey signerKey;
    private static PublicKey signerPub;

    private static Transaction fundingTx;
    private static Transaction issuanceTx;
    private static Transaction witnessTx;

    @BeforeClass
    public static void setUp() throws Exception {
        PP1TemplateRegistrar.registerAll();
        signerKey = PrivateKey.fromWIF(SIGNER_WIF);
        signerPub = signerKey.getPublicKey();

        Path fundingPath = Path.of("/tmp/funding_tx.hex");
        Path issuancePath = Path.of("/tmp/issuance_tx.hex");
        Path witnessPath = Path.of("/tmp/witness_tx.hex");

        if (Files.exists(fundingPath) && Files.exists(issuancePath) && Files.exists(witnessPath)) {
            fundingTx = Transaction.fromHex(Files.readString(fundingPath).trim());
            issuanceTx = Transaction.fromHex(Files.readString(issuancePath).trim());
            witnessTx = Transaction.fromHex(Files.readString(witnessPath).trim());
        }
    }

    /**
     * Proves the production bug: when the funding UTXO is at vout=0 (P2PKH change),
     * the hardcoded vout=1 causes the stamp TX to reference a PP1 template output
     * instead of the P2PKH output. ARC rejects with OP_EQUALVERIFY because the
     * P2PKH unlocker cannot satisfy the PP1 template script.
     */
    @Test
    public void stampWithHardcodedVout1_referencesWrongOutput() throws Exception {
        assumeTrue("Production TX hex files required in /tmp/", fundingTx != null);

        // Precondition: funding TX has P2PKH at vout=0, PP1 template at vout=1
        int vout0ScriptLen = fundingTx.getOutputs().get(0).getScript().getProgram().length;
        int vout1ScriptLen = fundingTx.getOutputs().get(1).getScript().getProgram().length;
        assertEquals("vout=0 should be P2PKH (25 bytes)", 25, vout0ScriptLen);
        assertEquals("vout=1 should be PP1 template (4457 bytes)", 4457, vout1ScriptLen);

        long vout0Sats = fundingTx.getOutputs().get(0).getAmount().longValue();
        long vout1Sats = fundingTx.getOutputs().get(1).getAmount().longValue();
        assertTrue("vout=0 (change) should have substantial value", vout0Sats > 1_000_000);
        assertEquals("vout=1 (PP1) should be 1 sat", 1, vout1Sats);

        // Build stamp TX with hardcoded fundingVout=1 (the production bug)
        AppendableTokenTool atTool = new AppendableTokenTool(NetworkAddressType.TEST_PKH);
        SigningCallback signer = sighash -> signerKey.sign(sighash);

        byte[] ownerPKH = new byte[20];
        byte[] parentPP1 = issuanceTx.getOutputs().get(1).getScript().getProgram();
        System.arraycopy(parentPP1, 1, ownerPKH, 0, 20);

        byte[] tokenId = Utils.HEX.decode(
                "3a3d0e7ce5729e9b2b874cf772ff46ed52ff2f17e578ced0fe2fe5007f1c4aef");

        Transaction stampTx = atTool.createTokenStampTxn(
                witnessTx, issuanceTx, signerPub,
                fundingTx, 1,  // ← HARDCODED vout=1 (the bug)
                signer, signerPub,
                new byte[36], "test-stamp".getBytes(),
                ownerPKH, tokenId, signerPub.getPubKeyHash(),
                0, 10, new byte[32]);

        // The stamp TX's input[0] spends fundingTx:1 — a PP1 template, not P2PKH
        var input0 = stampTx.getInputs().get(0);
        assertEquals("stamp input[0] references vout=1 (wrong)",
                1, (int) input0.getPrevTxnOutputIndex());

        // The output being spent is 4457-byte PP1 template — P2PKH unlocker can't satisfy it
        int spentScriptLen = fundingTx.getOutputs().get(1).getScript().getProgram().length;
        assertEquals("spent output is PP1 template, not P2PKH", 4457, spentScriptLen);

        // Only 1 sat available from PP1, so change = 1 - 3 - 135 = negative → ARC 464
        // OR the P2PKH unlocker fails against PP1 template → ARC 461 OP_EQUALVERIFY
        System.out.println("BUG REPRODUCED: stamp TX input[0] spends vout=1 (PP1 template, 1 sat) " +
                "instead of vout=0 (P2PKH change, " + vout0Sats + " sats)");
    }

    /**
     * Verifies the fix: using the correct fundingVout=0 makes input[0] reference
     * the P2PKH change output.
     */
    @Test
    public void stampWithCorrectVout0_referencesP2PKHOutput() throws Exception {
        assumeTrue("Production TX hex files required in /tmp/", fundingTx != null);

        AppendableTokenTool atTool = new AppendableTokenTool(NetworkAddressType.TEST_PKH);
        SigningCallback signer = sighash -> signerKey.sign(sighash);

        byte[] ownerPKH = new byte[20];
        byte[] parentPP1 = issuanceTx.getOutputs().get(1).getScript().getProgram();
        System.arraycopy(parentPP1, 1, ownerPKH, 0, 20);

        byte[] tokenId = Utils.HEX.decode(
                "3a3d0e7ce5729e9b2b874cf772ff46ed52ff2f17e578ced0fe2fe5007f1c4aef");

        Transaction stampTx = atTool.createTokenStampTxn(
                witnessTx, issuanceTx, signerPub,
                fundingTx, 0,  // ← CORRECT vout=0 (the fix)
                signer, signerPub,
                new byte[36], "test-stamp".getBytes(),
                ownerPKH, tokenId, signerPub.getPubKeyHash(),
                0, 10, new byte[32]);

        // The stamp TX's input[0] now spends fundingTx:0 — the P2PKH change output
        var input0 = stampTx.getInputs().get(0);
        assertEquals("stamp input[0] references vout=0 (correct)",
                0, (int) input0.getPrevTxnOutputIndex());

        int spentScriptLen = fundingTx.getOutputs().get(0).getScript().getProgram().length;
        assertEquals("spent output is P2PKH (25 bytes)", 25, spentScriptLen);

        System.out.println("FIX VERIFIED: stamp TX input[0] correctly spends vout=0 " +
                "(P2PKH change, " + fundingTx.getOutputs().get(0).getAmount() + " sats)");
    }
}
