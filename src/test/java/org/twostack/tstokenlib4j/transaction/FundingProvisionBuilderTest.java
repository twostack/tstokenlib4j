package org.twostack.tstokenlib4j.transaction;

import org.junit.Test;
import org.twostack.bitcoin4j.*;
import org.twostack.bitcoin4j.params.NetworkAddressType;
import org.twostack.bitcoin4j.script.Interpreter;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.transaction.Transaction;
import org.twostack.libspiffy4j.plugin.ProvisionedTransaction;

import java.util.EnumSet;
import java.util.List;

import static org.junit.Assert.*;

public class FundingProvisionBuilderTest {

    // Same test key as WitnessDebugTest
    static final String BOB_WIF = "cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS";
    static final String BOB_FUNDING_TX_HEX =
            "0200000001cf5ae107ead0a5117ea2124aacb61d0d700de05a937ed3e48c9245bfab19dd8c000000004847304402206edac55dd4f791a611e05a6d946862ca45d914d0cdf391bfd982399c3d84ea4602205a196505d536b3646834051793acd5d9e820249979c94d0a4252298d0ffe9a7041feffffff0200196bee000000001976a914da217dfa3513d4224802556228d07b278af36b0388ac00ca9a3b000000001976a914650c4adb156f19e36a755c820d892cda108299c488ac65000000";

    @Test
    public void singleLifecycleStep() throws Exception {
        PrivateKey bobPriv = PrivateKey.fromWIF(BOB_WIF);
        PublicKey bobPub = bobPriv.getPublicKey();
        Address bobAddress = Address.fromKey(NetworkAddressType.TEST_PKH, bobPub);
        SigningCallback bobSigner = sighash -> bobPriv.sign(sighash);
        Transaction fundingTx = Transaction.fromHex(BOB_FUNDING_TX_HEX);

        // fundingTx vout=1 has 1,000,000,000 sats (1 BSV), owned by Bob
        List<ProvisionedTransaction> results = FundingProvisionBuilder.provision(
                fundingTx, 1,
                bobSigner, bobPub,
                bobSigner, bobPub,  // same key for funding and change
                bobAddress,
                1, 100);  // 1 lifecycle step, 100 sat/KB

        // 1 split + 3 earmarks = 4 transactions
        assertEquals(4, results.size());

        // Split TX
        ProvisionedTransaction split = results.get(0);
        assertEquals("split", split.role());
        assertNull(split.purpose());
        Transaction splitTx = Transaction.fromHex(split.rawHex());
        assertEquals(4, splitTx.getOutputs().size()); // 3 earmarks + 1 change

        System.out.println("Split TX: " + split.txid());
        for (int i = 0; i < splitTx.getOutputs().size(); i++) {
            System.out.println("  OUTPUT[" + i + "]: " + splitTx.getOutputs().get(i).getAmount().longValue() + " sats");
        }

        // Earmarks
        String[] expectedPurposes = {"issuance-witness", "transfer", "transfer-witness"};
        for (int i = 0; i < 3; i++) {
            ProvisionedTransaction earmark = results.get(1 + i);
            assertEquals("earmark", earmark.role());
            assertEquals(expectedPurposes[i], earmark.purpose());
            assertEquals(1, earmark.fundingVout());
            assertTrue(earmark.fundingSats() > 0);

            Transaction earmarkTx = Transaction.fromHex(earmark.rawHex());
            assertEquals(2, earmarkTx.getOutputs().size());

            // vout=1 must match the declared fundingSats
            long vout1Sats = earmarkTx.getOutputs().get(1).getAmount().longValue();
            assertEquals(earmark.fundingSats(), vout1Sats);

            // vout=0 must be at least dust limit
            long vout0Sats = earmarkTx.getOutputs().get(0).getAmount().longValue();
            assertTrue("vout=0 should be >= dust (" + vout0Sats + ")", vout0Sats >= 546);

            // Earmark input must reference the split TX
            String prevTxid = Utils.HEX.encode(earmarkTx.getInputs().get(0).getPrevTxnId());
            assertEquals(split.txid(), prevTxid);

            // Earmark input vout must match the split output index
            int prevVout = (int) earmarkTx.getInputs().get(0).getPrevTxnOutputIndex();
            assertEquals(i, prevVout);

            System.out.println("Earmark " + earmark.purpose() + ": txid=" + earmark.txid()
                    + " vout1=" + vout1Sats + " sats");
        }

        // Change should be the bulk of the input
        long changeSats = splitTx.getOutputs().get(3).getAmount().longValue();
        assertTrue("Change should be large (" + changeSats + ")", changeSats > 999_000_000);
    }

    @Test
    public void multipleLifecycleSteps() throws Exception {
        PrivateKey bobPriv = PrivateKey.fromWIF(BOB_WIF);
        PublicKey bobPub = bobPriv.getPublicKey();
        Address bobAddress = Address.fromKey(NetworkAddressType.TEST_PKH, bobPub);
        SigningCallback bobSigner = sighash -> bobPriv.sign(sighash);
        Transaction fundingTx = Transaction.fromHex(BOB_FUNDING_TX_HEX);

        List<ProvisionedTransaction> results = FundingProvisionBuilder.provision(
                fundingTx, 1, bobSigner, bobPub, bobSigner, bobPub,
                bobAddress, 3, 100);

        // 1 split + 9 earmarks = 10 transactions
        assertEquals(10, results.size());
        assertEquals("split", results.get(0).role());

        Transaction splitTx = Transaction.fromHex(results.get(0).rawHex());
        assertEquals(10, splitTx.getOutputs().size()); // 9 earmarks + 1 change

        // Verify all earmarks
        for (int i = 1; i < results.size(); i++) {
            ProvisionedTransaction earmark = results.get(i);
            assertEquals("earmark", earmark.role());
            assertEquals(1, earmark.fundingVout());

            Transaction earmarkTx = Transaction.fromHex(earmark.rawHex());
            assertEquals(earmark.fundingSats(), earmarkTx.getOutputs().get(1).getAmount().longValue());
        }

        System.out.println("3 lifecycle steps: " + results.size() + " total TXs, "
                + "split has " + splitTx.getOutputs().size() + " outputs");
    }

    @Test
    public void insufficientFunds() throws Exception {
        PrivateKey bobPriv = PrivateKey.fromWIF(BOB_WIF);
        PublicKey bobPub = bobPriv.getPublicKey();
        Address bobAddress = Address.fromKey(NetworkAddressType.TEST_PKH, bobPub);
        SigningCallback bobSigner = sighash -> bobPriv.sign(sighash);

        // vout=1 has 1B sats (~1 BSV). At ~15,712 sats per step,
        // 100,000 steps needs ~1.57B sats — exceeds the 1B input.
        Transaction fundingTx = Transaction.fromHex(BOB_FUNDING_TX_HEX);
        try {
            FundingProvisionBuilder.provision(
                    fundingTx, 1, bobSigner, bobPub, bobSigner, bobPub,
                    bobAddress, 100_000, 100);
            fail("Should throw for insufficient funds");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("Insufficient funds"));
            System.out.println("Correctly rejected: " + e.getMessage());
        }
    }

    @Test
    public void scriptsVerifyInInterpreter() throws Exception {
        PrivateKey bobPriv = PrivateKey.fromWIF(BOB_WIF);
        PublicKey bobPub = bobPriv.getPublicKey();
        Address bobAddress = Address.fromKey(NetworkAddressType.TEST_PKH, bobPub);
        SigningCallback bobSigner = sighash -> bobPriv.sign(sighash);
        Transaction fundingTx = Transaction.fromHex(BOB_FUNDING_TX_HEX);

        List<ProvisionedTransaction> results = FundingProvisionBuilder.provision(
                fundingTx, 1, bobSigner, bobPub, bobSigner, bobPub,
                bobAddress, 1, 100);

        EnumSet<Script.VerifyFlag> flags = EnumSet.of(
                Script.VerifyFlag.SIGHASH_FORKID,
                Script.VerifyFlag.UTXO_AFTER_GENESIS,
                Script.VerifyFlag.MINIMALDATA);
        Interpreter interp = new Interpreter();

        // Verify split TX input against funding TX
        Transaction splitTx = Transaction.fromHex(results.get(0).rawHex());
        var splitInput = splitTx.getInputs().get(0);
        var fundingOutput = fundingTx.getOutputs().get(1);
        interp.correctlySpends(
                splitInput.getScriptSig(), fundingOutput.getScript(),
                splitTx, 0, flags, Coin.valueOf(fundingOutput.getAmount().longValue()));
        System.out.println("Split TX input: PASS");

        // Verify each earmark TX input against split TX
        for (int i = 1; i < results.size(); i++) {
            Transaction earmarkTx = Transaction.fromHex(results.get(i).rawHex());
            var earmarkInput = earmarkTx.getInputs().get(0);
            int prevVout = (int) earmarkInput.getPrevTxnOutputIndex();
            var splitOutput = splitTx.getOutputs().get(prevVout);

            interp.correctlySpends(
                    earmarkInput.getScriptSig(), splitOutput.getScript(),
                    earmarkTx, 0, flags, Coin.valueOf(splitOutput.getAmount().longValue()));
            System.out.println("Earmark " + results.get(i).purpose() + " input: PASS");
        }
    }

    @Test
    public void feeCalculation() throws Exception {
        // 226 bytes at 100 sat/KB = ceil(226 * 100 / 1000) = 23 sats
        assertEquals(23, FundingProvisionBuilder.computeFee(226, 100));

        // 1000 bytes at 100 sat/KB = 100 sats
        assertEquals(100, FundingProvisionBuilder.computeFee(1000, 100));

        // 1 byte at 100 sat/KB = ceil(100/1000) = 1 sat (minimum)
        assertEquals(1, FundingProvisionBuilder.computeFee(1, 100));

        // 66600 bytes at 100 sat/KB = ceil(6660000/1000) = 6660 sats
        assertEquals(6660, FundingProvisionBuilder.computeFee(66600, 100));
    }
}
