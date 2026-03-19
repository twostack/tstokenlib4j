package org.twostack.tstokenlib4j.transaction;

import org.junit.Test;
import org.twostack.bitcoin4j.*;
import org.twostack.bitcoin4j.params.NetworkAddressType;
import org.twostack.bitcoin4j.script.Interpreter;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptTraceCallback;
import org.twostack.bitcoin4j.transaction.Transaction;
import org.twostack.tstokenlib4j.crypto.Rabin;
import org.twostack.tstokenlib4j.crypto.RabinKeyPair;
import org.twostack.tstokenlib4j.crypto.RabinSignature;
import org.twostack.tstokenlib4j.unlock.TokenAction;

import java.math.BigInteger;
import java.util.EnumSet;
import java.util.LinkedList;

public class WitnessDebugTest {

    static final String BOB_WIF = "cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS";
    static final String BOB_FUNDING_TX_HEX =
            "0200000001cf5ae107ead0a5117ea2124aacb61d0d700de05a937ed3e48c9245bfab19dd8c000000004847304402206edac55dd4f791a611e05a6d946862ca45d914d0cdf391bfd982399c3d84ea4602205a196505d536b3646834051793acd5d9e820249979c94d0a4252298d0ffe9a7041feffffff0200196bee000000001976a914da217dfa3513d4224802556228d07b278af36b0388ac00ca9a3b000000001976a914650c4adb156f19e36a755c820d892cda108299c488ac65000000";

    @Test
    public void witnessVerification() throws Exception {
        TokenTool tokenTool = new TokenTool(NetworkAddressType.TEST_PKH);

        PrivateKey bobPriv = PrivateKey.fromWIF(BOB_WIF);
        PublicKey bobPub = bobPriv.getPublicKey();
        Address bobAddress = Address.fromKey(NetworkAddressType.TEST_PKH, bobPub);
        SigningCallback bobSigner = sighash -> bobPriv.sign(sighash);

        RabinKeyPair rabinKeyPair = Rabin.generateKeyPair(1024);
        byte[] rabinNBytes = Rabin.bigIntToScriptNum(rabinKeyPair.n());
        byte[] rabinPubKeyHash = Rabin.rabinPubKeyHash(rabinKeyPair.n());

        byte[] identityTxId = new byte[32];
        byte[] ed25519PubKey = new byte[32];
        for (int i = 0; i < 32; i++) { identityTxId[i] = (byte)(i+1); ed25519PubKey[i] = (byte)(i+33); }

        byte[] messageBytes = new byte[64];
        System.arraycopy(identityTxId, 0, messageBytes, 0, 32);
        System.arraycopy(ed25519PubKey, 0, messageBytes, 32, 32);
        BigInteger messageHash = Rabin.hashBytesToScriptInt(Sha256Hash.hash(messageBytes));
        RabinSignature rabinSig = Rabin.sign(messageHash, rabinKeyPair.p(), rabinKeyPair.q());
        byte[] rabinSBytes = Rabin.bigIntToScriptNum(rabinSig.s());

        Transaction fundingTx = Transaction.fromHex(BOB_FUNDING_TX_HEX);

        Transaction issuanceTx = tokenTool.createTokenIssuanceTxn(
                fundingTx, 1, bobSigner, bobPub, bobAddress,
                fundingTx.getTransactionIdBytes(), rabinPubKeyHash,
                "test".getBytes());

        System.out.println("Issuance txid: " + issuanceTx.getTransactionId());
        System.out.println("Issuance outputs: " + issuanceTx.getOutputs().size());
        for (int i = 0; i < issuanceTx.getOutputs().size(); i++) {
            System.out.println("  OUTPUT[" + i + "]: " + issuanceTx.getOutputs().get(i).getAmount().longValue()
                    + " sats, script len=" + issuanceTx.getOutputs().get(i).getScript().getProgram().length);
        }

        Transaction witnessTx = tokenTool.createWitnessTxn(
                bobSigner, bobPub, fundingTx, 1, issuanceTx, new byte[0],
                bobPub, bobAddress.getHash(), TokenAction.ISSUANCE,
                rabinNBytes, rabinSBytes, (long) rabinSig.padding(),
                identityTxId, ed25519PubKey);

        System.out.println("\nWitness txid: " + witnessTx.getTransactionId());
        System.out.println("Witness inputs: " + witnessTx.getInputs().size());
        System.out.println("Witness outputs: " + witnessTx.getOutputs().size());
        for (int i = 0; i < witnessTx.getOutputs().size(); i++) {
            System.out.println("  OUTPUT[" + i + "]: " + witnessTx.getOutputs().get(i).getAmount().longValue()
                    + " sats, script len=" + witnessTx.getOutputs().get(i).getScript().getProgram().length);
        }

        EnumSet<Script.VerifyFlag> consensusFlags = EnumSet.of(
                Script.VerifyFlag.SIGHASH_FORKID,
                Script.VerifyFlag.UTXO_AFTER_GENESIS);
        EnumSet<Script.VerifyFlag> policyFlags = EnumSet.of(
                Script.VerifyFlag.SIGHASH_FORKID,
                Script.VerifyFlag.UTXO_AFTER_GENESIS,
                Script.VerifyFlag.MINIMALDATA);
        Interpreter interp = new Interpreter();

        for (int i = 0; i < witnessTx.getInputs().size(); i++) {
            var input = witnessTx.getInputs().get(i);
            String prevTxid = Utils.HEX.encode(input.getPrevTxnId());
            int prevVout = (int) input.getPrevTxnOutputIndex();

            Transaction parentTx = prevTxid.equals(issuanceTx.getTransactionId()) ? issuanceTx : fundingTx;
            var parentOutput = parentTx.getOutputs().get(prevVout);
            String parentLabel = parentTx == issuanceTx ? "ISSUANCE" : "FUNDING";

            System.out.println("\nINPUT[" + i + "] spends " + parentLabel + "[" + prevVout + "]:");
            System.out.println("  scriptSig len=" + input.getScriptSig().getProgram().length);
            System.out.println("  scriptPubKey len=" + parentOutput.getScript().getProgram().length);
            System.out.println("  value=" + parentOutput.getAmount().longValue() + " sats");

            try {
                interp.correctlySpends(input.getScriptSig(), parentOutput.getScript(),
                        witnessTx, i, consensusFlags, Coin.valueOf(parentOutput.getAmount().longValue()));
                System.out.println("  CONSENSUS: PASS");
            } catch (Exception e) {
                System.out.println("  CONSENSUS: FAIL — " + e.getMessage());
            }
            try {
                interp.correctlySpends(input.getScriptSig(), parentOutput.getScript(),
                        witnessTx, i, policyFlags, Coin.valueOf(parentOutput.getAmount().longValue()));
                System.out.println("  POLICY:    PASS");
            } catch (Exception e) {
                System.out.println("  POLICY:    FAIL — " + e.getMessage());
            }
        }
    }

    /**
     * Reproduces the regtest scenario: witness is funded from the issuance tx's
     * change output (vout=0), NOT from the original funding tx.
     */
    @Test
    public void witnessWithIssuanceAsFunding() throws Exception {
        TokenTool tokenTool = new TokenTool(NetworkAddressType.TEST_PKH);

        PrivateKey bobPriv = PrivateKey.fromWIF(BOB_WIF);
        PublicKey bobPub = bobPriv.getPublicKey();
        Address bobAddress = Address.fromKey(NetworkAddressType.TEST_PKH, bobPub);
        SigningCallback bobSigner = sighash -> bobPriv.sign(sighash);

        RabinKeyPair rabinKeyPair = Rabin.generateKeyPair(1024);
        byte[] rabinNBytes = Rabin.bigIntToScriptNum(rabinKeyPair.n());
        byte[] rabinPubKeyHash = Rabin.rabinPubKeyHash(rabinKeyPair.n());

        byte[] identityTxId = new byte[32];
        byte[] ed25519PubKey = new byte[32];
        for (int i = 0; i < 32; i++) { identityTxId[i] = (byte)(i+1); ed25519PubKey[i] = (byte)(i+33); }

        byte[] messageBytes = new byte[64];
        System.arraycopy(identityTxId, 0, messageBytes, 0, 32);
        System.arraycopy(ed25519PubKey, 0, messageBytes, 32, 32);
        BigInteger messageHash = Rabin.hashBytesToScriptInt(Sha256Hash.hash(messageBytes));
        RabinSignature rabinSig = Rabin.sign(messageHash, rabinKeyPair.p(), rabinKeyPair.q());
        byte[] rabinSBytes = Rabin.bigIntToScriptNum(rabinSig.s());

        Transaction fundingTx = Transaction.fromHex(BOB_FUNDING_TX_HEX);

        // Step 1: Issue NFT (funded from original funding tx at vout=1)
        Transaction issuanceTx = tokenTool.createTokenIssuanceTxn(
                fundingTx, 1, bobSigner, bobPub, bobAddress,
                fundingTx.getTransactionIdBytes(), rabinPubKeyHash,
                "test".getBytes());

        System.out.println("=== REGTEST SCENARIO: Witness funded from issuance change output ===");
        System.out.println("Issuance txid: " + issuanceTx.getTransactionId());
        System.out.println("Issuance OUTPUT[0] (change): " + issuanceTx.getOutputs().get(0).getAmount().longValue() + " sats");

        // Step 2: Create witness funded from the ISSUANCE TX (change at vout=0)
        // This is what regtest does — the original funding UTXO was spent by the issuance,
        // so the witness uses the issuance's change output as funding.
        Transaction witnessTx = tokenTool.createWitnessTxn(
                bobSigner, bobPub,
                issuanceTx, 0,  // ← funding from ISSUANCE change output (vout=0)
                issuanceTx, new byte[0],
                bobPub, bobAddress.getHash(), TokenAction.ISSUANCE,
                rabinNBytes, rabinSBytes, (long) rabinSig.padding(),
                identityTxId, ed25519PubKey);

        System.out.println("\nWitness txid: " + witnessTx.getTransactionId());
        System.out.println("Witness inputs: " + witnessTx.getInputs().size());
        System.out.println("Witness outputs: " + witnessTx.getOutputs().size());

        // Verify each input
        EnumSet<Script.VerifyFlag> flags = EnumSet.of(
                Script.VerifyFlag.SIGHASH_FORKID,
                Script.VerifyFlag.UTXO_AFTER_GENESIS);
        Interpreter interp = new Interpreter();

        for (int i = 0; i < witnessTx.getInputs().size(); i++) {
            var input = witnessTx.getInputs().get(i);
            String prevTxid = Utils.HEX.encode(input.getPrevTxnId());
            int prevVout = (int) input.getPrevTxnOutputIndex();

            // All inputs should spend from issuanceTx in this scenario
            var parentOutput = issuanceTx.getOutputs().get(prevVout);

            System.out.println("\nINPUT[" + i + "] spends ISSUANCE[" + prevVout + "]:");
            System.out.println("  scriptSig len=" + input.getScriptSig().getProgram().length);
            System.out.println("  scriptPubKey len=" + parentOutput.getScript().getProgram().length);
            System.out.println("  value=" + parentOutput.getAmount().longValue() + " sats");

            try {
                interp.correctlySpends(input.getScriptSig(), parentOutput.getScript(),
                        witnessTx, i, flags, Coin.valueOf(parentOutput.getAmount().longValue()));
                System.out.println("  RESULT: PASS");
            } catch (Exception e) {
                System.out.println("  RESULT: FAIL — " + e.getMessage());
            }
        }
    }

    /**
     * Test witness funded at vout=0 instead of vout=1 to verify if PP1 hardcodes the vout.
     */
    @Test
    public void witnessWithFundingAtVout0() throws Exception {
        TokenTool tokenTool = new TokenTool(NetworkAddressType.TEST_PKH);

        PrivateKey bobPriv = PrivateKey.fromWIF(BOB_WIF);
        PublicKey bobPub = bobPriv.getPublicKey();
        Address bobAddress = Address.fromKey(NetworkAddressType.TEST_PKH, bobPub);
        SigningCallback bobSigner = sighash -> bobPriv.sign(sighash);

        RabinKeyPair rabinKeyPair = Rabin.generateKeyPair(1024);
        byte[] rabinNBytes = Rabin.bigIntToScriptNum(rabinKeyPair.n());
        byte[] rabinPubKeyHash = Rabin.rabinPubKeyHash(rabinKeyPair.n());

        byte[] identityTxId = new byte[32];
        byte[] ed25519PubKey = new byte[32];
        for (int i = 0; i < 32; i++) { identityTxId[i] = (byte)(i+1); ed25519PubKey[i] = (byte)(i+33); }

        byte[] messageBytes = new byte[64];
        System.arraycopy(identityTxId, 0, messageBytes, 0, 32);
        System.arraycopy(ed25519PubKey, 0, messageBytes, 32, 32);
        BigInteger messageHash = Rabin.hashBytesToScriptInt(Sha256Hash.hash(messageBytes));
        RabinSignature rabinSig = Rabin.sign(messageHash, rabinKeyPair.p(), rabinKeyPair.q());
        byte[] rabinSBytes = Rabin.bigIntToScriptNum(rabinSig.s());

        Transaction fundingTx = Transaction.fromHex(BOB_FUNDING_TX_HEX);

        // Issuance: fund from vout=1, commit witness funding txid (32 bytes, not outpoint)
        // createTokenIssuanceTxn calls getOutpoint() internally, so we pass the raw txid.
        // This test verifies that PP1 fails when witness funding is at vout=0.
        Transaction issuanceTx = tokenTool.createTokenIssuanceTxn(
                fundingTx, 1, bobSigner, bobPub, bobAddress,
                fundingTx.getTransactionIdBytes(),
                rabinPubKeyHash, "test".getBytes());

        System.out.println("=== VOUT=0 TEST ===");
        System.out.println("Issuance txid: " + issuanceTx.getTransactionId());

        // Witness: fund from vout=0 (the other output of fundingTx)
        Transaction witnessTx = tokenTool.createWitnessTxn(
                bobSigner, bobPub, fundingTx, 0, issuanceTx, new byte[0],
                bobPub, bobAddress.getHash(), TokenAction.ISSUANCE,
                rabinNBytes, rabinSBytes, (long) rabinSig.padding(),
                identityTxId, ed25519PubKey);

        System.out.println("Witness txid: " + witnessTx.getTransactionId());

        EnumSet<Script.VerifyFlag> flags = EnumSet.of(
                Script.VerifyFlag.SIGHASH_FORKID,
                Script.VerifyFlag.UTXO_AFTER_GENESIS);
        Interpreter interp = new Interpreter();

        for (int i = 0; i < witnessTx.getInputs().size(); i++) {
            var input = witnessTx.getInputs().get(i);
            String prevTxid = Utils.HEX.encode(input.getPrevTxnId());
            int prevVout = (int) input.getPrevTxnOutputIndex();

            Transaction parentTx = prevTxid.equals(issuanceTx.getTransactionId()) ? issuanceTx : fundingTx;
            var parentOutput = parentTx.getOutputs().get(prevVout);
            String parentLabel = parentTx == issuanceTx ? "ISSUANCE" : "FUNDING";

            System.out.println("\nINPUT[" + i + "] spends " + parentLabel + "[" + prevVout + "]:");
            System.out.println("  value=" + parentOutput.getAmount().longValue() + " sats");

            try {
                interp.correctlySpends(input.getScriptSig(), parentOutput.getScript(),
                        witnessTx, i, flags, Coin.valueOf(parentOutput.getAmount().longValue()));
                System.out.println("  RESULT: PASS");
            } catch (Exception e) {
                System.out.println("  RESULT: FAIL — " + e.getMessage());
            }
        }
    }

    /**
     * Trace PP1 execution with MINIMALDATA to find the exact opcode that triggers
     * "non-minimally encoded script number".
     */
    @Test
    public void traceMinimalDataFailure() throws Exception {
        TokenTool tokenTool = new TokenTool(NetworkAddressType.TEST_PKH);

        PrivateKey bobPriv = PrivateKey.fromWIF(BOB_WIF);
        PublicKey bobPub = bobPriv.getPublicKey();
        Address bobAddress = Address.fromKey(NetworkAddressType.TEST_PKH, bobPub);
        SigningCallback bobSigner = sighash -> bobPriv.sign(sighash);

        RabinKeyPair rabinKeyPair = Rabin.generateKeyPair(1024);
        byte[] rabinNBytes = Rabin.bigIntToScriptNum(rabinKeyPair.n());
        byte[] rabinPubKeyHash = Rabin.rabinPubKeyHash(rabinKeyPair.n());

        byte[] identityTxId = new byte[32];
        byte[] ed25519PubKey = new byte[32];
        for (int i = 0; i < 32; i++) { identityTxId[i] = (byte)(i+1); ed25519PubKey[i] = (byte)(i+33); }

        byte[] messageBytes = new byte[64];
        System.arraycopy(identityTxId, 0, messageBytes, 0, 32);
        System.arraycopy(ed25519PubKey, 0, messageBytes, 32, 32);
        BigInteger messageHash = Rabin.hashBytesToScriptInt(Sha256Hash.hash(messageBytes));
        RabinSignature rabinSig = Rabin.sign(messageHash, rabinKeyPair.p(), rabinKeyPair.q());
        byte[] rabinSBytes = Rabin.bigIntToScriptNum(rabinSig.s());

        Transaction fundingTx = Transaction.fromHex(BOB_FUNDING_TX_HEX);
        Transaction issuanceTx = tokenTool.createTokenIssuanceTxn(
                fundingTx, 1, bobSigner, bobPub, bobAddress,
                fundingTx.getTransactionIdBytes(), rabinPubKeyHash, "test".getBytes());

        Transaction witnessTx = tokenTool.createWitnessTxn(
                bobSigner, bobPub, fundingTx, 1, issuanceTx, new byte[0],
                bobPub, bobAddress.getHash(), TokenAction.ISSUANCE,
                rabinNBytes, rabinSBytes, (long) rabinSig.padding(),
                identityTxId, ed25519PubKey);

        // Trace PP1 (input[1]) execution with MINIMALDATA
        var input = witnessTx.getInputs().get(1);
        Script scriptSig = input.getScriptSig();
        Script scriptPubKey = issuanceTx.getOutputs().get(1).getScript();

        EnumSet<Script.VerifyFlag> flags = EnumSet.of(
                Script.VerifyFlag.SIGHASH_FORKID,
                Script.VerifyFlag.UTXO_AFTER_GENESIS,
                Script.VerifyFlag.MINIMALDATA);

        // Track the last N opcodes before failure
        final int WINDOW = 20;
        final String[][] recentOps = new String[WINDOW][1];
        final int[] opCounter = {0};

        ScriptTraceCallback tracer = (pc, opcode, opName, stack, altStack) -> {
            int idx = opCounter[0] % WINDOW;
            StringBuilder sb = new StringBuilder();
            sb.append(String.format("op#%d @%d 0x%02x %-12s stack=%d [", opCounter[0], pc, opcode, opName, stack.size()));
            int show = Math.min(stack.size(), 3);
            var it = stack.descendingIterator();
            for (int s = 0; s < show && it.hasNext(); s++) {
                byte[] item = it.next();
                if (s > 0) sb.append(" | ");
                if (item.length == 0) sb.append("(empty)");
                else if (item.length <= 40) sb.append(Utils.HEX.encode(item));
                else sb.append(item.length).append("B");
            }
            sb.append("]");
            recentOps[idx][0] = sb.toString();
            opCounter[0]++;
        };

        LinkedList<byte[]> stack = new LinkedList<>();

        System.out.println("=== Executing scriptSig ===");
        try {
            Interpreter.executeScript(witnessTx, 1, scriptSig, stack, Coin.valueOf(1), flags, null, tracer);
            System.out.println("scriptSig OK, stack size=" + stack.size());
        } catch (Exception e) {
            System.out.println("scriptSig FAILED: " + e.getMessage());
            printRecentOps(recentOps, opCounter[0], WINDOW);
            return;
        }

        System.out.println("\n=== Executing scriptPubKey (len=" + scriptPubKey.getProgram().length + ") ===");
        // Dump bytes around where we expect the failure (~position 346)
        byte[] spk = scriptPubKey.getProgram();
        System.out.println("  bytes @340-360: " + Utils.HEX.encode(java.util.Arrays.copyOfRange(spk, 340, Math.min(360, spk.length))));

        try {
            Interpreter.executeScript(witnessTx, 1, scriptPubKey, stack, Coin.valueOf(1), flags, null, tracer);
            System.out.println("scriptPubKey OK, stack size=" + stack.size());
        } catch (Exception e) {
            System.out.println("scriptPubKey FAILED at op#" + opCounter[0] + ": " + e.getMessage());
            printRecentOps(recentOps, opCounter[0], WINDOW);
        }
    }

    /**
     * Full lifecycle: issuance → witness → transfer.
     * Verifies every transfer input in the interpreter.
     */
    @Test
    public void transferVerification() throws Exception {
        TokenTool tokenTool = new TokenTool(NetworkAddressType.TEST_PKH);

        PrivateKey bobPriv = PrivateKey.fromWIF(BOB_WIF);
        PublicKey bobPub = bobPriv.getPublicKey();
        Address bobAddress = Address.fromKey(NetworkAddressType.TEST_PKH, bobPub);
        SigningCallback bobSigner = sighash -> bobPriv.sign(sighash);

        RabinKeyPair rabinKeyPair = Rabin.generateKeyPair(1024);
        byte[] rabinNBytes = Rabin.bigIntToScriptNum(rabinKeyPair.n());
        byte[] rabinPubKeyHash = Rabin.rabinPubKeyHash(rabinKeyPair.n());

        byte[] identityTxId = new byte[32];
        byte[] ed25519PubKey = new byte[32];
        for (int i = 0; i < 32; i++) { identityTxId[i] = (byte)(i+1); ed25519PubKey[i] = (byte)(i+33); }

        byte[] messageBytes = new byte[64];
        System.arraycopy(identityTxId, 0, messageBytes, 0, 32);
        System.arraycopy(ed25519PubKey, 0, messageBytes, 32, 32);
        BigInteger messageHash = Rabin.hashBytesToScriptInt(Sha256Hash.hash(messageBytes));
        RabinSignature rabinSig = Rabin.sign(messageHash, rabinKeyPair.p(), rabinKeyPair.q());
        byte[] rabinSBytes = Rabin.bigIntToScriptNum(rabinSig.s());

        Transaction fundingTx = Transaction.fromHex(BOB_FUNDING_TX_HEX);

        // --- Step 1: Issuance ---
        // Fund from vout=1, commit witness funding to fundingTx (vout=1 is the PP1 hardcode)
        Transaction issuanceTx = tokenTool.createTokenIssuanceTxn(
                fundingTx, 1, bobSigner, bobPub, bobAddress,
                fundingTx.getTransactionIdBytes(), rabinPubKeyHash,
                "test".getBytes());

        System.out.println("=== TRANSFER LIFECYCLE TEST ===");
        System.out.println("Issuance txid: " + issuanceTx.getTransactionId());

        // --- Step 2: Witness ---
        Transaction witnessTx = tokenTool.createWitnessTxn(
                bobSigner, bobPub, fundingTx, 1, issuanceTx, new byte[0],
                bobPub, bobAddress.getHash(), TokenAction.ISSUANCE,
                rabinNBytes, rabinSBytes, (long) rabinSig.padding(),
                identityTxId, ed25519PubKey);

        System.out.println("Witness txid: " + witnessTx.getTransactionId());

        // --- Step 3: Transfer ---
        // PP3 hardcodes funding at vout=1, so the transfer's funding UTXO must be at vout=1.
        // In a real flow, funding.prepare creates UTXOs at vout=1.
        // For this test, we reuse fundingTx:vout=1 (same as issuance/witness) since
        // we're verifying script correctness, not UTXO spending.
        int transferFundingVout = 1;
        Transaction transferTx = tokenTool.createTokenTransferTxn(
                witnessTx, issuanceTx,
                bobPub, bobAddress,
                fundingTx, transferFundingVout,
                bobSigner, bobPub,
                fundingTx.getTransactionIdBytes(),  // recipient witness funding
                issuanceTx.getTransactionIdBytes(),  // tokenId = issuance txid
                rabinPubKeyHash);

        System.out.println("Transfer txid: " + transferTx.getTransactionId());
        System.out.println("Transfer inputs: " + transferTx.getInputs().size());
        System.out.println("Transfer outputs: " + transferTx.getOutputs().size());

        // Verify each transfer input
        EnumSet<Script.VerifyFlag> consensusFlags = EnumSet.of(
                Script.VerifyFlag.SIGHASH_FORKID,
                Script.VerifyFlag.UTXO_AFTER_GENESIS);
        EnumSet<Script.VerifyFlag> policyFlags = EnumSet.of(
                Script.VerifyFlag.SIGHASH_FORKID,
                Script.VerifyFlag.UTXO_AFTER_GENESIS,
                Script.VerifyFlag.MINIMALDATA);
        Interpreter interp = new Interpreter();

        for (int i = 0; i < transferTx.getInputs().size(); i++) {
            var input = transferTx.getInputs().get(i);
            String prevTxid = Utils.HEX.encode(input.getPrevTxnId());
            int prevVout = (int) input.getPrevTxnOutputIndex();

            // Resolve parent transaction
            Transaction parentTx;
            String parentLabel;
            if (prevTxid.equals(issuanceTx.getTransactionId())) {
                parentTx = issuanceTx;
                parentLabel = "ISSUANCE";
            } else if (prevTxid.equals(witnessTx.getTransactionId())) {
                parentTx = witnessTx;
                parentLabel = "WITNESS";
            } else if (prevTxid.equals(fundingTx.getTransactionId())) {
                parentTx = fundingTx;
                parentLabel = "FUNDING";
            } else {
                System.out.println("INPUT[" + i + "]: UNKNOWN parent tx " + prevTxid);
                continue;
            }

            var parentOutput = parentTx.getOutputs().get(prevVout);
            System.out.println("\nINPUT[" + i + "] spends " + parentLabel + "[" + prevVout + "]:");
            System.out.println("  scriptSig len=" + input.getScriptSig().getProgram().length);
            System.out.println("  scriptPubKey len=" + parentOutput.getScript().getProgram().length);
            System.out.println("  value=" + parentOutput.getAmount().longValue() + " sats");

            try {
                interp.correctlySpends(input.getScriptSig(), parentOutput.getScript(),
                        transferTx, i, consensusFlags, Coin.valueOf(parentOutput.getAmount().longValue()));
                System.out.println("  CONSENSUS: PASS");
            } catch (Exception e) {
                System.out.println("  CONSENSUS: FAIL — " + e.getMessage());
            }
            try {
                interp.correctlySpends(input.getScriptSig(), parentOutput.getScript(),
                        transferTx, i, policyFlags, Coin.valueOf(parentOutput.getAmount().longValue()));
                System.out.println("  POLICY:    PASS");
            } catch (Exception e) {
                System.out.println("  POLICY:    FAIL — " + e.getMessage());
            }
        }
    }

    /**
     * Proves PP3 hardcodes vout=1 for the transfer funding outpoint.
     * Transfer funding at vout=0 causes PP3 hashPrevOuts mismatch.
     */
    @Test
    public void transferWithFundingAtVout0() throws Exception {
        TokenTool tokenTool = new TokenTool(NetworkAddressType.TEST_PKH);

        PrivateKey bobPriv = PrivateKey.fromWIF(BOB_WIF);
        PublicKey bobPub = bobPriv.getPublicKey();
        Address bobAddress = Address.fromKey(NetworkAddressType.TEST_PKH, bobPub);
        SigningCallback bobSigner = sighash -> bobPriv.sign(sighash);

        RabinKeyPair rabinKeyPair = Rabin.generateKeyPair(1024);
        byte[] rabinNBytes = Rabin.bigIntToScriptNum(rabinKeyPair.n());
        byte[] rabinPubKeyHash = Rabin.rabinPubKeyHash(rabinKeyPair.n());

        byte[] identityTxId = new byte[32];
        byte[] ed25519PubKey = new byte[32];
        for (int i = 0; i < 32; i++) { identityTxId[i] = (byte)(i+1); ed25519PubKey[i] = (byte)(i+33); }

        byte[] messageBytes = new byte[64];
        System.arraycopy(identityTxId, 0, messageBytes, 0, 32);
        System.arraycopy(ed25519PubKey, 0, messageBytes, 32, 32);
        BigInteger messageHash = Rabin.hashBytesToScriptInt(Sha256Hash.hash(messageBytes));
        RabinSignature rabinSig = Rabin.sign(messageHash, rabinKeyPair.p(), rabinKeyPair.q());
        byte[] rabinSBytes = Rabin.bigIntToScriptNum(rabinSig.s());

        Transaction fundingTx = Transaction.fromHex(BOB_FUNDING_TX_HEX);

        Transaction issuanceTx = tokenTool.createTokenIssuanceTxn(
                fundingTx, 1, bobSigner, bobPub, bobAddress,
                fundingTx.getTransactionIdBytes(), rabinPubKeyHash, "test".getBytes());

        Transaction witnessTx = tokenTool.createWitnessTxn(
                bobSigner, bobPub, fundingTx, 1, issuanceTx, new byte[0],
                bobPub, bobAddress.getHash(), TokenAction.ISSUANCE,
                rabinNBytes, rabinSBytes, (long) rabinSig.padding(),
                identityTxId, ed25519PubKey);

        // Transfer with funding at vout=0 — PP3 expects vout=1, so INPUT[2] should FAIL
        Transaction transferTx = tokenTool.createTokenTransferTxn(
                witnessTx, issuanceTx, bobPub, bobAddress,
                fundingTx, 0, bobSigner, bobPub,
                fundingTx.getTransactionIdBytes(),
                issuanceTx.getTransactionIdBytes(), rabinPubKeyHash);

        System.out.println("=== TRANSFER FUNDING VOUT=0 (should fail PP3) ===");

        EnumSet<Script.VerifyFlag> flags = EnumSet.of(
                Script.VerifyFlag.SIGHASH_FORKID,
                Script.VerifyFlag.UTXO_AFTER_GENESIS);
        Interpreter interp = new Interpreter();

        // Only check INPUT[2] (PP3)
        var input = transferTx.getInputs().get(2);
        var parentOutput = issuanceTx.getOutputs().get(3);
        try {
            interp.correctlySpends(input.getScriptSig(), parentOutput.getScript(),
                    transferTx, 2, flags, Coin.valueOf(1));
            System.out.println("PP3: PASS (unexpected!)");
            throw new AssertionError("PP3 should fail with funding at vout=0");
        } catch (org.twostack.bitcoin4j.script.ScriptException e) {
            System.out.println("PP3: FAIL as expected — " + e.getMessage());
            assert e.getMessage().contains("non-equal data") : "Expected hash mismatch, got: " + e.getMessage();
        }
    }

    private void printRecentOps(String[][] recentOps, int total, int window) {
        System.out.println("Last " + Math.min(total, window) + " opcodes before failure:");
        int start = Math.max(0, total - window);
        for (int j = start; j < total; j++) {
            int idx = j % window;
            if (recentOps[idx][0] != null) {
                System.out.println("  " + recentOps[idx][0]);
            }
        }
    }
}
