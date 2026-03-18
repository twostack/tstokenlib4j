package org.twostack.tstokenlib4j.transaction;

import org.junit.Test;
import org.twostack.bitcoin4j.*;
import org.twostack.bitcoin4j.params.NetworkAddressType;
import org.twostack.bitcoin4j.script.Interpreter;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.transaction.Transaction;
import org.twostack.tstokenlib4j.crypto.Rabin;
import org.twostack.tstokenlib4j.crypto.RabinKeyPair;
import org.twostack.tstokenlib4j.crypto.RabinSignature;
import org.twostack.tstokenlib4j.unlock.TokenAction;

import java.math.BigInteger;
import java.util.EnumSet;

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
}
