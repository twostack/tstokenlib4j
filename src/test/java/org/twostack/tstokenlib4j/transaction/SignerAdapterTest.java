package org.twostack.tstokenlib4j.transaction;

import org.junit.Test;
import org.twostack.bitcoin4j.*;
import org.twostack.bitcoin4j.params.NetworkAddressType;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptBuilder;
import org.twostack.bitcoin4j.transaction.*;
import org.twostack.tstokenlib4j.lock.ModP2PKHLockBuilder;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

/**
 * Verifies that InputIndexAwareTransactionSigner passes the correct
 * locking script bytes through the signing callback for each input.
 */
public class SignerAdapterTest {

    private static final String FUNDING_TX_HEX =
            "0200000001cf5ae107ead0a5117ea2124aacb61d0d700de05a937ed3e48c9245bfab19dd8c000000004847304402206edac55dd4f791a611e05a6d946862ca45d914d0cdf391bfd982399c3d84ea4602205a196505d536b3646834051793acd5d9e820249979c94d0a4252298d0ffe9a7041feffffff0200196bee000000001976a914da217dfa3513d4224802556228d07b278af36b0388ac00ca9a3b000000001976a914650c4adb156f19e36a755c820d892cda108299c488ac65000000";

    @Test
    public void signingCallback_receivesScriptPubKeyForEachInput() throws Exception {
        PrivateKey key = PrivateKey.fromWIF("cStLVGeWx7fVYKKDXYWVeEbEcPZEC4TD73DjQpHCks2Y8EAjVDSS");
        PublicKey pub = key.getPublicKey();
        Transaction fundingTx = Transaction.fromHex(FUNDING_TX_HEX);

        // Track which scriptPubKey bytes each input receives
        List<byte[]> receivedScripts = new ArrayList<>();

        SigningCallback callback = new SigningCallback() {
            @Override
            public byte[] sign(byte[] sighash) {
                return key.sign(sighash);
            }

            @Override
            public byte[] sign(byte[] sighash, int inputIndex, byte[] scriptPubKey) {
                receivedScripts.add(scriptPubKey);
                return key.sign(sighash);
            }
        };

        int sigHashAll = SigHashType.FORKID.value | SigHashType.ALL.value;
        TransactionSigner signer = SignerAdapter.fromCallback(callback, pub, sigHashAll);

        // Build a TX with 2 inputs spending different script types
        byte[] ownerPKH = pub.getPubKeyHash();
        Script modP2PKH = new ModP2PKHLockBuilder(ownerPKH).getLockingScript();

        // Create a second "parent" TX with a ModP2PKH output
        Transaction parentTx = new Transaction();
        parentTx.addInput(new TransactionInput(new byte[32], 0xFFFFFFFFL, 0xFFFFFFFFL,
                new DefaultUnlockBuilder()));
        parentTx.addOutput(new TransactionOutput(BigInteger.valueOf(10000), modP2PKH));

        P2PKHUnlockBuilder p2pkhUnlocker = new P2PKHUnlockBuilder(pub);
        DefaultUnlockBuilder modUnlocker = new DefaultUnlockBuilder();

        Transaction tx = new TransactionBuilder()
                .spendFromTransaction(signer, fundingTx, 1, TransactionInput.MAX_SEQ_NUMBER, p2pkhUnlocker)
                .spendFromTransaction(signer, parentTx, 0, TransactionInput.MAX_SEQ_NUMBER, modUnlocker)
                .spendTo(new org.twostack.bitcoin4j.transaction.P2PKHLockBuilder(
                        Address.fromKey(NetworkAddressType.TEST_PKH, pub)), BigInteger.valueOf(5000))
                .build(false);

        // Both inputs should have received their respective scriptPubKey bytes
        assertEquals(2, receivedScripts.size());

        // Input 0: P2PKH script from fundingTx output 1
        byte[] expectedP2PKH = fundingTx.getOutputs().get(1).getScript().getProgram();
        assertArrayEquals(expectedP2PKH, receivedScripts.get(0));

        // Input 1: ModP2PKH script from parentTx output 0
        byte[] expectedModP2PKH = modP2PKH.getProgram();
        assertArrayEquals(expectedModP2PKH, receivedScripts.get(1));
    }
}
