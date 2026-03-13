package org.twostack.tstokenlib4j.unlock;

import org.junit.Test;
import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptChunk;
import org.twostack.bitcoin4j.transaction.TransactionSignature;
import org.twostack.bitcoin4j.exception.SignatureDecodeException;
import static org.junit.Assert.*;

import java.util.List;

public class ModP2PKHUnlockBuilderTest {

    @Test
    public void testEmptyScriptBeforeSigning() {
        PublicKey pubKey = PublicKey.fromHex("02ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382");
        ModP2PKHUnlockBuilder builder = new ModP2PKHUnlockBuilder(pubKey);
        Script script = builder.getUnlockingScript();
        assertEquals(0, script.getProgram().length);
    }

    @Test
    public void testPubKeyBeforeSignature() throws SignatureDecodeException {
        PublicKey pubKey = PublicKey.fromHex("02ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382");
        ModP2PKHUnlockBuilder builder = new ModP2PKHUnlockBuilder(pubKey);

        // Use a dummy DER signature (valid format) with SIGHASH_ALL|FORKID
        String dummySigHex = "3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802207c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e41";
        TransactionSignature sig = TransactionSignature.fromTxFormat(dummySigHex);
        builder.addSignature(sig);

        Script script = builder.getUnlockingScript();
        List<ScriptChunk> chunks = script.getChunks();

        // ModP2PKH pushes pubkey first, then signature (reversed from P2PKH)
        assertEquals(2, chunks.size());
        assertArrayEquals(pubKey.getPubKeyBytes(), chunks.get(0).data);
    }
}
