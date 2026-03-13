package org.twostack.tstokenlib4j.unlock;

import org.junit.Test;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptChunk;
import static org.junit.Assert.*;

import java.util.List;

public class PP2UnlockBuilderTest {

    @Test
    public void testNormalModeProducesScript() {
        byte[] outpointTxId = new byte[32];
        java.util.Arrays.fill(outpointTxId, (byte) 0xAA);

        PP2UnlockBuilder builder = PP2UnlockBuilder.forNormal(outpointTxId);
        Script script = builder.getUnlockingScript();
        List<ScriptChunk> chunks = script.getChunks();

        // Should be: pushdata(outpointTxId), OP_0
        assertEquals(2, chunks.size());
        assertArrayEquals(outpointTxId, chunks.get(0).data);
    }

    @Test
    public void testBurnModeEmptyBeforeSigning() {
        PP2UnlockBuilder builder = PP2UnlockBuilder.forBurn(
            org.twostack.bitcoin4j.PublicKey.fromHex("02ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382")
        );
        Script script = builder.getUnlockingScript();
        assertEquals(0, script.getProgram().length);
    }
}
