package org.twostack.tstokenlib4j.unlock;

import org.junit.Test;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptChunk;
import static org.junit.Assert.*;

import java.util.List;

public class PP1FtUnlockBuilderTest {

    @Test
    public void testMintProducesScript() {
        byte[] preImage = new byte[]{0x01, 0x02};
        byte[] witnessFundingTxId = new byte[32];
        byte[] witnessPadding = new byte[]{0x00};

        PP1FtUnlockBuilder builder = PP1FtUnlockBuilder.forMint(preImage, witnessFundingTxId, witnessPadding);
        Script script = builder.getUnlockingScript();
        List<ScriptChunk> chunks = script.getChunks();

        // 3 data pushes + OP_0 selector = 4 chunks
        assertEquals(4, chunks.size());
    }

    @Test
    public void testTransferEmptyBeforeSigning() {
        PP1FtUnlockBuilder builder = PP1FtUnlockBuilder.forTransfer(
            new byte[]{0x01}, new byte[]{0x02},
            org.twostack.bitcoin4j.PublicKey.fromHex("02ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382"),
            new byte[20], 1000,
            new byte[]{0x03}, new byte[]{0x04}, new byte[]{0x05},
            5, 1
        );
        Script script = builder.getUnlockingScript();
        assertEquals(0, script.getProgram().length);
    }

    @Test
    public void testBurnEmptyBeforeSigning() {
        PP1FtUnlockBuilder builder = PP1FtUnlockBuilder.forBurn(
            org.twostack.bitcoin4j.PublicKey.fromHex("02ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382")
        );
        Script script = builder.getUnlockingScript();
        assertEquals(0, script.getProgram().length);
    }
}
