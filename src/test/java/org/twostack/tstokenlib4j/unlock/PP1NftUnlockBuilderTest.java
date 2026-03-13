package org.twostack.tstokenlib4j.unlock;

import org.junit.Test;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptChunk;
import static org.junit.Assert.*;

import java.util.List;

public class PP1NftUnlockBuilderTest {

    @Test
    public void testIssuanceProducesScript() {
        byte[] preImage = new byte[]{0x01, 0x02};
        byte[] witnessFundingTxId = new byte[32];
        byte[] witnessPadding = new byte[]{0x00};
        byte[] rabinN = new byte[]{0x03};
        byte[] rabinS = new byte[]{0x04};
        byte[] identityTxId = new byte[32];
        byte[] ed25519PubKey = new byte[32];

        PP1NftUnlockBuilder builder = PP1NftUnlockBuilder.forIssuance(
            preImage, witnessFundingTxId, witnessPadding,
            rabinN, rabinS, 0,
            identityTxId, ed25519PubKey
        );
        Script script = builder.getUnlockingScript();
        List<ScriptChunk> chunks = script.getChunks();

        // 8 data pushes + OP_0 selector = 9 chunks
        assertEquals(9, chunks.size());
    }

    @Test
    public void testTransferEmptyBeforeSigning() {
        PP1NftUnlockBuilder builder = PP1NftUnlockBuilder.forTransfer(
            new byte[]{0x01}, new byte[]{0x02},
            org.twostack.bitcoin4j.PublicKey.fromHex("02ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382"),
            new byte[20], 1000,
            new byte[]{0x03}, new byte[]{0x04}, new byte[]{0x05}
        );
        Script script = builder.getUnlockingScript();
        assertEquals(0, script.getProgram().length);
    }

    @Test
    public void testBurnEmptyBeforeSigning() {
        PP1NftUnlockBuilder builder = PP1NftUnlockBuilder.forBurn(
            org.twostack.bitcoin4j.PublicKey.fromHex("02ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382")
        );
        Script script = builder.getUnlockingScript();
        assertEquals(0, script.getProgram().length);
    }
}
