package org.twostack.tstokenlib4j.lock;

import org.junit.Test;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.Script;
import static org.junit.Assert.*;

public class PP1NftLockBuilderTest {

    @Test
    public void testScriptStartsWithParams() {
        byte[] ownerPKH = new byte[20];
        byte[] tokenId = new byte[32];
        byte[] rabinPKH = new byte[20];
        java.util.Arrays.fill(ownerPKH, (byte) 0xAA);
        java.util.Arrays.fill(tokenId, (byte) 0xBB);
        java.util.Arrays.fill(rabinPKH, (byte) 0xCC);

        PP1NftLockBuilder builder = new PP1NftLockBuilder(ownerPKH, tokenId, rabinPKH);
        Script script = builder.getLockingScript();
        String hex = Utils.HEX.encode(script.getProgram());

        // Template starts with: 14{{ownerPKH}}20{{tokenId}}14{{rabinPubKeyHash}}...
        // So the script hex should start with: 14 + 20xAA + 20 + 32xBB + 14 + 20xCC
        String expected = "14" + "aa".repeat(20) + "20" + "bb".repeat(32) + "14" + "cc".repeat(20);
        assertTrue("Script should start with parameter bytes", hex.startsWith(expected));
    }

    @Test
    public void testScriptIsNonTrivial() {
        PP1NftLockBuilder builder = new PP1NftLockBuilder(new byte[20], new byte[32], new byte[20]);
        Script script = builder.getLockingScript();
        // PP1 NFT scripts are large (~5KB)
        assertTrue("Script should be large", script.getProgram().length > 1000);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidTokenIdSize() {
        new PP1NftLockBuilder(new byte[20], new byte[31], new byte[20]);
    }
}
