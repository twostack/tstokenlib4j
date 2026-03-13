package org.twostack.tstokenlib4j.lock;

import org.junit.Test;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.Script;
import static org.junit.Assert.*;

public class PP1FtLockBuilderTest {

    @Test
    public void testScriptStartsWithParams() {
        byte[] ownerPKH = new byte[20];
        byte[] tokenId = new byte[32];
        java.util.Arrays.fill(ownerPKH, (byte) 0xAA);
        java.util.Arrays.fill(tokenId, (byte) 0xBB);
        long amount = 1000;

        PP1FtLockBuilder builder = new PP1FtLockBuilder(ownerPKH, tokenId, amount);
        Script script = builder.getLockingScript();
        String hex = Utils.HEX.encode(script.getProgram());

        // Template starts with: 14{{ownerPKH}}20{{tokenId}}08{{amount}}...
        // amount=1000 LE 8 bytes: e803000000000000
        String expected = "14" + "aa".repeat(20) + "20" + "bb".repeat(32) + "08" + "e803000000000000";
        assertTrue("Script should start with parameter bytes", hex.startsWith(expected));
    }

    @Test
    public void testScriptIsNonTrivial() {
        PP1FtLockBuilder builder = new PP1FtLockBuilder(new byte[20], new byte[32], 100);
        Script script = builder.getLockingScript();
        assertTrue("PP1_FT script should be large", script.getProgram().length > 5000);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNegativeAmountThrows() {
        new PP1FtLockBuilder(new byte[20], new byte[32], -1);
    }
}
