package org.twostack.tstokenlib4j.lock;

import org.junit.Test;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.Script;
import static org.junit.Assert.*;

public class PP1FtLockBuilderTest {

    private static final byte[] DUMMY_RABIN_PKH = new byte[20];
    static { java.util.Arrays.fill(DUMMY_RABIN_PKH, (byte) 0xCC); }

    @Test
    public void testScriptStartsWithParams() {
        byte[] ownerPKH = new byte[20];
        byte[] tokenId = new byte[32];
        java.util.Arrays.fill(ownerPKH, (byte) 0xAA);
        java.util.Arrays.fill(tokenId, (byte) 0xBB);
        long amount = 1000;

        PP1FtLockBuilder builder = new PP1FtLockBuilder(ownerPKH, tokenId, DUMMY_RABIN_PKH, amount);
        Script script = builder.getLockingScript();
        String hex = Utils.HEX.encode(script.getProgram());

        // Template starts with: 14{{ownerPKH}}20{{tokenId}}14{{rabinPKH}}08{{amount}}...
        // amount=1000 LE 8 bytes: e803000000000000
        String expected = "14" + "aa".repeat(20) + "20" + "bb".repeat(32) + "14" + "cc".repeat(20) + "08" + "e803000000000000";
        assertTrue("Script should start with parameter bytes", hex.startsWith(expected));
    }

    @Test
    public void testScriptIsNonTrivial() {
        PP1FtLockBuilder builder = new PP1FtLockBuilder(new byte[20], new byte[32], new byte[20], 100);
        Script script = builder.getLockingScript();
        assertTrue("PP1_FT script should be large", script.getProgram().length > 5000);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNegativeAmountThrows() {
        new PP1FtLockBuilder(new byte[20], new byte[32], new byte[20], -1);
    }
}
