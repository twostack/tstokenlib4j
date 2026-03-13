package org.twostack.tstokenlib4j.lock;

import org.junit.Test;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.Script;
import static org.junit.Assert.*;

public class ModP2PKHLockBuilderTest {

    @Test
    public void testModP2PKHScript() {
        byte[] ownerPKH = Utils.HEX.decode("650c4adb156f19e36a755c820d892cda108299c4");
        ModP2PKHLockBuilder builder = new ModP2PKHLockBuilder(ownerPKH);
        Script script = builder.getLockingScript();
        String hex = Utils.HEX.encode(script.getProgram());
        // Expected: OP_SWAP(7c) OP_DUP(76) OP_HASH160(a9) PUSH20(14) <PKH> OP_EQUALVERIFY(88) OP_CHECKSIG(ac)
        assertEquals("7c76a914650c4adb156f19e36a755c820d892cda108299c488ac", hex);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidSize() {
        new ModP2PKHLockBuilder(new byte[19]);
    }
}
