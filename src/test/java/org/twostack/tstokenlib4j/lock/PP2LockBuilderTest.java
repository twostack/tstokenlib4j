package org.twostack.tstokenlib4j.lock;

import org.junit.Test;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.Script;
import static org.junit.Assert.*;

public class PP2LockBuilderTest {

    @Test
    public void testScriptIsNonTrivial() {
        byte[] outpoint = new byte[36];
        byte[] witnessChangePKH = new byte[20];
        byte[] ownerPKH = new byte[20];

        PP2LockBuilder builder = new PP2LockBuilder(outpoint, witnessChangePKH, 1000, ownerPKH);
        Script script = builder.getLockingScript();
        assertTrue("PP2 script should be non-trivial", script.getProgram().length > 500);
    }

    @Test
    public void testDifferentAmountsProduceDifferentScripts() {
        byte[] outpoint = new byte[36];
        byte[] witnessChangePKH = new byte[20];
        byte[] ownerPKH = new byte[20];

        PP2LockBuilder b1 = new PP2LockBuilder(outpoint, witnessChangePKH, 1000, ownerPKH);
        PP2LockBuilder b2 = new PP2LockBuilder(outpoint, witnessChangePKH, 2000, ownerPKH);

        assertNotEquals(
            Utils.HEX.encode(b1.getLockingScript().getProgram()),
            Utils.HEX.encode(b2.getLockingScript().getProgram())
        );
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidOutpointSize() {
        new PP2LockBuilder(new byte[35], new byte[20], 0, new byte[20]);
    }
}
