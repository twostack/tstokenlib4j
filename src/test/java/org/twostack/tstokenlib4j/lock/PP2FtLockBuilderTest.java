package org.twostack.tstokenlib4j.lock;

import org.junit.Test;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.Script;
import static org.junit.Assert.*;

public class PP2FtLockBuilderTest {

    @Test
    public void testScriptIsNonTrivial() {
        byte[] outpoint = new byte[36];
        byte[] witnessChangePKH = new byte[20];
        byte[] ownerPKH = new byte[20];

        PP2FtLockBuilder builder = new PP2FtLockBuilder(outpoint, witnessChangePKH, 1000, ownerPKH, 1, 2);
        Script script = builder.getLockingScript();
        assertTrue("PP2_FT script should be non-trivial", script.getProgram().length > 500);
    }

    @Test
    public void testDifferentIndicesProduceDifferentScripts() {
        byte[] outpoint = new byte[36];
        byte[] witnessChangePKH = new byte[20];
        byte[] ownerPKH = new byte[20];

        PP2FtLockBuilder b1 = new PP2FtLockBuilder(outpoint, witnessChangePKH, 1000, ownerPKH, 1, 2);
        PP2FtLockBuilder b2 = new PP2FtLockBuilder(outpoint, witnessChangePKH, 1000, ownerPKH, 3, 4);

        assertNotEquals(
            Utils.HEX.encode(b1.getLockingScript().getProgram()),
            Utils.HEX.encode(b2.getLockingScript().getProgram())
        );
    }
}
