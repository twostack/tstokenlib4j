package org.twostack.tstokenlib4j.encoding;

import org.junit.Test;
import static org.junit.Assert.*;

public class ScriptNumberEncoderTest {

    @Test
    public void testZero() {
        assertEquals("00", ScriptNumberEncoder.encode(0));
    }

    @Test
    public void testSmallNumbers() {
        assertEquals("51", ScriptNumberEncoder.encode(1));  // OP_1
        assertEquals("60", ScriptNumberEncoder.encode(16)); // OP_16
    }

    @Test
    public void testSeventeen() {
        // 17 needs pushdata: 01 11
        assertEquals("0111", ScriptNumberEncoder.encode(17));
    }

    @Test
    public void testNegativeOne() {
        assertEquals("4f", ScriptNumberEncoder.encode(-1)); // OP_1NEGATE
    }

    @Test
    public void testLargerNumber() {
        // 1000 = 0x03E8. Script number LE: e8 03, pushdata prefix: 02
        assertEquals("02e803", ScriptNumberEncoder.encode(1000));
    }
}
