package org.twostack.tstokenlib4j.encoding;

import org.junit.Test;
import org.twostack.bitcoin4j.Utils;
import static org.junit.Assert.*;

public class PushdataEncoderTest {

    @Test
    public void testTwentyBytes() {
        byte[] data = new byte[20];
        for (int i = 0; i < 20; i++) data[i] = (byte) 0xAA;
        String result = PushdataEncoder.encode(data);
        // 20 bytes: pushdata prefix = 0x14 (20), then 20 bytes of 0xAA
        assertEquals("14" + "aa".repeat(20), result);
    }

    @Test
    public void testThirtySixBytes() {
        byte[] data = new byte[36];
        for (int i = 0; i < 36; i++) data[i] = (byte) 0xBB;
        String result = PushdataEncoder.encode(data);
        // 36 bytes: pushdata prefix = 0x24 (36), then 36 bytes of 0xBB
        assertEquals("24" + "bb".repeat(36), result);
    }
}
