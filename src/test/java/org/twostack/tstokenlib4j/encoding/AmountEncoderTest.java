package org.twostack.tstokenlib4j.encoding;

import org.junit.Test;
import org.twostack.bitcoin4j.Utils;
import static org.junit.Assert.*;

public class AmountEncoderTest {

    @Test
    public void testZeroAmount() {
        byte[] result = AmountEncoder.encodeLeUint56(0);
        assertEquals(8, result.length);
        for (byte b : result) assertEquals(0, b);
    }

    @Test
    public void testSmallAmount() {
        byte[] result = AmountEncoder.encodeLeUint56(1000);
        assertEquals(8, result.length);
        // 1000 = 0x3E8, LE: e8 03 00 00 00 00 00 00
        assertEquals((byte) 0xe8, result[0]);
        assertEquals((byte) 0x03, result[1]);
        for (int i = 2; i < 8; i++) assertEquals(0, result[i]);
    }

    @Test
    public void testLargeAmount() {
        // 100_000_000 (1 BSV in satoshis) = 0x5F5E100
        byte[] result = AmountEncoder.encodeLeUint56(100_000_000L);
        assertEquals(8, result.length);
        assertEquals("00e1f50500000000", Utils.HEX.encode(result));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNegativeAmountThrows() {
        AmountEncoder.encodeLeUint56(-1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testTooLargeAmountThrows() {
        AmountEncoder.encodeLeUint56(1L << 55);
    }
}
