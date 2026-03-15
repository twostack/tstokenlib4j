package org.twostack.tstokenlib4j.encoding;

/**
 * Encodes fungible token amounts into the 8-byte little-endian format required by
 * PP1 fungible token locking scripts.
 *
 * <p>Used by {@link org.twostack.tstokenlib4j.lock.PP1FtLockBuilder} and
 * {@link org.twostack.tstokenlib4j.lock.PP1RftLockBuilder} for the {@code {{amount}}}
 * template placeholder.
 *
 * @see <a href="https://github.com/twostack/tsl1">TSL1 Specification</a>
 */
public class AmountEncoder {

    /**
     * Encodes a fungible token amount as an 8-byte little-endian value
     * with bit 63 clear (maximum value 2^55 - 1).
     *
     * Layout: bytes[0..6] = 7 LE value bytes, bytes[7] = (value &gt;&gt; 56) &amp; 0x7F
     */
    public static byte[] encodeLeUint56(long value) {
        if (value < 0) {
            throw new IllegalArgumentException("Amount must be non-negative, got: " + value);
        }
        if (value >= (1L << 55)) {
            throw new IllegalArgumentException("Amount must be less than 2^55, got: " + value);
        }

        byte[] result = new byte[8];
        for (int i = 0; i < 7; i++) {
            result[i] = (byte) ((value >> (i * 8)) & 0xFF);
        }
        result[7] = (byte) ((value >> 56) & 0x7F);
        return result;
    }
}
