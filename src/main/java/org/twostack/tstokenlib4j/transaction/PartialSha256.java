package org.twostack.tstokenlib4j.transaction;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * A block-at-a-time SHA256 implementation used for partial hash proofs.
 *
 * <p>Unlike a standard SHA256 that processes an entire message, this class
 * exposes {@link #hashOneBlock} to hash individual 512-bit blocks with a caller-supplied
 * intermediate hash vector, enabling partial/resumable SHA256 computation.
 */
public final class PartialSha256 {

    /** SHA256 processes data in 64-byte (512-bit) blocks. */
    public static final int BLOCK_BYTES = 64;

    /** The standard SHA256 initial hash vector (H0..H7). */
    public static final int[] STD_INIT_VECTOR = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    private static final int[] K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    private PartialSha256() {}

    /**
     * Pads a message according to SHA256 specifications (append 1-bit, zero-pad,
     * append 64-bit length) and returns the result as an array of big-endian 32-bit words.
     *
     * @param message the message bytes to pad
     * @return the padded message as int[] (big-endian words)
     */
    public static int[] getPaddedPreImage(byte[] message) {
        int finalBlockLength = message.length % BLOCK_BYTES;
        int blockCount = message.length / BLOCK_BYTES + (finalBlockLength + 1 + 8 > BLOCK_BYTES ? 2 : 1);

        int[] result = new int[blockCount * (BLOCK_BYTES / 4)];

        // Copy as much of the message as possible (full 4-byte words)
        ByteBuffer buf = ByteBuffer.wrap(message);
        buf.order(ByteOrder.BIG_ENDIAN);
        int i = 0;
        int n = message.length / 4;
        while (i < n) {
            result[i] = buf.getInt(i * 4);
            i++;
        }

        // Copy the remaining bytes (less than 4) and append 1 bit
        byte[] remainder = new byte[4];
        for (int j = 0; j < message.length % 4; j++) {
            remainder[j] = message[(message.length / 4) * 4 + j];
        }
        remainder[message.length % 4] = (byte) 0x80;
        result[i] = ByteBuffer.wrap(remainder).order(ByteOrder.BIG_ENDIAN).getInt(0);

        // Append 64-bit length (in bits)
        long bitLength = (long) message.length * 8;
        result[result.length - 2] = (int) (bitLength >>> 32);
        result[result.length - 1] = (int) bitLength;

        return result;
    }

    /**
     * Hashes a single 512-bit (16-word) SHA256 block using the given input vector
     * as the initial hash state.
     *
     * @param oneChunk    exactly 16 int words (one SHA256 block)
     * @param inputVector 8-word hash state from the previous block (or {@link #STD_INIT_VECTOR})
     * @return the resulting 32-byte intermediate hash
     */
    public static byte[] hashOneBlock(int[] oneChunk, int[] inputVector) {
        int[] W = new int[64];
        int[] H = new int[8];
        int[] TEMP = new int[8];

        System.arraycopy(inputVector, 0, H, 0, inputVector.length);

        int wordCount = oneChunk.length / 16;
        if (wordCount != 1) {
            throw new IllegalArgumentException("Expected exactly one block (16 words)");
        }

        // Initialize W from the block's words
        System.arraycopy(oneChunk, 0, W, 0, 16);
        for (int t = 16; t < 64; t++) {
            W[t] = smallSig1(W[t - 2]) + W[t - 7] + smallSig0(W[t - 15]) + W[t - 16];
        }

        System.arraycopy(H, 0, TEMP, 0, H.length);

        for (int t = 0; t < 64; t++) {
            int t1 = TEMP[7] + bigSig1(TEMP[4]) + ch(TEMP[4], TEMP[5], TEMP[6]) + K[t] + W[t];
            int t2 = bigSig0(TEMP[0]) + maj(TEMP[0], TEMP[1], TEMP[2]);
            System.arraycopy(TEMP, 0, TEMP, 1, TEMP.length - 1);
            TEMP[4] += t1;
            TEMP[0] = t1 + t2;
        }

        for (int t = 0; t < H.length; t++) {
            H[t] += TEMP[t];
        }

        return int32ArrayToBytes(H);
    }

    /**
     * Converts an 8-element int array (hash vector) to a 32-byte big-endian byte array.
     */
    public static byte[] int32ArrayToBytes(int[] vector) {
        ByteBuffer buf = ByteBuffer.allocate(vector.length * 4);
        buf.order(ByteOrder.BIG_ENDIAN);
        for (int v : vector) {
            buf.putInt(v);
        }
        return buf.array();
    }

    /**
     * Converts a byte array to an int array by reading big-endian 32-bit words.
     *
     * @param bytes must have length that is a multiple of 4
     * @return the int array
     */
    public static int[] bytesToInt32Array(byte[] bytes) {
        if (bytes.length % 4 != 0) {
            throw new IllegalArgumentException("Byte array length must be a multiple of 4");
        }
        ByteBuffer buf = ByteBuffer.wrap(bytes);
        buf.order(ByteOrder.BIG_ENDIAN);
        int[] result = new int[bytes.length / 4];
        for (int i = 0; i < result.length; i++) {
            result[i] = buf.getInt(i * 4);
        }
        return result;
    }

    // SHA256 round functions

    private static int rotateRight(int value, int distance) {
        return Integer.rotateRight(value, distance);
    }

    private static int smallSig0(int x) {
        return rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >>> 3);
    }

    private static int smallSig1(int x) {
        return rotateRight(x, 17) ^ rotateRight(x, 19) ^ (x >>> 10);
    }

    private static int ch(int x, int y, int z) {
        return (x & y) | (~x & z);
    }

    private static int maj(int x, int y, int z) {
        return (x & y) | (x & z) | (y & z);
    }

    private static int bigSig0(int x) {
        return rotateRight(x, 2) ^ rotateRight(x, 13) ^ rotateRight(x, 22);
    }

    private static int bigSig1(int x) {
        return rotateRight(x, 6) ^ rotateRight(x, 11) ^ rotateRight(x, 25);
    }
}
