package org.twostack.tstokenlib4j.parser;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Shared helpers for PP1 script template matching and field extraction.
 *
 * <p>All PP1 scripts share a common prefix:
 * <pre>
 *   byte[0]      = 0x14 (push 20 bytes)
 *   byte[1..20]  = ownerPKH
 *   byte[21]     = 0x20 (push 32 bytes)
 *   byte[22..53] = tokenId
 *   byte[54+]    = archetype-specific fields
 * </pre>
 */
class PP1TemplateBase {

    static final int PREFIX_LEN = 54;
    static final byte PUSH_20 = 0x14;
    static final byte PUSH_32 = 0x20;
    static final byte PUSH_8 = 0x08;
    static final byte PUSH_4 = 0x04;
    static final byte PUSH_1 = 0x01;

    static boolean hasValidPrefix(byte[] program, int minLength) {
        if (program == null || program.length < minLength) {
            return false;
        }
        return program[0] == PUSH_20 && program[21] == PUSH_32;
    }

    static byte[] extractBytes(byte[] program, int offset, int length) {
        byte[] result = new byte[length];
        System.arraycopy(program, offset, result, 0, length);
        return result;
    }

    static byte[] extractOwnerPKH(byte[] program) {
        return extractBytes(program, 1, 20);
    }

    static byte[] extractTokenId(byte[] program) {
        return extractBytes(program, 22, 32);
    }

    static int readLeUint32(byte[] program, int offset) {
        return ByteBuffer.wrap(program, offset, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    static long readLeUint56(byte[] program, int offset) {
        long value = 0;
        for (int i = 0; i < 7; i++) {
            value |= ((long) (program[offset + i] & 0xFF)) << (i * 8);
        }
        value |= ((long) (program[offset + 7] & 0x7F)) << 56;
        return value;
    }
}
