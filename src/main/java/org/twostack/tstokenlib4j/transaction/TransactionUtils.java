package org.twostack.tstokenlib4j.transaction;

import org.twostack.bitcoin4j.transaction.Transaction;
import org.twostack.bitcoin4j.transaction.TransactionInput;
import org.twostack.bitcoin4j.transaction.TransactionOutput;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Utility methods for TSToken transaction manipulation.
 *
 * <p>Provides helpers for SHA256 block-alignment padding, partial hash
 * computation, and extracting the left-hand side (inputs) of a transaction.
 */
public final class TransactionUtils {

    /** SHA256 processes data in 64-byte (512-bit) blocks. */
    private static final int SHA256_BLOCK_SIZE = 64;

    /** Transaction locktime field is always 4 bytes. */
    private static final int LOCKTIME_SIZE = 4;

    /**
     * Returns the combined serialized size of the last input and first output of the transaction.
     */
    public int getInOutSize(Transaction tx) throws IOException {
        byte[] lastInput = tx.getInputs().get(2).serialize();
        byte[] firstOutput = tx.getOutputs().get(0).serialize();
        return lastInput.length + 1 + firstOutput.length;
    }

    /**
     * Calculates padding bytes needed to align the witness transaction's last input
     * to a SHA256 64-byte block boundary.
     *
     * <p>This alignment enables the partial SHA256 witness proof mechanism.
     *
     * @param witnessTx the witness transaction to calculate padding for
     * @return the padding bytes (zero-filled)
     */
    public byte[] calculatePaddingBytes(Transaction witnessTx) throws IOException {
        byte[] witnessBytes = witnessTx.serialize();
        int originalSize = witnessBytes.length;

        int inOutSize = getInOutSize(witnessTx);

        // Pad so that the start of the last input falls on a 64-byte (SHA256 block) boundary
        int lastInputStart = originalSize - (inOutSize + LOCKTIME_SIZE);

        // Calculate bytes needed to reach the next 64-byte boundary.
        // When already on a boundary (remainder=0), we add a full block (64 bytes)
        // to ensure non-empty padding (required by PP1/PP1_FT contracts).
        int remainder = lastInputStart % SHA256_BLOCK_SIZE;
        int lastBlockPadding = remainder == 0 ? SHA256_BLOCK_SIZE : SHA256_BLOCK_SIZE - remainder;

        // Subtract 1 to accommodate the pushdata byte in script.
        // +2 for placeholder padding prior to running this algo
        return new byte[lastBlockPadding - 1 + 2];
    }

    /**
     * Computes a partial SHA256 hash over the preImage, excluding the last
     * {@code excludeBlocks} 64-byte blocks from the intermediate hash.
     *
     * @param preImage      the full preimage bytes
     * @param excludeBlocks number of trailing blocks to exclude from partial hash
     * @return a two-element array: [partialHash (32 bytes), remainderBytes (128 bytes)]
     */
    public byte[][] computePartialHash(byte[] preImage, int excludeBlocks) {
        int blockCount = preImage.length / PartialSha256.BLOCK_BYTES;
        int rounds = blockCount - excludeBlocks;

        int[] paddedPreImage = PartialSha256.getPaddedPreImage(preImage);

        int start = 0;
        int end = 16; // 16 int words = 64 bytes = 1 block

        int[] firstBlock = new int[16];
        System.arraycopy(paddedPreImage, start, firstBlock, 0, 16);

        byte[] currentHash = PartialSha256.hashOneBlock(firstBlock, PartialSha256.STD_INIT_VECTOR);

        for (int round = 0; round < rounds; round++) {
            start = end;
            end = start + 16;
            int[] currentBlock = new int[16];
            System.arraycopy(paddedPreImage, start, currentBlock, 0, 16);
            currentHash = PartialSha256.hashOneBlock(currentBlock, PartialSha256.bytesToInt32Array(currentHash));
        }

        // Last 32 int words (128 bytes) as remainder
        int[] lastBlocks = new int[32];
        System.arraycopy(paddedPreImage, paddedPreImage.length - 32, lastBlocks, 0, 32);
        byte[] remainderBytes = PartialSha256.int32ArrayToBytes(lastBlocks);

        return new byte[][] { currentHash, remainderBytes };
    }

    /**
     * Returns the left-hand side of a transaction: version, input count, and
     * all serialized inputs. Excludes outputs and locktime.
     *
     * @param fullTx the transaction
     * @return serialized LHS bytes
     */
    public byte[] getTxLHS(Transaction fullTx) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        // Write version (4 bytes, little-endian)
        ByteBuffer versionBuf = ByteBuffer.allocate(4);
        versionBuf.order(ByteOrder.LITTLE_ENDIAN);
        versionBuf.putInt((int) fullTx.getVersion());
        bos.write(versionBuf.array());

        // Write input count as varint
        int numInputs = fullTx.getInputs().size();
        bos.write(encodeVarInt(numInputs));

        // Write the inputs
        for (TransactionInput input : fullTx.getInputs()) {
            bos.write(input.serialize());
        }

        return bos.toByteArray();
    }

    /**
     * Encodes an integer as a Bitcoin-style variable-length integer.
     */
    private static byte[] encodeVarInt(long value) {
        if (value < 0xFD) {
            return new byte[] { (byte) value };
        } else if (value <= 0xFFFF) {
            byte[] buf = new byte[3];
            buf[0] = (byte) 0xFD;
            buf[1] = (byte) (value & 0xFF);
            buf[2] = (byte) ((value >> 8) & 0xFF);
            return buf;
        } else if (value <= 0xFFFFFFFFL) {
            byte[] buf = new byte[5];
            buf[0] = (byte) 0xFE;
            buf[1] = (byte) (value & 0xFF);
            buf[2] = (byte) ((value >> 8) & 0xFF);
            buf[3] = (byte) ((value >> 16) & 0xFF);
            buf[4] = (byte) ((value >> 24) & 0xFF);
            return buf;
        } else {
            byte[] buf = new byte[9];
            buf[0] = (byte) 0xFF;
            for (int i = 0; i < 8; i++) {
                buf[1 + i] = (byte) ((value >> (i * 8)) & 0xFF);
            }
            return buf;
        }
    }
}
