package org.twostack.tstokenlib4j.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Constructs a binary Merkle tree from a list of 20-byte pubkey hashes and
 * provides root computation and inclusion proof generation.
 *
 * <p>Used by the PP1_RFT (Restricted Fungible Token) whitelist system.
 *
 * <p>Tree structure:
 * <ul>
 *   <li>Each leaf is {@code SHA256(pubkeyHash)}.</li>
 *   <li>Each internal node is {@code SHA256(left || right)}.</li>
 *   <li>If a level has an odd number of nodes, the last node is duplicated.</li>
 *   <li>Maximum depth: 16 levels (supports up to 65,536 entries).</li>
 * </ul>
 */
public class MerkleTree {

    public static final int MAX_DEPTH = 16;
    public static final int MAX_LEAVES = 1 << MAX_DEPTH; // 65536

    /** All tree levels. Index 0 is the leaf level, last element is the root level. */
    private final List<List<byte[]>> levels;

    /**
     * Constructs the Merkle tree from a list of 20-byte pubkey hashes.
     *
     * @param pubkeyHashes list of 20-byte pubkey hashes
     * @throws IllegalArgumentException if the list is empty, contains incorrectly sized
     *         entries, or exceeds the maximum number of leaves (65,536)
     */
    public MerkleTree(List<byte[]> pubkeyHashes) {
        if (pubkeyHashes.isEmpty()) {
            throw new IllegalArgumentException("Cannot build a Merkle tree from an empty list");
        }
        if (pubkeyHashes.size() > MAX_LEAVES) {
            throw new IllegalArgumentException(
                    "Too many leaves: " + pubkeyHashes.size() + " exceeds maximum of " + MAX_LEAVES);
        }
        for (int i = 0; i < pubkeyHashes.size(); i++) {
            if (pubkeyHashes.get(i).length != 20) {
                throw new IllegalArgumentException(
                        "Pubkey hash at index " + i + " has length " + pubkeyHashes.get(i).length + ", expected 20");
            }
        }

        levels = new ArrayList<>();

        // Build leaf level: SHA256(pubkeyHash) for each entry.
        List<byte[]> leaves = new ArrayList<>();
        for (byte[] pkh : pubkeyHashes) {
            leaves.add(sha256(pkh));
        }
        levels.add(leaves);

        // Build successive levels until we reach a single root node.
        List<byte[]> current = leaves;
        while (current.size() > 1) {
            List<byte[]> next = new ArrayList<>();
            // If odd, duplicate the last node.
            if (current.size() % 2 != 0) {
                current = new ArrayList<>(current);
                current.add(current.get(current.size() - 1));
            }
            for (int i = 0; i < current.size(); i += 2) {
                byte[] combined = new byte[64];
                System.arraycopy(current.get(i), 0, combined, 0, 32);
                System.arraycopy(current.get(i + 1), 0, combined, 32, 32);
                next.add(sha256(combined));
            }
            levels.add(next);
            current = next;
        }
    }

    /** The 32-byte Merkle root hash. */
    public byte[] getRoot() {
        List<byte[]> rootLevel = levels.get(levels.size() - 1);
        return Arrays.copyOf(rootLevel.get(0), 32);
    }

    /** The number of leaves in the tree. */
    public int getLeafCount() {
        return levels.get(0).size();
    }

    /** The depth of the tree (number of levels excluding the root level). */
    public int getDepth() {
        return levels.size() - 1;
    }

    /**
     * Generates an inclusion proof for the leaf at {@code leafIndex}.
     *
     * @param leafIndex the index of the leaf to prove
     * @return a list of {@link MerkleProofEntry} from the leaf level up to (but not including) the root
     * @throws IndexOutOfBoundsException if leafIndex is out of bounds
     */
    public List<MerkleProofEntry> getProof(int leafIndex) {
        if (leafIndex < 0 || leafIndex >= levels.get(0).size()) {
            throw new IndexOutOfBoundsException(
                    "leafIndex " + leafIndex + " is out of range [0, " + levels.get(0).size() + ")");
        }

        List<MerkleProofEntry> proof = new ArrayList<>();
        int idx = leafIndex;

        for (int level = 0; level < levels.size() - 1; level++) {
            List<byte[]> levelNodes = levels.get(level);
            // If odd number of nodes, conceptually duplicate the last.
            if (levelNodes.size() % 2 != 0) {
                levelNodes = new ArrayList<>(levelNodes);
                levelNodes.add(levelNodes.get(levelNodes.size() - 1));
            }

            int siblingIdx = (idx % 2 == 0) ? idx + 1 : idx - 1;
            boolean siblingIsLeft = (idx % 2 != 0); // sibling is on the left if we are odd

            proof.add(new MerkleProofEntry(
                    Arrays.copyOf(levelNodes.get(siblingIdx), 32),
                    siblingIsLeft));

            // Move to the parent index.
            idx = idx / 2;
        }

        return proof;
    }

    /**
     * Verifies a Merkle inclusion proof.
     *
     * @param leaf         the raw 20-byte pubkey hash (not yet hashed)
     * @param proof        the list of {@link MerkleProofEntry} from {@link #getProof}
     * @param expectedRoot the expected 32-byte Merkle root
     * @return true if the proof is valid
     */
    public static boolean verifyProof(byte[] leaf, List<MerkleProofEntry> proof, byte[] expectedRoot) {
        if (leaf.length != 20) {
            throw new IllegalArgumentException("Leaf must be 20 bytes (pubkey hash)");
        }
        if (expectedRoot.length != 32) {
            throw new IllegalArgumentException("Root must be 32 bytes");
        }

        // Start with SHA256 of the leaf data.
        byte[] current = sha256(leaf);

        for (MerkleProofEntry entry : proof) {
            byte[] combined = new byte[64];
            if (entry.isLeft()) {
                // Sibling is on the left.
                System.arraycopy(entry.sibling(), 0, combined, 0, 32);
                System.arraycopy(current, 0, combined, 32, 32);
            } else {
                // Sibling is on the right.
                System.arraycopy(current, 0, combined, 0, 32);
                System.arraycopy(entry.sibling(), 0, combined, 32, 32);
            }
            current = sha256(combined);
        }

        return Arrays.equals(current, expectedRoot);
    }

    private static byte[] sha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}
