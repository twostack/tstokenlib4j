package org.twostack.tstokenlib4j.crypto;

import org.junit.Test;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

/**
 * Tests for {@link MerkleTree} — ported from Dart merkle_tree test cases.
 */
public class MerkleTreeTest {

    private static byte[] makePKH(int fillByte) {
        byte[] pkh = new byte[20];
        Arrays.fill(pkh, (byte) fillByte);
        return pkh;
    }

    private static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    @Test
    public void singleLeaf_rootIsSha256OfLeaf() throws Exception {
        byte[] pkh = makePKH(0x01);
        MerkleTree tree = new MerkleTree(List.of(pkh));

        assertEquals(32, tree.getRoot().length);
        assertEquals(0, tree.getDepth());
        assertEquals(1, tree.getLeafCount());

        // Root should be SHA256(pkh)
        byte[] expected = sha256(pkh);
        assertArrayEquals(expected, tree.getRoot());
    }

    @Test
    public void twoLeaves_producesValidProofs() {
        byte[] pkh1 = makePKH(0x01);
        byte[] pkh2 = makePKH(0x02);
        MerkleTree tree = new MerkleTree(List.of(pkh1, pkh2));
        assertEquals(1, tree.getDepth());

        List<MerkleProofEntry> proof0 = tree.getProof(0);
        assertEquals(1, proof0.size());
        assertTrue(MerkleTree.verifyProof(pkh1, proof0, tree.getRoot()));

        List<MerkleProofEntry> proof1 = tree.getProof(1);
        assertTrue(MerkleTree.verifyProof(pkh2, proof1, tree.getRoot()));

        // Wrong proof should fail
        assertFalse(MerkleTree.verifyProof(pkh2, proof0, tree.getRoot()));
    }

    @Test
    public void fourLeaves_allProofsValid() {
        List<byte[]> leaves = List.of(makePKH(1), makePKH(2), makePKH(3), makePKH(4));
        MerkleTree tree = new MerkleTree(leaves);
        assertEquals(2, tree.getDepth());

        for (int i = 0; i < 4; i++) {
            List<MerkleProofEntry> proof = tree.getProof(i);
            assertTrue("Proof for leaf " + i + " should verify",
                    MerkleTree.verifyProof(leaves.get(i), proof, tree.getRoot()));
        }
    }

    @Test
    public void oddCount_threeLeaves_handlesDuplication() {
        List<byte[]> leaves = List.of(makePKH(1), makePKH(2), makePKH(3));
        MerkleTree tree = new MerkleTree(leaves);
        assertEquals(2, tree.getDepth());

        for (int i = 0; i < 3; i++) {
            List<MerkleProofEntry> proof = tree.getProof(i);
            assertTrue("Proof for leaf " + i + " should verify",
                    MerkleTree.verifyProof(leaves.get(i), proof, tree.getRoot()));
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void emptyList_throws() {
        new MerkleTree(List.of());
    }

    @Test(expected = IllegalArgumentException.class)
    public void wrongSize_throws() {
        new MerkleTree(List.of(new byte[19]));
    }

    @Test
    public void proofRoundtrip_verifyAndReject() {
        List<byte[]> leaves = List.of(makePKH(0x10), makePKH(0x20), makePKH(0x30), makePKH(0x40));
        MerkleTree tree = new MerkleTree(leaves);

        // Verify all
        for (int i = 0; i < leaves.size(); i++) {
            assertTrue(MerkleTree.verifyProof(leaves.get(i), tree.getProof(i), tree.getRoot()));
        }

        // Non-existent leaf should fail
        byte[] fakeLeaf = makePKH(0xFF);
        assertFalse(MerkleTree.verifyProof(fakeLeaf, tree.getProof(0), tree.getRoot()));
    }
}
