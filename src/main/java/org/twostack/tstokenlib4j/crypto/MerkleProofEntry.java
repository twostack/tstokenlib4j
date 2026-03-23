package org.twostack.tstokenlib4j.crypto;

/**
 * A single entry in a Merkle inclusion proof.
 *
 * @param sibling  the 32-byte SHA256 hash of the sibling node
 * @param isLeft   true if the sibling is on the left side (i.e. the proven node is on the right)
 */
public record MerkleProofEntry(byte[] sibling, boolean isLeft) {}
