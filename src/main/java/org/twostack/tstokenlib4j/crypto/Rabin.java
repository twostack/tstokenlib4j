package org.twostack.tstokenlib4j.crypto;

import org.twostack.bitcoin4j.Utils;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Rabin signature scheme utilities for Bitcoin Script verification.
 *
 * Rabin signatures are ideal for in-script verification because the
 * verification formula {@code s² mod n == hash} compiles to just 3 opcodes
 * (OP_DUP OP_MUL, OP_MOD), making it far more compact than ECDSA or
 * Ed25519 verification in script.
 */
public final class Rabin {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final BigInteger FOUR = BigInteger.valueOf(4);
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger TWO = BigInteger.TWO;

    private Rabin() {}

    /**
     * Generate a Rabin keypair with the given bit length.
     * Both primes p and q satisfy p ≡ 3 (mod 4), which enables efficient
     * square root computation via s = m^((p+1)/4) mod p.
     */
    public static RabinKeyPair generateKeyPair(int bitLength) {
        int halfBits = bitLength / 2;
        BigInteger p = generateBlumPrime(halfBits);
        BigInteger q = generateBlumPrime(halfBits);
        BigInteger n = p.multiply(q);
        return new RabinKeyPair(n, p, q);
    }

    /**
     * Sign a message hash (as BigInteger) using the Rabin private key.
     * If the hash is not a quadratic residue mod n, increments by 1
     * until a residue is found. Returns (s, padding) where s² mod n == hash + padding.
     */
    public static RabinSignature sign(BigInteger messageHash, BigInteger p, BigInteger q) {
        BigInteger n = p.multiply(q);

        for (int padding = 0; padding < 256; padding++) {
            BigInteger m = messageHash.add(BigInteger.valueOf(padding));

            if (isQuadraticResidue(m, p) && isQuadraticResidue(m, q)) {
                // Compute square roots mod p and mod q
                // Since p ≡ 3 (mod 4): sqrt(m) mod p = m^((p+1)/4) mod p
                BigInteger sp = m.modPow(p.add(BigInteger.ONE).shiftRight(2), p);
                BigInteger sq = m.modPow(q.add(BigInteger.ONE).shiftRight(2), q);

                // Combine using Chinese Remainder Theorem
                BigInteger s = crt(sp, sq, p, q, n);

                // Verify: s² mod n == m mod n
                assert s.multiply(s).mod(n).equals(m.mod(n));

                return new RabinSignature(s, padding);
            }
        }

        throw new IllegalStateException("Could not find quadratic residue within 256 padding values");
    }

    /**
     * Verify a Rabin signature: s² mod n == messageHash + padding.
     */
    public static boolean verify(BigInteger messageHash, RabinSignature sig, BigInteger n) {
        BigInteger expected = messageHash.add(BigInteger.valueOf(sig.padding())).mod(n);
        BigInteger actual = sig.s().multiply(sig.s()).mod(n);
        return actual.equals(expected);
    }

    /**
     * Convert a SHA256 hash (32 bytes, big-endian) to a BigInteger.
     * Interprets the bytes in standard big-endian order (MSB first).
     */
    public static BigInteger hashToInt(byte[] hashBytes) {
        return new BigInteger(1, hashBytes);
    }

    /**
     * Convert raw hash bytes to the BigInteger that Bitcoin Script would produce.
     * The script appends 0x00 (positive sign byte) and interprets as LE sign-magnitude.
     * This is equivalent to reading the bytes as unsigned little-endian.
     */
    public static BigInteger hashBytesToScriptInt(byte[] hashBytes) {
        BigInteger result = BigInteger.ZERO;
        for (int i = 0; i < hashBytes.length; i++) {
            result = result.or(BigInteger.valueOf(hashBytes[i] & 0xFF).shiftLeft(8 * i));
        }
        return result;
    }

    /**
     * Encode a BigInteger as sign-magnitude little-endian bytes (Bitcoin Script number format).
     */
    public static byte[] bigIntToScriptNum(BigInteger value) {
        if (value.equals(BigInteger.ZERO)) {
            return new byte[0];
        }

        boolean isNegative = value.signum() < 0;
        BigInteger abs = value.abs();

        // Convert to little-endian unsigned bytes
        byte[] beBytes = abs.toByteArray();

        // BigInteger.toByteArray() is big-endian and may have a leading zero byte
        // Convert to LE and strip leading zero
        int start = (beBytes[0] == 0) ? 1 : 0;
        int len = beBytes.length - start;
        byte[] leBytes = new byte[len];
        for (int i = 0; i < len; i++) {
            leBytes[i] = beBytes[beBytes.length - 1 - i];
        }

        // If the MSB has the sign bit set, add a sign byte
        if ((leBytes[leBytes.length - 1] & 0x80) != 0) {
            byte[] extended = new byte[leBytes.length + 1];
            System.arraycopy(leBytes, 0, extended, 0, leBytes.length);
            extended[leBytes.length] = (byte) (isNegative ? 0x80 : 0x00);
            return extended;
        } else if (isNegative) {
            leBytes[leBytes.length - 1] |= (byte) 0x80;
        }

        return leBytes;
    }

    /**
     * Compute HASH160(bigIntToBytes(n)) — the 20-byte hash of the Rabin public key.
     */
    public static byte[] rabinPubKeyHash(BigInteger n) {
        byte[] nBytes = bigIntToScriptNum(n);
        return Utils.sha256hash160(nBytes);
    }

    // --- Private helpers ---

    /**
     * Generate a prime p where p ≡ 3 (mod 4) (a "Blum prime").
     */
    private static BigInteger generateBlumPrime(int bitLength) {
        while (true) {
            BigInteger candidate = BigInteger.probablePrime(bitLength, SECURE_RANDOM);
            if (candidate.mod(FOUR).equals(THREE)) {
                return candidate;
            }
            // Try adjusting: find next prime ≡ 3 (mod 4)
            // Simply loop again — probablePrime is fast
        }
    }

    /**
     * Check if m is a quadratic residue mod p using Euler's criterion.
     */
    private static boolean isQuadraticResidue(BigInteger m, BigInteger p) {
        BigInteger mMod = m.mod(p);
        if (mMod.equals(BigInteger.ZERO)) {
            return true;
        }
        return mMod.modPow(p.subtract(BigInteger.ONE).shiftRight(1), p).equals(BigInteger.ONE);
    }

    /**
     * Chinese Remainder Theorem to combine square roots.
     */
    private static BigInteger crt(BigInteger sp, BigInteger sq, BigInteger p, BigInteger q, BigInteger n) {
        BigInteger[] gcdResult = extendedGcd(p, q);
        BigInteger yp = gcdResult[1];
        BigInteger yq = gcdResult[2];

        // s = (sp * yq * q + sq * yp * p) mod n
        BigInteger s = sp.multiply(yq).multiply(q)
                .add(sq.multiply(yp).multiply(p))
                .mod(n);
        if (s.signum() < 0) {
            s = s.add(n);
        }
        return s;
    }

    /**
     * Extended Euclidean algorithm. Returns [gcd, x, y] where a*x + b*y = gcd.
     */
    private static BigInteger[] extendedGcd(BigInteger a, BigInteger b) {
        if (a.equals(BigInteger.ZERO)) {
            return new BigInteger[]{b, BigInteger.ZERO, BigInteger.ONE};
        }
        BigInteger[] result = extendedGcd(b.mod(a), a);
        BigInteger g = result[0];
        BigInteger x1 = result[1];
        BigInteger y1 = result[2];
        return new BigInteger[]{g, y1.subtract(b.divide(a).multiply(x1)), x1};
    }
}
