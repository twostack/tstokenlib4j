package org.twostack.tstokenlib4j.crypto;

import java.math.BigInteger;

public record RabinKeyPair(BigInteger n, BigInteger p, BigInteger q) {}
