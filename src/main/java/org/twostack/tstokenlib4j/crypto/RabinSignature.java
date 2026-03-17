package org.twostack.tstokenlib4j.crypto;

import java.math.BigInteger;

public record RabinSignature(BigInteger s, int padding) {}
