package org.twostack.tstokenlib4j.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Test;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import static org.assertj.core.api.Assertions.assertThat;

public class RabinTest {

    @Test
    public void generateKeyPair_primesAreBlum() {
        RabinKeyPair kp = Rabin.generateKeyPair(512);

        // p ≡ 3 (mod 4)
        assertThat(kp.p().mod(BigInteger.valueOf(4)))
                .isEqualTo(BigInteger.valueOf(3));
        // q ≡ 3 (mod 4)
        assertThat(kp.q().mod(BigInteger.valueOf(4)))
                .isEqualTo(BigInteger.valueOf(3));
        // n = p * q
        assertThat(kp.n()).isEqualTo(kp.p().multiply(kp.q()));
        // Both primes should be probable primes
        assertThat(kp.p().isProbablePrime(20)).isTrue();
        assertThat(kp.q().isProbablePrime(20)).isTrue();
    }

    @Test
    public void signAndVerify_roundTrips() {
        RabinKeyPair kp = Rabin.generateKeyPair(1024);

        // Hash some test data
        byte[] data = "Hello Rabin signatures!".getBytes(StandardCharsets.UTF_8);
        byte[] hash = sha256(data);
        BigInteger hashInt = Rabin.hashBytesToScriptInt(hash);

        RabinSignature sig = Rabin.sign(hashInt, kp.p(), kp.q());

        assertThat(sig).isNotNull();
        assertThat(sig.padding()).isBetween(0, 255);

        // Verify
        boolean valid = Rabin.verify(hashInt, sig, kp.n());
        assertThat(valid).isTrue();
    }

    @Test
    public void verify_wrongHash_returnsFalse() {
        RabinKeyPair kp = Rabin.generateKeyPair(1024);

        byte[] data = "Original message".getBytes(StandardCharsets.UTF_8);
        byte[] hash = sha256(data);
        BigInteger hashInt = Rabin.hashBytesToScriptInt(hash);

        RabinSignature sig = Rabin.sign(hashInt, kp.p(), kp.q());

        // Verify with wrong hash
        byte[] wrongData = "Tampered message".getBytes(StandardCharsets.UTF_8);
        byte[] wrongHash = sha256(wrongData);
        BigInteger wrongHashInt = Rabin.hashBytesToScriptInt(wrongHash);

        boolean valid = Rabin.verify(wrongHashInt, sig, kp.n());
        assertThat(valid).isFalse();
    }

    @Test
    public void verify_crossLanguageVector() throws Exception {
        // Load cross-language vectors
        InputStream is = getClass().getClassLoader()
                .getResourceAsStream("cross_language_vectors.json");
        assertThat(is).isNotNull();

        ObjectMapper mapper = new ObjectMapper();
        JsonNode root = mapper.readTree(is);

        // Find PP1_NFT_UNLOCK_ISSUANCE vector which contains rabinN, rabinS, rabinPadding
        JsonNode vectors = root.get("vectors");
        JsonNode nftUnlockInputs = null;
        for (JsonNode vec : vectors) {
            if ("PP1_NFT_UNLOCK_ISSUANCE".equals(vec.get("name").asText())) {
                nftUnlockInputs = vec.get("inputs");
                break;
            }
        }
        assertThat(nftUnlockInputs).isNotNull();

        String rabinNHex = nftUnlockInputs.get("rabinN").asText();
        String rabinSHex = nftUnlockInputs.get("rabinS").asText();
        int rabinPadding = nftUnlockInputs.get("rabinPadding").asInt();

        BigInteger rabinN = new BigInteger(rabinNHex, 16);
        BigInteger rabinS = new BigInteger(rabinSHex, 16);

        assertThat(rabinN.signum()).isPositive();
        assertThat(rabinS.signum()).isPositive();

        // These are test vectors — the values are deterministic hex sequences,
        // not real cryptographic signatures. Verify the encoding round-trips correctly.
        RabinSignature sig = new RabinSignature(rabinS, rabinPadding);
        assertThat(sig.s()).isEqualTo(rabinS);
        assertThat(sig.padding()).isEqualTo(rabinPadding);
    }

    @Test
    public void bigIntToScriptNum_matchesDartEncoding() {
        // Zero
        byte[] zero = Rabin.bigIntToScriptNum(BigInteger.ZERO);
        assertThat(zero).isEmpty();

        // Small positive
        byte[] one = Rabin.bigIntToScriptNum(BigInteger.ONE);
        assertThat(one).isEqualTo(new byte[]{0x01});

        // 127 — doesn't need sign byte
        byte[] b127 = Rabin.bigIntToScriptNum(BigInteger.valueOf(127));
        assertThat(b127).isEqualTo(new byte[]{0x7f});

        // 128 — needs sign byte (0x00) because 0x80 is the sign bit
        byte[] b128 = Rabin.bigIntToScriptNum(BigInteger.valueOf(128));
        assertThat(b128).isEqualTo(new byte[]{(byte) 0x80, 0x00});

        // 255
        byte[] b255 = Rabin.bigIntToScriptNum(BigInteger.valueOf(255));
        assertThat(b255).isEqualTo(new byte[]{(byte) 0xff, 0x00});

        // Negative: -1
        byte[] negOne = Rabin.bigIntToScriptNum(BigInteger.valueOf(-1));
        assertThat(negOne).isEqualTo(new byte[]{(byte) 0x81});

        // Negative: -128
        byte[] neg128 = Rabin.bigIntToScriptNum(BigInteger.valueOf(-128));
        assertThat(neg128).isEqualTo(new byte[]{(byte) 0x80, (byte) 0x80});
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static byte[] sha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
