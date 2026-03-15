package org.twostack.tstokenlib4j.lock;

import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.transaction.LockingScriptBuilder;
import org.twostack.tstokenlib4j.template.TemplateDescriptor;
import org.twostack.tstokenlib4j.template.TemplateLoader;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Builds the PP1 (Plugpoint 1) locking script for a TSL1 appendable token (AT).
 *
 * <p>An appendable token is an NFT that accumulates "stamps" (endorsements) over its
 * lifetime. The script encodes the issuer's public-key hash, the current stamp count,
 * a threshold that gates some action, and a hash of all accumulated stamps, alongside
 * the standard owner PKH and token ID.</p>
 *
 * <p>The builder loads the pre-compiled script template from
 * {@code templates/nft/pp1_at.json} and performs raw hex substitution. Integer fields
 * ({@code stampCount}, {@code threshold}) are encoded as 4-byte little-endian values.</p>
 *
 * <p>Because this is a PP1-style template, pushdata prefixes are baked into the template
 * hex; only the raw parameter bytes are substituted.</p>
 *
 * @see <a href="https://github.com/twostack/tsl1">TSL1 Specification</a>
 */
public class PP1AtLockBuilder extends LockingScriptBuilder {

    private final byte[] ownerPKH;
    private final byte[] tokenId;
    private final byte[] issuerPKH;
    private final int stampCount;
    private final int threshold;
    private final byte[] stampsHash;

    /**
     * Creates a new PP1 appendable token lock builder.
     *
     * @param ownerPKH   the HASH160 of the token owner's public key (must be exactly 20 bytes)
     * @param tokenId    the unique 256-bit token identifier (must be exactly 32 bytes)
     * @param issuerPKH  the HASH160 of the issuer's public key (must be exactly 20 bytes)
     * @param stampCount the current number of stamps accumulated on this token
     * @param threshold  the stamp threshold required to gate an action
     * @param stampsHash a 256-bit hash of all accumulated stamps (must be exactly 32 bytes)
     * @throws IllegalArgumentException if any byte-array parameter is null or has an incorrect length
     */
    public PP1AtLockBuilder(byte[] ownerPKH, byte[] tokenId, byte[] issuerPKH,
                            int stampCount, int threshold, byte[] stampsHash) {
        if (ownerPKH == null || ownerPKH.length != 20) {
            throw new IllegalArgumentException("ownerPKH must be 20 bytes");
        }
        if (tokenId == null || tokenId.length != 32) {
            throw new IllegalArgumentException("tokenId must be 32 bytes");
        }
        if (issuerPKH == null || issuerPKH.length != 20) {
            throw new IllegalArgumentException("issuerPKH must be 20 bytes");
        }
        if (stampsHash == null || stampsHash.length != 32) {
            throw new IllegalArgumentException("stampsHash must be 32 bytes");
        }
        this.ownerPKH = ownerPKH.clone();
        this.tokenId = tokenId.clone();
        this.issuerPKH = issuerPKH.clone();
        this.stampCount = stampCount;
        this.threshold = threshold;
        this.stampsHash = stampsHash.clone();
    }

    /**
     * Builds the PP1 appendable token locking script by loading the template from
     * {@code templates/nft/pp1_at.json} and substituting the {@code {{ownerPKH}}},
     * {@code {{tokenId}}}, {@code {{issuerPKH}}}, {@code {{stampCount}}},
     * {@code {{threshold}}}, and {@code {{stampsHash}}} placeholders.
     *
     * @return the fully assembled locking {@link Script}
     */
    @Override
    public Script getLockingScript() {
        TemplateDescriptor td = TemplateLoader.load("templates/nft/pp1_at.json");
        String hex = td.getHex();
        hex = hex.replace("{{ownerPKH}}", Utils.HEX.encode(ownerPKH));
        hex = hex.replace("{{tokenId}}", Utils.HEX.encode(tokenId));
        hex = hex.replace("{{issuerPKH}}", Utils.HEX.encode(issuerPKH));
        hex = hex.replace("{{stampCount}}", encodeLeUint32(stampCount));
        hex = hex.replace("{{threshold}}", encodeLeUint32(threshold));
        hex = hex.replace("{{stampsHash}}", Utils.HEX.encode(stampsHash));
        return Script.fromByteArray(Utils.HEX.decode(hex));
    }

    private static String encodeLeUint32(int value) {
        byte[] bytes = new byte[4];
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(value);
        return Utils.HEX.encode(bytes);
    }

    /** @return a defensive copy of the owner's public-key hash (20 bytes) */
    public byte[] getOwnerPKH() { return ownerPKH.clone(); }
    /** @return a defensive copy of the token identifier (32 bytes) */
    public byte[] getTokenId() { return tokenId.clone(); }
    /** @return a defensive copy of the issuer's public-key hash (20 bytes) */
    public byte[] getIssuerPKH() { return issuerPKH.clone(); }
    /** @return the current stamp count */
    public int getStampCount() { return stampCount; }
    /** @return the stamp threshold */
    public int getThreshold() { return threshold; }
    /** @return a defensive copy of the accumulated stamps hash (32 bytes) */
    public byte[] getStampsHash() { return stampsHash.clone(); }
}
