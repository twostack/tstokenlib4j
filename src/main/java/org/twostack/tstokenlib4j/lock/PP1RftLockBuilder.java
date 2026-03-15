package org.twostack.tstokenlib4j.lock;

import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.transaction.LockingScriptBuilder;
import org.twostack.tstokenlib4j.encoding.AmountEncoder;
import org.twostack.tstokenlib4j.template.TemplateDescriptor;
import org.twostack.tstokenlib4j.template.TemplateLoader;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Builds the PP1 (Plugpoint 1) locking script for a TSL1 restricted fungible token (RFT).
 *
 * <p>An RFT extends the standard fungible token with a Rabin oracle public-key hash for
 * issuer-controlled transfer restrictions and a flags field that encodes the current
 * restriction policy. The builder loads the pre-compiled script template from
 * {@code templates/ft/pp1_rft.json} and performs raw hex substitution for all parameters.</p>
 *
 * <p>Because this is a PP1-style template, pushdata prefixes are baked into the template
 * hex; only the raw parameter bytes are substituted.</p>
 *
 * @see <a href="https://github.com/twostack/tsl1">TSL1 Specification</a>
 */
public class PP1RftLockBuilder extends LockingScriptBuilder {

    private final byte[] ownerPKH;
    private final byte[] tokenId;
    private final byte[] rabinPubKeyHash;
    private final int flags;
    private final long amount;

    /**
     * Creates a new PP1 restricted fungible token lock builder.
     *
     * @param ownerPKH        the HASH160 of the token owner's public key (must be exactly 20 bytes)
     * @param tokenId         the unique 256-bit token identifier (must be exactly 32 bytes)
     * @param rabinPubKeyHash the HASH160 of the Rabin oracle's public key (must be exactly 20 bytes)
     * @param flags           restriction flags encoded as a 4-byte little-endian integer
     * @param amount          the fungible token amount
     * @throws IllegalArgumentException if any byte-array parameter is null or has an incorrect length
     */
    public PP1RftLockBuilder(byte[] ownerPKH, byte[] tokenId, byte[] rabinPubKeyHash,
                             int flags, long amount) {
        if (ownerPKH == null || ownerPKH.length != 20) {
            throw new IllegalArgumentException("ownerPKH must be 20 bytes");
        }
        if (tokenId == null || tokenId.length != 32) {
            throw new IllegalArgumentException("tokenId must be 32 bytes");
        }
        if (rabinPubKeyHash == null || rabinPubKeyHash.length != 20) {
            throw new IllegalArgumentException("rabinPubKeyHash must be 20 bytes");
        }
        this.ownerPKH = ownerPKH.clone();
        this.tokenId = tokenId.clone();
        this.rabinPubKeyHash = rabinPubKeyHash.clone();
        this.flags = flags;
        this.amount = amount;
    }

    /**
     * Builds the PP1 RFT locking script by loading the template from
     * {@code templates/ft/pp1_rft.json} and substituting the {@code {{ownerPKH}}},
     * {@code {{tokenId}}}, {@code {{rabinPubKeyHash}}}, {@code {{flags}}}, and
     * {@code {{amount}}} placeholders.
     *
     * @return the fully assembled locking {@link Script}
     */
    @Override
    public Script getLockingScript() {
        TemplateDescriptor td = TemplateLoader.load("templates/ft/pp1_rft.json");
        String hex = td.getHex();
        hex = hex.replace("{{ownerPKH}}", Utils.HEX.encode(ownerPKH));
        hex = hex.replace("{{tokenId}}", Utils.HEX.encode(tokenId));
        hex = hex.replace("{{rabinPubKeyHash}}", Utils.HEX.encode(rabinPubKeyHash));
        hex = hex.replace("{{flags}}", encodeLeUint32(flags));
        hex = hex.replace("{{amount}}", Utils.HEX.encode(AmountEncoder.encodeLeUint56(amount)));
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
    /** @return a defensive copy of the Rabin oracle public-key hash (20 bytes) */
    public byte[] getRabinPubKeyHash() { return rabinPubKeyHash.clone(); }
    /** @return the restriction flags */
    public int getFlags() { return flags; }
    /** @return the fungible token amount */
    public long getAmount() { return amount; }
}
