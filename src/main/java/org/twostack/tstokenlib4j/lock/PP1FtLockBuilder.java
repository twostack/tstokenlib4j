package org.twostack.tstokenlib4j.lock;

import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.transaction.LockingScriptBuilder;
import org.twostack.tstokenlib4j.encoding.AmountEncoder;
import org.twostack.tstokenlib4j.template.TemplateDescriptor;
import org.twostack.tstokenlib4j.template.TemplateLoader;

/**
 * Builds the PP1 (Proof Part 1) locking script for a TSL1 fungible token (FT).
 *
 * <p>The PP1 FT script encodes the inductive proof that establishes ownership and the
 * token balance for a fungible token output. It loads the pre-compiled script template
 * from {@code templates/ft/pp1_ft.json} and performs raw hex substitution for the
 * owner's public-key hash, the token identifier, and the token amount.</p>
 *
 * <p>The amount is encoded as a 7-byte (56-bit) little-endian unsigned integer via
 * {@link AmountEncoder#encodeLeUint56(long)}, constraining the maximum value to
 * 2<sup>55</sup> - 1.</p>
 *
 * <p>Because this is a PP1-style template, pushdata prefixes are baked into the template
 * hex; only the raw parameter bytes are substituted.</p>
 *
 * @see <a href="https://github.com/twostack/tsl1">TSL1 Specification</a>
 */
public class PP1FtLockBuilder extends LockingScriptBuilder {

    private final byte[] ownerPKH;
    private final byte[] tokenId;
    private final long amount;

    /**
     * Creates a new PP1 FT lock builder.
     *
     * @param ownerPKH the HASH160 of the token owner's public key (must be exactly 20 bytes)
     * @param tokenId  the unique 256-bit token identifier (must be exactly 32 bytes)
     * @param amount   the fungible token amount; must be &gt;= 0 and &lt; 2<sup>55</sup>
     * @throws IllegalArgumentException if any parameter is null, has an incorrect length,
     *                                  or {@code amount} is out of range
     */
    public PP1FtLockBuilder(byte[] ownerPKH, byte[] tokenId, long amount) {
        if (ownerPKH == null || ownerPKH.length != 20) {
            throw new IllegalArgumentException("ownerPKH must be 20 bytes");
        }
        if (tokenId == null || tokenId.length != 32) {
            throw new IllegalArgumentException("tokenId must be 32 bytes");
        }
        if (amount < 0 || amount >= (1L << 55)) {
            throw new IllegalArgumentException("amount must be >= 0 and < 2^55");
        }
        this.ownerPKH = ownerPKH.clone();
        this.tokenId = tokenId.clone();
        this.amount = amount;
    }

    /**
     * Builds the PP1 FT locking script by loading the template from
     * {@code templates/ft/pp1_ft.json} and substituting the {@code {{ownerPKH}}},
     * {@code {{tokenId}}}, and {@code {{amount}}} placeholders.
     *
     * @return the fully assembled locking {@link Script}
     */
    @Override
    public Script getLockingScript() {
        TemplateDescriptor td = TemplateLoader.load("templates/ft/pp1_ft.json");
        String hex = td.getHex();
        hex = hex.replace("{{ownerPKH}}", Utils.HEX.encode(ownerPKH));
        hex = hex.replace("{{tokenId}}", Utils.HEX.encode(tokenId));
        hex = hex.replace("{{amount}}", Utils.HEX.encode(AmountEncoder.encodeLeUint56(amount)));
        return Script.fromByteArray(Utils.HEX.decode(hex));
    }

    /** @return a defensive copy of the owner's public-key hash (20 bytes) */
    public byte[] getOwnerPKH() {
        return ownerPKH.clone();
    }

    /** @return a defensive copy of the token identifier (32 bytes) */
    public byte[] getTokenId() {
        return tokenId.clone();
    }

    /** @return the fungible token amount */
    public long getAmount() {
        return amount;
    }
}
