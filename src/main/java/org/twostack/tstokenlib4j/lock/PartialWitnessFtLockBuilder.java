package org.twostack.tstokenlib4j.lock;

import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.transaction.LockingScriptBuilder;
import org.twostack.tstokenlib4j.template.TemplateDescriptor;
import org.twostack.tstokenlib4j.template.TemplateLoader;

/**
 * Builds the PP3 (Plugpoint 3) locking script for a TSL1 fungible-token (FT) partial-witness output.
 *
 * <p>The PP3 FT partial-witness script is a lightweight witness used during FT transfers.
 * It requires only the owner's public-key hash. The builder loads the pre-compiled
 * script template from {@code templates/ft/pp3_ft_witness.json} and performs raw hex
 * substitution of the single parameter.</p>
 *
 * <p>Because this is a PP1-style template, pushdata prefixes are baked into the template
 * hex; only the raw parameter bytes are substituted.</p>
 *
 * @see <a href="https://github.com/twostack/tsl1">TSL1 Specification</a>
 */
public class PartialWitnessFtLockBuilder extends LockingScriptBuilder {

    private final byte[] ownerPKH;
    private final int pp2OutputIndex;

    /**
     * Creates a new PP3 FT partial-witness lock builder.
     *
     * @param ownerPKH        the HASH160 of the token owner's public key (must be exactly 20 bytes)
     * @param pp2OutputIndex  the output index of the PP2-FT output (2 for standard triplet, 5 for change triplet)
     * @throws IllegalArgumentException if {@code ownerPKH} is null or not 20 bytes
     */
    public PartialWitnessFtLockBuilder(byte[] ownerPKH, int pp2OutputIndex) {
        if (ownerPKH == null || ownerPKH.length != 20) {
            throw new IllegalArgumentException("ownerPKH must be 20 bytes");
        }
        this.ownerPKH = ownerPKH.clone();
        this.pp2OutputIndex = pp2OutputIndex;
    }

    /**
     * Builds the PP3 FT partial-witness locking script by loading the template from
     * {@code templates/ft/pp3_ft_witness.json} and substituting the {@code {{ownerPKH}}}
     * and {@code {{pp2OutputIndex}}} placeholders.
     *
     * @return the fully assembled locking {@link Script}
     */
    @Override
    public Script getLockingScript() {
        TemplateDescriptor td = TemplateLoader.load("templates/ft/pp3_ft_witness.json");
        String hex = td.getHex();
        hex = hex.replace("{{ownerPKH}}", Utils.HEX.encode(ownerPKH));
        // pp2OutputIndex is encoded as 4-byte little-endian (raw hex, no pushdata prefix)
        byte[] pp2LE = new byte[4];
        pp2LE[0] = (byte) (pp2OutputIndex & 0xFF);
        pp2LE[1] = (byte) ((pp2OutputIndex >> 8) & 0xFF);
        pp2LE[2] = (byte) ((pp2OutputIndex >> 16) & 0xFF);
        pp2LE[3] = (byte) ((pp2OutputIndex >> 24) & 0xFF);
        hex = hex.replace("{{pp2OutputIndex}}", Utils.HEX.encode(pp2LE));
        return Script.fromByteArray(Utils.HEX.decode(hex));
    }

    /** @return a defensive copy of the owner's public-key hash (20 bytes) */
    public byte[] getOwnerPKH() {
        return ownerPKH.clone();
    }

    /** @return the output index of the PP2-FT output */
    public int getPp2OutputIndex() {
        return pp2OutputIndex;
    }
}
