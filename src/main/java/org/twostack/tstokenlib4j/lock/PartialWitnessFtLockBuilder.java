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

    /**
     * Creates a new PP3 FT partial-witness lock builder.
     *
     * @param ownerPKH the HASH160 of the token owner's public key (must be exactly 20 bytes);
     *                  defensively cloned on construction
     * @throws IllegalArgumentException if {@code ownerPKH} is null or not 20 bytes
     */
    public PartialWitnessFtLockBuilder(byte[] ownerPKH) {
        if (ownerPKH == null || ownerPKH.length != 20) {
            throw new IllegalArgumentException("ownerPKH must be 20 bytes");
        }
        this.ownerPKH = ownerPKH.clone();
    }

    /**
     * Builds the PP3 FT partial-witness locking script by loading the template from
     * {@code templates/ft/pp3_ft_witness.json} and substituting the {@code {{ownerPKH}}}
     * placeholder with the hex-encoded owner public-key hash.
     *
     * @return the fully assembled locking {@link Script}
     */
    @Override
    public Script getLockingScript() {
        TemplateDescriptor td = TemplateLoader.load("templates/ft/pp3_ft_witness.json");
        String hex = td.getHex();
        hex = hex.replace("{{ownerPKH}}", Utils.HEX.encode(ownerPKH));
        return Script.fromByteArray(Utils.HEX.decode(hex));
    }

    /** @return a defensive copy of the owner's public-key hash (20 bytes) */
    public byte[] getOwnerPKH() {
        return ownerPKH.clone();
    }
}
