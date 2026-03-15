package org.twostack.tstokenlib4j.lock;

import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.transaction.LockingScriptBuilder;
import org.twostack.tstokenlib4j.template.TemplateDescriptor;
import org.twostack.tstokenlib4j.template.TemplateLoader;

/**
 * Builds a locking script for a modified Pay-to-Public-Key-Hash (mod-P2PKH) utility output.
 *
 * <p>This builder produces a non-token utility script used for change outputs and other
 * auxiliary purposes within TSL1 transactions. It loads the pre-compiled script template
 * from {@code templates/utility/mod_p2pkh.json} and performs raw hex substitution of the
 * owner's public-key hash.</p>
 *
 * <p>Because this is a PP1-style template, pushdata prefixes are baked into the template
 * hex; only the raw parameter bytes are substituted.</p>
 *
 * @see <a href="https://github.com/twostack/tsl1">TSL1 Specification</a>
 */
public class ModP2PKHLockBuilder extends LockingScriptBuilder {

    private final byte[] ownerPKH;

    /**
     * Creates a new mod-P2PKH lock builder.
     *
     * @param ownerPKH the HASH160 of the owner's public key (must be exactly 20 bytes);
     *                  defensively cloned on construction
     * @throws IllegalArgumentException if {@code ownerPKH} is null or not 20 bytes
     */
    public ModP2PKHLockBuilder(byte[] ownerPKH) {
        if (ownerPKH == null || ownerPKH.length != 20) {
            throw new IllegalArgumentException("ownerPKH must be 20 bytes");
        }
        this.ownerPKH = ownerPKH.clone();
    }

    /**
     * Builds the mod-P2PKH locking script by loading the template from
     * {@code templates/utility/mod_p2pkh.json} and substituting the {@code {{ownerPKH}}}
     * placeholder with the hex-encoded owner public-key hash.
     *
     * @return the fully assembled locking {@link Script}
     */
    @Override
    public Script getLockingScript() {
        TemplateDescriptor td = TemplateLoader.load("templates/utility/mod_p2pkh.json");
        String hex = td.getHex();
        hex = hex.replace("{{ownerPKH}}", Utils.HEX.encode(ownerPKH));
        return Script.fromByteArray(Utils.HEX.decode(hex));
    }

    /** @return a defensive copy of the owner's public-key hash (20 bytes) */
    public byte[] getOwnerPKH() {
        return ownerPKH.clone();
    }
}
