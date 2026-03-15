package org.twostack.tstokenlib4j.lock;

import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.transaction.LockingScriptBuilder;
import org.twostack.tstokenlib4j.template.TemplateDescriptor;
import org.twostack.tstokenlib4j.template.TemplateLoader;

/**
 * Builds the PP1 (Plugpoint 1) locking script for a TSL1 non-fungible token (NFT).
 *
 * <p>The PP1 NFT script encodes the inductive proof that establishes ownership and
 * authenticity of a unique token. It loads the pre-compiled script template from
 * {@code templates/nft/pp1_nft.json} and performs raw hex substitution for the owner's
 * public-key hash, the token identifier, and the Rabin oracle public-key hash.</p>
 *
 * <p>Because this is a PP1-style template, pushdata prefixes are baked into the template
 * hex; only the raw parameter bytes are substituted.</p>
 *
 * @see <a href="https://github.com/twostack/tsl1">TSL1 Specification</a>
 */
public class PP1NftLockBuilder extends LockingScriptBuilder {

    private final byte[] ownerPKH;
    private final byte[] tokenId;
    private final byte[] rabinPubKeyHash;

    /**
     * Creates a new PP1 NFT lock builder.
     *
     * @param ownerPKH        the HASH160 of the token owner's public key (must be exactly 20 bytes)
     * @param tokenId         the unique 256-bit token identifier (must be exactly 32 bytes)
     * @param rabinPubKeyHash the HASH160 of the Rabin oracle's public key (must be exactly 20 bytes)
     * @throws IllegalArgumentException if any parameter is null or has an incorrect length
     */
    public PP1NftLockBuilder(byte[] ownerPKH, byte[] tokenId, byte[] rabinPubKeyHash) {
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
    }

    /**
     * Builds the PP1 NFT locking script by loading the template from
     * {@code templates/nft/pp1_nft.json} and substituting the {@code {{ownerPKH}}},
     * {@code {{tokenId}}}, and {@code {{rabinPubKeyHash}}} placeholders.
     *
     * @return the fully assembled locking {@link Script}
     */
    @Override
    public Script getLockingScript() {
        TemplateDescriptor td = TemplateLoader.load("templates/nft/pp1_nft.json");
        String hex = td.getHex();
        hex = hex.replace("{{ownerPKH}}", Utils.HEX.encode(ownerPKH));
        hex = hex.replace("{{tokenId}}", Utils.HEX.encode(tokenId));
        hex = hex.replace("{{rabinPubKeyHash}}", Utils.HEX.encode(rabinPubKeyHash));
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

    /** @return a defensive copy of the Rabin oracle public-key hash (20 bytes) */
    public byte[] getRabinPubKeyHash() {
        return rabinPubKeyHash.clone();
    }
}
