package org.twostack.tstokenlib4j.lock;

import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.transaction.LockingScriptBuilder;
import org.twostack.tstokenlib4j.encoding.PushdataEncoder;
import org.twostack.tstokenlib4j.encoding.ScriptNumberEncoder;
import org.twostack.tstokenlib4j.template.TemplateDescriptor;
import org.twostack.tstokenlib4j.template.TemplateLoader;

/**
 * Builds the PP2 (Plugpoint 2) locking script for a TSL1 NFT witness output.
 *
 * <p>The PP2 witness script provides the second part of the inductive proof for NFT
 * transfers. It records the previous transaction's outpoint, the witness change address
 * and amount, and the new owner's public-key hash.</p>
 *
 * <p>Unlike PP1 templates, this PP2 template uses dynamic-length encoding: byte-array
 * parameters are encoded via {@link PushdataEncoder} (which prepends the appropriate
 * pushdata opcode/length prefix), and numeric parameters are encoded via
 * {@link ScriptNumberEncoder} (which uses Bitcoin's script-number format). The template
 * is loaded from {@code templates/nft/pp2.json}.</p>
 *
 * @see <a href="https://github.com/twostack/tsl1">TSL1 Specification</a>
 */
public class PP2LockBuilder extends LockingScriptBuilder {

    private final byte[] outpoint;
    private final byte[] witnessChangePKH;
    private final long witnessChangeAmount;
    private final byte[] ownerPKH;

    /**
     * Creates a new PP2 NFT witness lock builder.
     *
     * @param outpoint            the previous transaction outpoint (txid + vout, must be exactly 36 bytes)
     * @param witnessChangePKH    the HASH160 of the witness change address (must be exactly 20 bytes)
     * @param witnessChangeAmount the satoshi amount for the witness change output
     * @param ownerPKH            the HASH160 of the new token owner's public key (must be exactly 20 bytes)
     * @throws IllegalArgumentException if any byte-array parameter is null or has an incorrect length
     */
    public PP2LockBuilder(byte[] outpoint, byte[] witnessChangePKH, long witnessChangeAmount, byte[] ownerPKH) {
        if (outpoint == null || outpoint.length != 36) {
            throw new IllegalArgumentException("outpoint must be 36 bytes");
        }
        if (witnessChangePKH == null || witnessChangePKH.length != 20) {
            throw new IllegalArgumentException("witnessChangePKH must be 20 bytes");
        }
        if (ownerPKH == null || ownerPKH.length != 20) {
            throw new IllegalArgumentException("ownerPKH must be 20 bytes");
        }
        this.outpoint = outpoint.clone();
        this.witnessChangePKH = witnessChangePKH.clone();
        this.witnessChangeAmount = witnessChangeAmount;
        this.ownerPKH = ownerPKH.clone();
    }

    /**
     * Builds the PP2 NFT witness locking script by loading the template from
     * {@code templates/nft/pp2.json} and substituting the {@code {{outpoint}}},
     * {@code {{witnessChangePKH}}}, {@code {{witnessChangeAmount}}}, and
     * {@code {{ownerPKH}}} placeholders. Byte-array values are encoded with
     * {@link PushdataEncoder} and numeric values with {@link ScriptNumberEncoder}.
     *
     * @return the fully assembled locking {@link Script}
     */
    @Override
    public Script getLockingScript() {
        TemplateDescriptor td = TemplateLoader.load("templates/nft/pp2.json");
        String hex = td.getHex();
        hex = hex.replace("{{outpoint}}", PushdataEncoder.encode(outpoint));
        hex = hex.replace("{{witnessChangePKH}}", PushdataEncoder.encode(witnessChangePKH));
        hex = hex.replace("{{witnessChangeAmount}}", ScriptNumberEncoder.encode(witnessChangeAmount));
        hex = hex.replace("{{ownerPKH}}", PushdataEncoder.encode(ownerPKH));
        return Script.fromByteArray(Utils.HEX.decode(hex));
    }

    /** @return a defensive copy of the previous transaction outpoint (36 bytes) */
    public byte[] getOutpoint() {
        return outpoint.clone();
    }

    /** @return a defensive copy of the witness change public-key hash (20 bytes) */
    public byte[] getWitnessChangePKH() {
        return witnessChangePKH.clone();
    }

    /** @return the witness change amount in satoshis */
    public long getWitnessChangeAmount() {
        return witnessChangeAmount;
    }

    /** @return a defensive copy of the owner's public-key hash (20 bytes) */
    public byte[] getOwnerPKH() {
        return ownerPKH.clone();
    }
}
