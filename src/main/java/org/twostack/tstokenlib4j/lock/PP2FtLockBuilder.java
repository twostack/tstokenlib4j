package org.twostack.tstokenlib4j.lock;

import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.transaction.LockingScriptBuilder;
import org.twostack.tstokenlib4j.encoding.PushdataEncoder;
import org.twostack.tstokenlib4j.encoding.ScriptNumberEncoder;
import org.twostack.tstokenlib4j.template.TemplateDescriptor;
import org.twostack.tstokenlib4j.template.TemplateLoader;

/**
 * Builds the PP2 (Plugpoint 2) locking script for a TSL1 fungible-token (FT) witness output.
 *
 * <p>The PP2 FT witness script extends the NFT witness with two additional output-index
 * parameters that link the witness to the corresponding PP1 FT output and the PP2 output
 * within the same transaction. It records the previous transaction's outpoint, the witness
 * change address and amount, the new owner's public-key hash, and the two output indices.</p>
 *
 * <p>Like {@link PP2LockBuilder}, this builder uses dynamic-length encoding: byte-array
 * parameters are encoded via {@link PushdataEncoder} and numeric parameters via
 * {@link ScriptNumberEncoder}. The template is loaded from
 * {@code templates/ft/pp2_ft.json}.</p>
 *
 * @see PP2LockBuilder
 * @see <a href="https://github.com/twostack/tsl1">TSL1 Specification</a>
 */
public class PP2FtLockBuilder extends LockingScriptBuilder {

    private final byte[] outpoint;
    private final byte[] witnessChangePKH;
    private final long witnessChangeAmount;
    private final byte[] ownerPKH;
    private final int pp1FtOutputIndex;
    private final int pp2OutputIndex;

    /**
     * Creates a new PP2 FT witness lock builder.
     *
     * @param outpoint            the previous transaction outpoint (txid + vout, must be exactly 36 bytes)
     * @param witnessChangePKH    the HASH160 of the witness change address (must be exactly 20 bytes)
     * @param witnessChangeAmount the satoshi amount for the witness change output
     * @param ownerPKH            the HASH160 of the new token owner's public key (must be exactly 20 bytes)
     * @param pp1FtOutputIndex    the output index of the PP1 FT output in the current transaction
     * @param pp2OutputIndex      the output index of this PP2 output in the current transaction
     * @throws IllegalArgumentException if any byte-array parameter is null or has an incorrect length
     */
    public PP2FtLockBuilder(byte[] outpoint, byte[] witnessChangePKH, long witnessChangeAmount,
                            byte[] ownerPKH, int pp1FtOutputIndex, int pp2OutputIndex) {
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
        this.pp1FtOutputIndex = pp1FtOutputIndex;
        this.pp2OutputIndex = pp2OutputIndex;
    }

    /**
     * Builds the PP2 FT witness locking script by loading the template from
     * {@code templates/ft/pp2_ft.json} and substituting the {@code {{outpoint}}},
     * {@code {{witnessChangePKH}}}, {@code {{witnessChangeAmount}}}, {@code {{ownerPKH}}},
     * {@code {{pp1FtOutputIndex}}}, and {@code {{pp2OutputIndex}}} placeholders.
     * Byte-array values are encoded with {@link PushdataEncoder} and numeric values with
     * {@link ScriptNumberEncoder}.
     *
     * @return the fully assembled locking {@link Script}
     */
    @Override
    public Script getLockingScript() {
        TemplateDescriptor td = TemplateLoader.load("templates/ft/pp2_ft.json");
        String hex = td.getHex();
        hex = hex.replace("{{outpoint}}", PushdataEncoder.encode(outpoint));
        hex = hex.replace("{{witnessChangePKH}}", PushdataEncoder.encode(witnessChangePKH));
        hex = hex.replace("{{witnessChangeAmount}}", ScriptNumberEncoder.encode(witnessChangeAmount));
        hex = hex.replace("{{ownerPKH}}", PushdataEncoder.encode(ownerPKH));
        hex = hex.replace("{{pp1FtOutputIndex}}", ScriptNumberEncoder.encode(pp1FtOutputIndex));
        hex = hex.replace("{{pp2OutputIndex}}", ScriptNumberEncoder.encode(pp2OutputIndex));
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

    /** @return the output index of the PP1 FT output in the current transaction */
    public int getPp1FtOutputIndex() {
        return pp1FtOutputIndex;
    }

    /** @return the output index of this PP2 output in the current transaction */
    public int getPp2OutputIndex() {
        return pp2OutputIndex;
    }
}
