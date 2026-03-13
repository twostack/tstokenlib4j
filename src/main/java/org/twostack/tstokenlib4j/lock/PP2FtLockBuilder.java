package org.twostack.tstokenlib4j.lock;

import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.transaction.LockingScriptBuilder;
import org.twostack.tstokenlib4j.encoding.PushdataEncoder;
import org.twostack.tstokenlib4j.encoding.ScriptNumberEncoder;
import org.twostack.tstokenlib4j.template.TemplateDescriptor;
import org.twostack.tstokenlib4j.template.TemplateLoader;

public class PP2FtLockBuilder extends LockingScriptBuilder {

    private final byte[] outpoint;
    private final byte[] witnessChangePKH;
    private final long witnessChangeAmount;
    private final byte[] ownerPKH;
    private final int pp1FtOutputIndex;
    private final int pp2OutputIndex;

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

    public byte[] getOutpoint() {
        return outpoint.clone();
    }

    public byte[] getWitnessChangePKH() {
        return witnessChangePKH.clone();
    }

    public long getWitnessChangeAmount() {
        return witnessChangeAmount;
    }

    public byte[] getOwnerPKH() {
        return ownerPKH.clone();
    }

    public int getPp1FtOutputIndex() {
        return pp1FtOutputIndex;
    }

    public int getPp2OutputIndex() {
        return pp2OutputIndex;
    }
}
