package org.twostack.tstokenlib4j.lock;

import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.transaction.LockingScriptBuilder;
import org.twostack.tstokenlib4j.template.TemplateDescriptor;
import org.twostack.tstokenlib4j.template.TemplateLoader;

public class PartialWitnessFtLockBuilder extends LockingScriptBuilder {

    private final byte[] ownerPKH;

    public PartialWitnessFtLockBuilder(byte[] ownerPKH) {
        if (ownerPKH == null || ownerPKH.length != 20) {
            throw new IllegalArgumentException("ownerPKH must be 20 bytes");
        }
        this.ownerPKH = ownerPKH.clone();
    }

    @Override
    public Script getLockingScript() {
        TemplateDescriptor td = TemplateLoader.load("templates/ft/pp3_ft_witness.json");
        String hex = td.getHex();
        hex = hex.replace("{{ownerPKH}}", Utils.HEX.encode(ownerPKH));
        return Script.fromByteArray(Utils.HEX.decode(hex));
    }

    public byte[] getOwnerPKH() {
        return ownerPKH.clone();
    }
}
