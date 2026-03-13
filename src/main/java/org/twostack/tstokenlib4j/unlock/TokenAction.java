package org.twostack.tstokenlib4j.unlock;

public enum TokenAction {
    ISSUANCE(0), TRANSFER(1), BURN(2);

    public final int opValue;

    TokenAction(int opValue) {
        this.opValue = opValue;
    }
}
