package org.twostack.tstokenlib4j.unlock;

public enum FungibleTokenAction {
    MINT(0), TRANSFER(1), SPLIT_TRANSFER(2), MERGE(3), BURN(4);

    public final int opValue;

    FungibleTokenAction(int opValue) {
        this.opValue = opValue;
    }
}
