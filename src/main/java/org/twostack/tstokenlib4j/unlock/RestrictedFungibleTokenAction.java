package org.twostack.tstokenlib4j.unlock;

public enum RestrictedFungibleTokenAction {
    MINT(0),
    TRANSFER(1),
    SPLIT_TRANSFER(2),
    MERGE(3),
    REDEEM(4),
    BURN(5);

    private final int value;

    RestrictedFungibleTokenAction(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
