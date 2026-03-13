package org.twostack.tstokenlib4j.unlock;

public enum RestrictedTokenAction {
    ISSUANCE(0),
    TRANSFER(1),
    REDEEM(2),
    BURN(3);

    private final int value;

    RestrictedTokenAction(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
