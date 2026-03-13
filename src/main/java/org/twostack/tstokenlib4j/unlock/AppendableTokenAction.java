package org.twostack.tstokenlib4j.unlock;

public enum AppendableTokenAction {
    ISSUANCE(0),
    STAMP(1),
    REDEEM(2),
    TRANSFER(3),
    BURN(4);

    private final int value;

    AppendableTokenAction(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
