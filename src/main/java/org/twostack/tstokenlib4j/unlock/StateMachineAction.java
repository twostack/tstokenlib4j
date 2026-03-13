package org.twostack.tstokenlib4j.unlock;

public enum StateMachineAction {
    CREATE(0),
    ENROLL(1),
    CONFIRM(2),
    CONVERT(3),
    SETTLE(4),
    TIMEOUT(5),
    BURN(6);

    private final int value;

    StateMachineAction(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
