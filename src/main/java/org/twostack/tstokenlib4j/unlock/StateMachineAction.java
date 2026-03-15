package org.twostack.tstokenlib4j.unlock;

/**
 * Actions supported by state machine (SM) token unlock scripts.
 *
 * <p>Each action's value is pushed as the last item in the unlock script,
 * where the PP1 SM lock script uses it as a dispatch selector.
 *
 * <ul>
 *   <li>{@link #CREATE} (0) — Create a new state machine token.</li>
 *   <li>{@link #ENROLL} (1) — Enroll a customer into the state machine flow.</li>
 *   <li>{@link #CONFIRM} (2) — Confirm a milestone (requires both merchant and customer signatures).</li>
 *   <li>{@link #CONVERT} (3) — Convert the state machine state (requires both merchant and customer signatures).</li>
 *   <li>{@link #SETTLE} (4) — Settle the state machine, distributing rewards and payments.</li>
 *   <li>{@link #TIMEOUT} (5) — Handle a timeout condition, processing refunds.</li>
 *   <li>{@link #BURN} (6) — Permanently destroy the state machine token.</li>
 * </ul>
 *
 * @see PP1SmUnlockBuilder
 */
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
