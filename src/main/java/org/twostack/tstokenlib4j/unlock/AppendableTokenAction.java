package org.twostack.tstokenlib4j.unlock;

/**
 * Actions supported by appendable token (AT) unlock scripts.
 *
 * <p>Each action's value is pushed as the last item in the unlock script,
 * where the PP1 AT lock script uses it as a dispatch selector.
 *
 * <ul>
 *   <li>{@link #ISSUANCE} (0) — Create a new appendable token.</li>
 *   <li>{@link #STAMP} (1) — Append a stamp (metadata entry) to the token.</li>
 *   <li>{@link #REDEEM} (2) — Redeem the token after the stamp threshold is met.</li>
 *   <li>{@link #TRANSFER} (3) — Transfer ownership to a new owner.</li>
 *   <li>{@link #BURN} (4) — Permanently destroy the token.</li>
 * </ul>
 *
 * @see PP1AtUnlockBuilder
 */
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
