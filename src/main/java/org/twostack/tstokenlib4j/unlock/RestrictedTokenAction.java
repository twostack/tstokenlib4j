package org.twostack.tstokenlib4j.unlock;

/**
 * Actions supported by restricted non-fungible token (RNFT) unlock scripts.
 *
 * <p>Each action's value is pushed as the last item in the unlock script,
 * where the PP1 RNFT lock script uses it as a dispatch selector.
 *
 * <ul>
 *   <li>{@link #ISSUANCE} (0) — Create a new restricted NFT with Rabin identity anchoring.</li>
 *   <li>{@link #TRANSFER} (1) — Transfer ownership to a new owner.</li>
 *   <li>{@link #REDEEM} (2) — Redeem the token (restricted action requiring authorization).</li>
 *   <li>{@link #BURN} (3) — Permanently destroy the token.</li>
 * </ul>
 *
 * @see PP1RnftUnlockBuilder
 */
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
