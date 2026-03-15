package org.twostack.tstokenlib4j.unlock;

/**
 * Actions supported by restricted fungible token (RFT) unlock scripts.
 *
 * <p>Each action's value is pushed as the last item in the unlock script,
 * where the PP1 RFT lock script uses it as a dispatch selector.
 *
 * <ul>
 *   <li>{@link #MINT} (0) — Create new restricted fungible tokens.</li>
 *   <li>{@link #TRANSFER} (1) — Transfer the full token amount to a new owner.</li>
 *   <li>{@link #SPLIT_TRANSFER} (2) — Split the token amount between a recipient and change output.</li>
 *   <li>{@link #MERGE} (3) — Combine two token UTXOs into one with the summed amount.</li>
 *   <li>{@link #REDEEM} (4) — Redeem the tokens (restricted action requiring authorization).</li>
 *   <li>{@link #BURN} (5) — Permanently destroy the tokens.</li>
 * </ul>
 *
 * @see PP1RftUnlockBuilder
 */
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
