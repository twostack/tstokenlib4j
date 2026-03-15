package org.twostack.tstokenlib4j.unlock;

/**
 * Actions supported by fungible token (FT) unlock scripts.
 *
 * <p>Each action's {@link #opValue} is pushed as the last item in the unlock script,
 * where the PP1 FT lock script uses it as a dispatch selector.
 *
 * <ul>
 *   <li>{@link #MINT} (0) — Create new fungible tokens. No owner signature required.</li>
 *   <li>{@link #TRANSFER} (1) — Transfer the full token amount to a new owner.</li>
 *   <li>{@link #SPLIT_TRANSFER} (2) — Split the token amount between a recipient and change output.</li>
 *   <li>{@link #MERGE} (3) — Combine two token UTXOs into one with the summed amount.</li>
 *   <li>{@link #BURN} (4) — Permanently destroy the tokens.</li>
 * </ul>
 *
 * @see PP1FtUnlockBuilder
 */
public enum FungibleTokenAction {
    MINT(0), TRANSFER(1), SPLIT_TRANSFER(2), MERGE(3), BURN(4);

    public final int opValue;

    FungibleTokenAction(int opValue) {
        this.opValue = opValue;
    }
}
