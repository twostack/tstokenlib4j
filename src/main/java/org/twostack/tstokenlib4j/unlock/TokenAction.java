package org.twostack.tstokenlib4j.unlock;

/**
 * Actions supported by non-fungible token (NFT) unlock scripts.
 *
 * <p>Each action's {@link #opValue} is pushed as the last item in the unlock script,
 * where the PP1 NFT lock script uses it as a dispatch selector.
 *
 * <ul>
 *   <li>{@link #ISSUANCE} (0) — Create a new NFT. Requires Rabin signature and identity anchoring.</li>
 *   <li>{@link #TRANSFER} (1) — Transfer ownership to a new owner. Requires owner signature.</li>
 *   <li>{@link #BURN} (2) — Permanently destroy the token. Requires owner signature.</li>
 * </ul>
 *
 * @see PP1NftUnlockBuilder
 */
public enum TokenAction {
    ISSUANCE(0), TRANSFER(1), BURN(2);

    public final int opValue;

    TokenAction(int opValue) {
        this.opValue = opValue;
    }
}
