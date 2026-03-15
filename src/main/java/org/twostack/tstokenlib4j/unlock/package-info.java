/**
 * Unlocking script (scriptSig) builders and action enums for all TSL1 token archetypes.
 *
 * <p>Unlock builders generate the unlocking scripts that satisfy the corresponding
 * locking scripts. Each builder uses the factory method pattern with static methods
 * named {@code forAction()} (e.g., {@code forMint()}, {@code forTransfer()}, {@code forBurn()}).
 *
 * <p>Action enums define the supported operations for each token type:
 * <ul>
 *   <li>{@link org.twostack.tstokenlib4j.unlock.TokenAction} — NFT actions</li>
 *   <li>{@link org.twostack.tstokenlib4j.unlock.FungibleTokenAction} — FT actions</li>
 *   <li>{@link org.twostack.tstokenlib4j.unlock.RestrictedTokenAction} — RNFT actions</li>
 *   <li>{@link org.twostack.tstokenlib4j.unlock.RestrictedFungibleTokenAction} — RFT actions</li>
 *   <li>{@link org.twostack.tstokenlib4j.unlock.StateMachineAction} — SM actions</li>
 *   <li>{@link org.twostack.tstokenlib4j.unlock.AppendableTokenAction} — AT actions</li>
 * </ul>
 */
package org.twostack.tstokenlib4j.unlock;
