/**
 * Java library for building and unlocking Bitcoin token scripts per the
 * <a href="https://github.com/twostack/tsl1">TSL1 (Two Stack Language) token specification</a>.
 *
 * <p>The library supports six token archetypes: Fungible Tokens (FT), Non-Fungible Tokens (NFT),
 * Restricted Fungible Tokens (RFT), Restricted Non-Fungible Tokens (RNFT), State Machines (SM),
 * and Appendable Tokens (AT).
 *
 * <h2>Packages</h2>
 * <ul>
 *   <li>{@link org.twostack.tstokenlib4j.encoding} — Bitcoin script data encoding utilities</li>
 *   <li>{@link org.twostack.tstokenlib4j.lock} — Locking script (scriptPubKey) builders</li>
 *   <li>{@link org.twostack.tstokenlib4j.unlock} — Unlocking script (scriptSig) builders and action enums</li>
 *   <li>{@link org.twostack.tstokenlib4j.parser} — Token script parsers</li>
 *   <li>{@link org.twostack.tstokenlib4j.template} — JSON template loading and caching</li>
 * </ul>
 */
package org.twostack.tstokenlib4j;
