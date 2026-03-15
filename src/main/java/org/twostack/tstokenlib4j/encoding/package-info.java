/**
 * Bitcoin script data encoding utilities for TSL1 token scripts.
 *
 * <p>Provides encoders for converting token parameters into the byte formats
 * required by locking script templates:
 * <ul>
 *   <li>{@link org.twostack.tstokenlib4j.encoding.AmountEncoder} — 8-byte LE encoding for fungible token amounts</li>
 *   <li>{@link org.twostack.tstokenlib4j.encoding.PushdataEncoder} — Bitcoin pushdata framing for PP2 template parameters</li>
 *   <li>{@link org.twostack.tstokenlib4j.encoding.ScriptNumberEncoder} — Bitcoin script number encoding for PP2 numeric parameters</li>
 * </ul>
 */
package org.twostack.tstokenlib4j.encoding;
