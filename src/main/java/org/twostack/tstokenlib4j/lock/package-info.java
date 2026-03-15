/**
 * Locking script (scriptPubKey) builders for all TSL1 token archetypes.
 *
 * <p>Lock builders generate the locking scripts that encode token state and validation logic.
 * The library uses a three-layer architecture:
 * <ul>
 *   <li><b>PP1</b> — Token logic layer with inductive proof validation
 *       ({@link org.twostack.tstokenlib4j.lock.PP1FtLockBuilder},
 *        {@link org.twostack.tstokenlib4j.lock.PP1NftLockBuilder},
 *        {@link org.twostack.tstokenlib4j.lock.PP1RftLockBuilder},
 *        {@link org.twostack.tstokenlib4j.lock.PP1RnftLockBuilder},
 *        {@link org.twostack.tstokenlib4j.lock.PP1SmLockBuilder},
 *        {@link org.twostack.tstokenlib4j.lock.PP1AtLockBuilder})</li>
 *   <li><b>PP2</b> — Witness layer anchoring to specific outpoints
 *       ({@link org.twostack.tstokenlib4j.lock.PP2LockBuilder},
 *        {@link org.twostack.tstokenlib4j.lock.PP2FtLockBuilder})</li>
 *   <li><b>PP3 / Partial Witness</b> — Funding layer
 *       ({@link org.twostack.tstokenlib4j.lock.PartialWitnessLockBuilder},
 *        {@link org.twostack.tstokenlib4j.lock.PartialWitnessFtLockBuilder})</li>
 * </ul>
 *
 * <p>Additionally, {@link org.twostack.tstokenlib4j.lock.ModP2PKHLockBuilder} provides
 * a modified P2PKH utility script, and {@link org.twostack.tstokenlib4j.lock.MetadataLockBuilder}
 * produces OP_FALSE OP_RETURN metadata outputs.
 */
package org.twostack.tstokenlib4j.lock;
