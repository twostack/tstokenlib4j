package org.twostack.tstokenlib4j.lock;

import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.transaction.LockingScriptBuilder;
import org.twostack.tstokenlib4j.template.TemplateDescriptor;
import org.twostack.tstokenlib4j.template.TemplateLoader;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Builds the PP1 (Plugpoint 1) locking script for a TSL1 state-machine token (SM).
 *
 * <p>A state-machine token models a multi-step workflow (e.g., an escrow or milestone-based
 * payment) between a merchant and a customer. The script encodes the current state, the
 * allowed state transitions (as a bitmask), a milestone count, a commitment hash, and a
 * timeout delta, alongside the public-key hashes that identify the owner, merchant, and
 * customer.</p>
 *
 * <p>The builder loads the pre-compiled script template from {@code templates/sm/pp1_sm.json}
 * and performs raw hex substitution. Integer fields are encoded as single bytes
 * ({@code currentState}, {@code milestoneCount}, {@code transitionBitmask}) or as 4-byte
 * little-endian values ({@code timeoutDelta}).</p>
 *
 * <p>Because this is a PP1-style template, pushdata prefixes are baked into the template
 * hex; only the raw parameter bytes are substituted.</p>
 *
 * @see <a href="https://github.com/twostack/tsl1">TSL1 Specification</a>
 */
public class PP1SmLockBuilder extends LockingScriptBuilder {

    private final byte[] ownerPKH;
    private final byte[] tokenId;
    private final byte[] merchantPKH;
    private final byte[] customerPKH;
    private final byte[] rabinPubKeyHash;
    private final int currentState;
    private final int milestoneCount;
    private final byte[] commitmentHash;
    private final int transitionBitmask;
    private final int timeoutDelta;

    /**
     * Creates a new PP1 state-machine lock builder.
     *
     * @param ownerPKH          the HASH160 of the token owner's public key (must be exactly 20 bytes)
     * @param tokenId           the unique 256-bit token identifier (must be exactly 32 bytes)
     * @param merchantPKH       the HASH160 of the merchant's public key (must be exactly 20 bytes)
     * @param customerPKH       the HASH160 of the customer's public key (must be exactly 20 bytes)
     * @param currentState      the current state index, encoded as a single byte
     * @param milestoneCount    the total number of milestones, encoded as a single byte
     * @param commitmentHash    a 256-bit hash committing to the state-machine definition (must be exactly 32 bytes)
     * @param transitionBitmask a bitmask of allowed state transitions, encoded as a single byte
     * @param timeoutDelta      the timeout delta in seconds, encoded as a 4-byte little-endian integer
     * @throws IllegalArgumentException if any byte-array parameter is null or has an incorrect length
     */
    public PP1SmLockBuilder(byte[] ownerPKH, byte[] tokenId,
                            byte[] merchantPKH, byte[] customerPKH,
                            byte[] rabinPubKeyHash,
                            int currentState, int milestoneCount,
                            byte[] commitmentHash, int transitionBitmask,
                            int timeoutDelta) {
        if (ownerPKH == null || ownerPKH.length != 20) {
            throw new IllegalArgumentException("ownerPKH must be 20 bytes");
        }
        if (tokenId == null || tokenId.length != 32) {
            throw new IllegalArgumentException("tokenId must be 32 bytes");
        }
        if (merchantPKH == null || merchantPKH.length != 20) {
            throw new IllegalArgumentException("merchantPKH must be 20 bytes");
        }
        if (customerPKH == null || customerPKH.length != 20) {
            throw new IllegalArgumentException("customerPKH must be 20 bytes");
        }
        if (rabinPubKeyHash == null || rabinPubKeyHash.length != 20) {
            throw new IllegalArgumentException("rabinPubKeyHash must be 20 bytes");
        }
        if (commitmentHash == null || commitmentHash.length != 32) {
            throw new IllegalArgumentException("commitmentHash must be 32 bytes");
        }
        this.ownerPKH = ownerPKH.clone();
        this.tokenId = tokenId.clone();
        this.merchantPKH = merchantPKH.clone();
        this.customerPKH = customerPKH.clone();
        this.rabinPubKeyHash = rabinPubKeyHash.clone();
        this.currentState = currentState;
        this.milestoneCount = milestoneCount;
        this.commitmentHash = commitmentHash.clone();
        this.transitionBitmask = transitionBitmask;
        this.timeoutDelta = timeoutDelta;
    }

    /**
     * Builds the PP1 state-machine locking script by loading the template from
     * {@code templates/sm/pp1_sm.json} and substituting all nine parameter placeholders:
     * {@code {{ownerPKH}}}, {@code {{tokenId}}}, {@code {{merchantPKH}}},
     * {@code {{customerPKH}}}, {@code {{currentState}}}, {@code {{milestoneCount}}},
     * {@code {{commitmentHash}}}, {@code {{transitionBitmask}}}, and {@code {{timeoutDelta}}}.
     *
     * @return the fully assembled locking {@link Script}
     */
    @Override
    public Script getLockingScript() {
        TemplateDescriptor td = TemplateLoader.load("templates/sm/pp1_sm.json");
        String hex = td.getHex();
        hex = hex.replace("{{ownerPKH}}", Utils.HEX.encode(ownerPKH));
        hex = hex.replace("{{tokenId}}", Utils.HEX.encode(tokenId));
        hex = hex.replace("{{merchantPKH}}", Utils.HEX.encode(merchantPKH));
        hex = hex.replace("{{customerPKH}}", Utils.HEX.encode(customerPKH));
        hex = hex.replace("{{rabinPubKeyHash}}", Utils.HEX.encode(rabinPubKeyHash));
        hex = hex.replace("{{currentState}}", encodeHexByte(currentState));
        hex = hex.replace("{{milestoneCount}}", encodeHexByte(milestoneCount));
        hex = hex.replace("{{commitmentHash}}", Utils.HEX.encode(commitmentHash));
        hex = hex.replace("{{transitionBitmask}}", encodeHexByte(transitionBitmask));
        hex = hex.replace("{{timeoutDelta}}", encodeLeUint32(timeoutDelta));
        return Script.fromByteArray(Utils.HEX.decode(hex));
    }

    private static String encodeHexByte(int value) {
        return String.format("%02x", value & 0xFF);
    }

    private static String encodeLeUint32(int value) {
        byte[] bytes = new byte[4];
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(value);
        return Utils.HEX.encode(bytes);
    }

    /** @return a defensive copy of the owner's public-key hash (20 bytes) */
    public byte[] getOwnerPKH() { return ownerPKH.clone(); }
    /** @return a defensive copy of the token identifier (32 bytes) */
    public byte[] getTokenId() { return tokenId.clone(); }
    /** @return a defensive copy of the merchant's public-key hash (20 bytes) */
    public byte[] getMerchantPKH() { return merchantPKH.clone(); }
    /** @return a defensive copy of the customer's public-key hash (20 bytes) */
    public byte[] getCustomerPKH() { return customerPKH.clone(); }
    /** @return a defensive copy of the Rabin oracle public-key hash (20 bytes) */
    public byte[] getRabinPubKeyHash() { return rabinPubKeyHash.clone(); }
    /** @return the current state index */
    public int getCurrentState() { return currentState; }
    /** @return the total milestone count */
    public int getMilestoneCount() { return milestoneCount; }
    /** @return a defensive copy of the commitment hash (32 bytes) */
    public byte[] getCommitmentHash() { return commitmentHash.clone(); }
    /** @return the allowed state-transition bitmask */
    public int getTransitionBitmask() { return transitionBitmask; }
    /** @return the timeout delta in seconds */
    public int getTimeoutDelta() { return timeoutDelta; }
}
