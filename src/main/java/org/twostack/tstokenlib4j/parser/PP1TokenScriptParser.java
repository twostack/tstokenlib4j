package org.twostack.tstokenlib4j.parser;

import org.twostack.bitcoin4j.script.Script;

import java.util.Optional;

/**
 * Extracts ownerPKH and tokenId from any PP1* locking script.
 *
 * <p>All PP1* lock scripts (FT, NFT, RFT, RNFT, SM, AT) share a common prefix layout:
 * <pre>
 *   byte[0]      = 0x14 (push 20 bytes)
 *   byte[1..20]  = ownerPKH
 *   byte[21]     = 0x20 (push 32 bytes)
 *   byte[22..53] = tokenId
 *   byte[54+]    = archetype-specific fields
 * </pre>
 *
 * <p>Usage:
 * <pre>{@code
 * Script lockingScript = ...; // any PP1* locking script
 * Optional<TokenScriptInfo> info = PP1TokenScriptParser.parse(lockingScript);
 * info.ifPresent(i -> {
 *     byte[] ownerPKH = i.ownerPKH();
 *     byte[] tokenId = i.tokenId();
 * });
 * }</pre>
 *
 * @since 0.1.0
 * @deprecated Use {@link org.twostack.bitcoin4j.script.ScriptTemplateRegistry#identifyScript}
 *             with the PP1 templates registered via {@link PP1TemplateRegistrar#registerAll()}.
 *             The typed ScriptInfo subclasses (e.g. {@link PP1NftScriptInfo}) provide
 *             archetype-specific field extraction beyond just ownerPKH and tokenId.
 * @see <a href="https://github.com/twostack/tsl1">TSL1 Specification</a>
 */
@Deprecated
public class PP1TokenScriptParser {

    /** Minimum script length: 1 + 20 + 1 + 32 = 54 bytes. */
    private static final int MIN_LENGTH = 54;

    /** OP_PUSH 20 bytes. */
    private static final byte PUSH_20 = 0x14;

    /** OP_PUSH 32 bytes. */
    private static final byte PUSH_32 = 0x20;

    public record TokenScriptInfo(byte[] ownerPKH, byte[] tokenId) {}

    /**
     * Extract ownerPKH + tokenId from any PP1* locking script.
     *
     * @param script the locking script
     * @return parsed info, or empty if the script does not match the PP1* prefix pattern
     */
    public static Optional<TokenScriptInfo> parse(Script script) {
        if (script == null) {
            return Optional.empty();
        }
        return parse(script.getProgram());
    }

    /**
     * Extract ownerPKH + tokenId from any PP1* locking script bytes.
     *
     * @param scriptBytes raw script bytes
     * @return parsed info, or empty if the script does not match the PP1* prefix pattern
     */
    public static Optional<TokenScriptInfo> parse(byte[] scriptBytes) {
        if (scriptBytes == null || scriptBytes.length < MIN_LENGTH) {
            return Optional.empty();
        }

        if (scriptBytes[0] != PUSH_20 || scriptBytes[21] != PUSH_32) {
            return Optional.empty();
        }

        byte[] ownerPKH = new byte[20];
        System.arraycopy(scriptBytes, 1, ownerPKH, 0, 20);

        byte[] tokenId = new byte[32];
        System.arraycopy(scriptBytes, 22, tokenId, 0, 32);

        return Optional.of(new TokenScriptInfo(ownerPKH, tokenId));
    }
}
