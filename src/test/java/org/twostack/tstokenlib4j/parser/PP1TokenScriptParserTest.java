package org.twostack.tstokenlib4j.parser;

import org.junit.Test;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.tstokenlib4j.lock.*;
import org.twostack.tstokenlib4j.parser.PP1TokenScriptParser.TokenScriptInfo;

import java.util.Optional;

import static org.junit.Assert.*;

public class PP1TokenScriptParserTest {

    private static final byte[] OWNER_PKH = new byte[]{
            (byte) 0xaa, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, (byte) 0xbb
    };

    private static final byte[] TOKEN_ID = new byte[]{
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };

    private static final byte[] RABIN_PKH = new byte[]{
            (byte) 0xcc, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, (byte) 0xdd
    };

    private static final byte[] STAMPS_HASH = new byte[]{
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    private static final byte[] COMMITMENT_HASH = STAMPS_HASH;

    @Test
    public void testNftScriptExtraction() {
        PP1NftLockBuilder builder = new PP1NftLockBuilder(OWNER_PKH, TOKEN_ID, RABIN_PKH);
        Script script = builder.getLockingScript();

        Optional<TokenScriptInfo> result = PP1TokenScriptParser.parse(script);

        assertTrue(result.isPresent());
        assertArrayEquals(OWNER_PKH, result.get().ownerPKH());
        assertArrayEquals(TOKEN_ID, result.get().tokenId());
    }

    @Test
    public void testFtScriptExtraction() {
        PP1FtLockBuilder builder = new PP1FtLockBuilder(OWNER_PKH, TOKEN_ID, 1000L);
        Script script = builder.getLockingScript();

        Optional<TokenScriptInfo> result = PP1TokenScriptParser.parse(script);

        assertTrue(result.isPresent());
        assertArrayEquals(OWNER_PKH, result.get().ownerPKH());
        assertArrayEquals(TOKEN_ID, result.get().tokenId());
    }

    @Test
    public void testAtScriptExtraction() {
        PP1AtLockBuilder builder = new PP1AtLockBuilder(
                OWNER_PKH, TOKEN_ID, RABIN_PKH, 0, 10, STAMPS_HASH);
        Script script = builder.getLockingScript();

        Optional<TokenScriptInfo> result = PP1TokenScriptParser.parse(script);

        assertTrue(result.isPresent());
        assertArrayEquals(OWNER_PKH, result.get().ownerPKH());
        assertArrayEquals(TOKEN_ID, result.get().tokenId());
    }

    @Test
    public void testSmScriptExtraction() {
        PP1SmLockBuilder builder = new PP1SmLockBuilder(
                OWNER_PKH, TOKEN_ID, RABIN_PKH, RABIN_PKH,
                0, 0, COMMITMENT_HASH, 0xFF, 600);
        Script script = builder.getLockingScript();

        Optional<TokenScriptInfo> result = PP1TokenScriptParser.parse(script);

        assertTrue(result.isPresent());
        assertArrayEquals(OWNER_PKH, result.get().ownerPKH());
        assertArrayEquals(TOKEN_ID, result.get().tokenId());
    }

    @Test
    public void testP2pkhScriptReturnsEmpty() {
        // A P2PKH script starts with OP_DUP (0x76), not 0x14
        byte[] p2pkhScript = new byte[]{
                0x76, (byte) 0xa9, 0x14,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
                (byte) 0x88, (byte) 0xac
        };

        Optional<TokenScriptInfo> result = PP1TokenScriptParser.parse(p2pkhScript);

        assertFalse(result.isPresent());
    }

    @Test
    public void testEmptyAndShortScriptsReturnEmpty() {
        assertFalse(PP1TokenScriptParser.parse((byte[]) null).isPresent());
        assertFalse(PP1TokenScriptParser.parse(new byte[0]).isPresent());
        assertFalse(PP1TokenScriptParser.parse(new byte[53]).isPresent());
    }
}
