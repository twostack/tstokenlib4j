package org.twostack.tstokenlib4j.parser;

import org.junit.Before;
import org.junit.Test;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptInfo;
import org.twostack.tstokenlib4j.lock.ModP2PKHLockBuilder;
import org.twostack.tstokenlib4j.lock.PP1AtLockBuilder;

import static org.junit.Assert.*;

public class ModP2PKHTemplateTest {

    private static final byte[] OWNER_PKH = new byte[]{
            (byte) 0xaa, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, (byte) 0xbb
    };

    private ModP2PKHTemplate template;

    @Before
    public void setUp() {
        PP1TemplateRegistrar.registerAll();
        template = new ModP2PKHTemplate();
    }

    @Test
    public void matches_modP2PKHScript() {
        Script script = new ModP2PKHLockBuilder(OWNER_PKH).getLockingScript();
        assertTrue(template.matches(script));
    }

    @Test
    public void rejectsStandardP2PKH() {
        // Standard P2PKH: 76 a9 14 <20B> 88 ac (25 bytes, no OP_SWAP prefix)
        byte[] p2pkh = new byte[25];
        p2pkh[0] = 0x76;
        p2pkh[1] = (byte) 0xa9;
        p2pkh[2] = 0x14;
        System.arraycopy(OWNER_PKH, 0, p2pkh, 3, 20);
        p2pkh[23] = (byte) 0x88;
        p2pkh[24] = (byte) 0xac;
        assertFalse(template.matches(new Script(p2pkh)));
    }

    @Test
    public void rejectsPP1Script() {
        byte[] tokenId = new byte[32];
        byte[] rabinPKH = new byte[20];
        Script pp1 = new PP1AtLockBuilder(OWNER_PKH, tokenId, OWNER_PKH, rabinPKH,
                0, 10, new byte[32]).getLockingScript();
        assertFalse(template.matches(pp1));
    }

    @Test
    public void extractsCorrectOwnerPKH() {
        Script script = new ModP2PKHLockBuilder(OWNER_PKH).getLockingScript();
        ScriptInfo info = template.extractScriptInfo(script);

        assertNotNull(info);
        assertTrue(info instanceof ModP2PKHScriptInfo);
        assertArrayEquals(OWNER_PKH, ((ModP2PKHScriptInfo) info).getOwnerPKH());
    }

    @Test
    public void getName_returnsModP2PKH() {
        assertEquals("ModP2PKH", template.getName());
    }
}
