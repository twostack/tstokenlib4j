package org.twostack.tstokenlib4j.parser;

import org.junit.Before;
import org.junit.Test;
import org.twostack.bitcoin4j.ECKey;
import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptInfo;
import org.twostack.bitcoin4j.script.ScriptTemplate;
import org.twostack.bitcoin4j.script.ScriptTemplateRegistry;
import org.twostack.tstokenlib4j.lock.*;

import java.util.List;

import static org.junit.Assert.*;

public class PP1ScriptTemplateTest {

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

    private static final byte[] ISSUER_PKH = new byte[]{
            (byte) 0xee, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, (byte) 0xff
    };

    private static final byte[] MERCHANT_PKH = RABIN_PKH;
    private static final byte[] CUSTOMER_PKH = ISSUER_PKH;

    private static final byte[] STAMPS_HASH = new byte[32]; // zeros
    private static final byte[] COMMITMENT_HASH = new byte[32]; // zeros

    private Script nftScript;
    private Script ftScript;
    private Script atScript;
    private Script smScript;
    private Script rnftScript;
    private Script rftScript;

    @Before
    public void setUp() {
        PP1TemplateRegistrar.registerAll();

        nftScript = new PP1NftLockBuilder(OWNER_PKH, TOKEN_ID, RABIN_PKH).getLockingScript();
        ftScript = new PP1FtLockBuilder(OWNER_PKH, TOKEN_ID, RABIN_PKH, 1000L).getLockingScript();
        atScript = new PP1AtLockBuilder(OWNER_PKH, TOKEN_ID, ISSUER_PKH, RABIN_PKH, 5, 10, STAMPS_HASH).getLockingScript();
        smScript = new PP1SmLockBuilder(OWNER_PKH, TOKEN_ID, MERCHANT_PKH, CUSTOMER_PKH, RABIN_PKH,
                1, 3, COMMITMENT_HASH, 0x3F, 144).getLockingScript();
        rnftScript = new PP1RnftLockBuilder(OWNER_PKH, TOKEN_ID, RABIN_PKH, 7).getLockingScript();
        rftScript = new PP1RftLockBuilder(OWNER_PKH, TOKEN_ID, RABIN_PKH, 7, 5000L, 0, new byte[32]).getLockingScript();
    }

    // --- NFT ---

    @Test
    public void nftTemplate_matchesNftScript() {
        assertTrue(new PP1NftTemplate().matches(nftScript));
    }

    @Test
    public void nftTemplate_doesNotMatchOtherScripts() {
        PP1NftTemplate t = new PP1NftTemplate();
        assertFalse(t.matches(ftScript));
        assertFalse(t.matches(atScript));
        assertFalse(t.matches(smScript));
        assertFalse(t.matches(rnftScript));
        assertFalse(t.matches(rftScript));
    }

    @Test
    public void nftTemplate_extractsCorrectInfo() {
        PP1NftScriptInfo info = (PP1NftScriptInfo) new PP1NftTemplate().extractScriptInfo(nftScript);
        assertArrayEquals(OWNER_PKH, info.getOwnerPKH());
        assertArrayEquals(TOKEN_ID, info.getTokenId());
        assertArrayEquals(RABIN_PKH, info.getRabinPKH());
        assertEquals("PP1_NFT", info.getType());
    }

    // --- FT ---

    @Test
    public void ftTemplate_matchesFtScript() {
        assertTrue(new PP1FtTemplate().matches(ftScript));
    }

    @Test
    public void ftTemplate_doesNotMatchOtherScripts() {
        PP1FtTemplate t = new PP1FtTemplate();
        assertFalse(t.matches(nftScript));
        assertFalse(t.matches(atScript));
        assertFalse(t.matches(smScript));
        assertFalse(t.matches(rnftScript));
        assertFalse(t.matches(rftScript));
    }

    @Test
    public void ftTemplate_extractsCorrectInfo() {
        PP1FtScriptInfo info = (PP1FtScriptInfo) new PP1FtTemplate().extractScriptInfo(ftScript);
        assertArrayEquals(OWNER_PKH, info.getOwnerPKH());
        assertArrayEquals(TOKEN_ID, info.getTokenId());
        assertEquals(1000L, info.getAmount());
        assertEquals("PP1_FT", info.getType());
    }

    // --- AT ---

    @Test
    public void atTemplate_matchesAtScript() {
        assertTrue(new PP1AtTemplate().matches(atScript));
    }

    @Test
    public void atTemplate_doesNotMatchOtherScripts() {
        PP1AtTemplate t = new PP1AtTemplate();
        assertFalse(t.matches(nftScript));
        assertFalse(t.matches(ftScript));
        assertFalse(t.matches(smScript));
        assertFalse(t.matches(rnftScript));
        assertFalse(t.matches(rftScript));
    }

    @Test
    public void atTemplate_extractsCorrectInfo() {
        PP1AtScriptInfo info = (PP1AtScriptInfo) new PP1AtTemplate().extractScriptInfo(atScript);
        assertArrayEquals(OWNER_PKH, info.getOwnerPKH());
        assertArrayEquals(TOKEN_ID, info.getTokenId());
        assertArrayEquals(ISSUER_PKH, info.getIssuerPKH());
        assertEquals(5, info.getStampCount());
        assertEquals(10, info.getThreshold());
        assertArrayEquals(STAMPS_HASH, info.getStampsHash());
        assertEquals("PP1_AT", info.getType());
    }

    // --- SM ---

    @Test
    public void smTemplate_matchesSmScript() {
        assertTrue(new PP1SmTemplate().matches(smScript));
    }

    @Test
    public void smTemplate_doesNotMatchOtherScripts() {
        PP1SmTemplate t = new PP1SmTemplate();
        assertFalse(t.matches(nftScript));
        assertFalse(t.matches(ftScript));
        assertFalse(t.matches(atScript));
        assertFalse(t.matches(rnftScript));
        assertFalse(t.matches(rftScript));
    }

    @Test
    public void smTemplate_extractsCorrectInfo() {
        PP1SmScriptInfo info = (PP1SmScriptInfo) new PP1SmTemplate().extractScriptInfo(smScript);
        assertArrayEquals(OWNER_PKH, info.getOwnerPKH());
        assertArrayEquals(TOKEN_ID, info.getTokenId());
        assertArrayEquals(MERCHANT_PKH, info.getMerchantPKH());
        assertArrayEquals(CUSTOMER_PKH, info.getCustomerPKH());
        assertEquals(1, info.getCurrentState());
        assertEquals(3, info.getMilestoneCount());
        assertArrayEquals(COMMITMENT_HASH, info.getCommitmentHash());
        assertEquals(0x3F, info.getTransitionBitmask());
        assertEquals(144, info.getTimeoutDelta());
        assertEquals("PP1_SM", info.getType());
    }

    // --- RNFT ---

    @Test
    public void rnftTemplate_matchesRnftScript() {
        assertTrue(new PP1RnftTemplate().matches(rnftScript));
    }

    @Test
    public void rnftTemplate_doesNotMatchOtherScripts() {
        PP1RnftTemplate t = new PP1RnftTemplate();
        assertFalse(t.matches(nftScript));
        assertFalse(t.matches(ftScript));
        assertFalse(t.matches(atScript));
        assertFalse(t.matches(smScript));
        assertFalse(t.matches(rftScript));
    }

    @Test
    public void rnftTemplate_extractsCorrectInfo() {
        PP1RnftScriptInfo info = (PP1RnftScriptInfo) new PP1RnftTemplate().extractScriptInfo(rnftScript);
        assertArrayEquals(OWNER_PKH, info.getOwnerPKH());
        assertArrayEquals(TOKEN_ID, info.getTokenId());
        assertArrayEquals(RABIN_PKH, info.getRabinPKH());
        assertEquals(7, info.getFlags());
        assertEquals("PP1_RNFT", info.getType());
    }

    // --- RFT ---

    @Test
    public void rftTemplate_matchesRftScript() {
        assertTrue(new PP1RftTemplate().matches(rftScript));
    }

    @Test
    public void rftTemplate_doesNotMatchOtherScripts() {
        PP1RftTemplate t = new PP1RftTemplate();
        assertFalse(t.matches(nftScript));
        assertFalse(t.matches(ftScript));
        assertFalse(t.matches(atScript));
        assertFalse(t.matches(smScript));
        assertFalse(t.matches(rnftScript));
    }

    @Test
    public void rftTemplate_extractsCorrectInfo() {
        PP1RftScriptInfo info = (PP1RftScriptInfo) new PP1RftTemplate().extractScriptInfo(rftScript);
        assertArrayEquals(OWNER_PKH, info.getOwnerPKH());
        assertArrayEquals(TOKEN_ID, info.getTokenId());
        assertArrayEquals(RABIN_PKH, info.getRabinPKH());
        assertEquals(7, info.getFlags());
        assertEquals(5000L, info.getAmount());
        assertEquals("PP1_RFT", info.getType());
    }

    // --- Registry identification ---

    @Test
    public void registry_identifiesNft() {
        ScriptTemplate found = ScriptTemplateRegistry.getInstance().identifyScript(nftScript);
        assertNotNull(found);
        assertEquals("PP1_NFT", found.getName());
    }

    @Test
    public void registry_identifiesFt() {
        ScriptTemplate found = ScriptTemplateRegistry.getInstance().identifyScript(ftScript);
        assertNotNull(found);
        assertEquals("PP1_FT", found.getName());
    }

    @Test
    public void registry_identifiesAt() {
        ScriptTemplate found = ScriptTemplateRegistry.getInstance().identifyScript(atScript);
        assertNotNull(found);
        assertEquals("PP1_AT", found.getName());
    }

    @Test
    public void registry_identifiesSm() {
        ScriptTemplate found = ScriptTemplateRegistry.getInstance().identifyScript(smScript);
        assertNotNull(found);
        assertEquals("PP1_SM", found.getName());
    }

    @Test
    public void registry_identifiesRnft() {
        ScriptTemplate found = ScriptTemplateRegistry.getInstance().identifyScript(rnftScript);
        assertNotNull(found);
        assertEquals("PP1_RNFT", found.getName());
    }

    @Test
    public void registry_identifiesRft() {
        ScriptTemplate found = ScriptTemplateRegistry.getInstance().identifyScript(rftScript);
        assertNotNull(found);
        assertEquals("PP1_RFT", found.getName());
    }

    // --- canBeSatisfiedBy ---

    @Test
    public void canBeSatisfiedBy_matchingKey() {
        ECKey key = new ECKey();
        byte[] pkh = key.getPubKeyHash();
        Script script = new PP1NftLockBuilder(pkh, TOKEN_ID, RABIN_PKH).getLockingScript();
        PP1NftTemplate template = new PP1NftTemplate();
        assertTrue(template.canBeSatisfiedBy(List.of(PublicKey.fromBytes(key.getPubKey())), script));
    }

    @Test
    public void canBeSatisfiedBy_nonMatchingKey() {
        ECKey key1 = new ECKey();
        ECKey key2 = new ECKey();
        byte[] pkh1 = key1.getPubKeyHash();
        Script script = new PP1NftLockBuilder(pkh1, TOKEN_ID, RABIN_PKH).getLockingScript();
        PP1NftTemplate template = new PP1NftTemplate();
        assertFalse(template.canBeSatisfiedBy(List.of(PublicKey.fromBytes(key2.getPubKey())), script));
    }

    // --- Registry extractScriptInfo ---

    @Test
    public void registry_extractsScriptInfo() {
        ScriptInfo info = ScriptTemplateRegistry.getInstance().extractScriptInfo(nftScript);
        assertNotNull(info);
        assertEquals("PP1_NFT", info.getType());
        assertTrue(info instanceof PP1NftScriptInfo);
    }
}
