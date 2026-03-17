package org.twostack.tstokenlib4j.plugin;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.twostack.bitcoin4j.params.NetworkAddressType;
import org.twostack.libspiffy4j.plugin.PluginRegistry;
import org.twostack.libspiffy4j.plugin.TransactionBuilderPlugin;
import org.twostack.tstokenlib4j.lock.PP1NftLockBuilder;

import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test that registers the TSL1 plugin with libspiffy4j's PluginRegistry
 * and verifies the full identification and metadata extraction pipeline.
 */
public class Tsl1PluginRegistryIntegrationTest {

    private PluginRegistry registry;

    private static final byte[] TEST_PKH = new byte[20];
    private static final byte[] TEST_TOKEN_ID = new byte[32];
    private static final byte[] TEST_RABIN_PKH = new byte[20];

    static {
        for (int i = 0; i < 20; i++) { TEST_PKH[i] = (byte)(i + 1); }
        for (int i = 0; i < 32; i++) { TEST_TOKEN_ID[i] = (byte)(i + 0x10); }
        for (int i = 0; i < 20; i++) { TEST_RABIN_PKH[i] = (byte)(i + 0x20); }
    }

    @Before
    public void setup() {
        registry = new PluginRegistry();
        registry.register(new Tsl1TransactionBuilderPlugin(NetworkAddressType.TEST_PKH));
    }

    @After
    public void cleanup() {
        registry.clear();
    }

    @Test
    public void identifyScript_returnsTsl1PluginId() {
        byte[] nftScript = new PP1NftLockBuilder(TEST_PKH, TEST_TOKEN_ID, TEST_RABIN_PKH)
                .getLockingScript().getProgram();

        Optional<PluginRegistry.PluginIdentification> id = registry.identifyScript(nftScript);

        assertThat(id).isPresent();
        assertThat(id.get().pluginId()).isEqualTo("tsl1");
        assertThat(id.get().scriptType()).isEqualTo("pp1_nft");
    }

    @Test
    public void getTransactionBuilderPlugin_returnsCastedPlugin() {
        Optional<TransactionBuilderPlugin> plugin = registry.getTransactionBuilderPlugin("tsl1");

        assertThat(plugin).isPresent();
        assertThat(plugin.get()).isInstanceOf(Tsl1TransactionBuilderPlugin.class);
        assertThat(plugin.get().supportedActions()).contains("nft.issue");
    }

    @Test
    public void extractMetadata_viaRegistry_returnsOwnerAddress() {
        byte[] nftScript = new PP1NftLockBuilder(TEST_PKH, TEST_TOKEN_ID, TEST_RABIN_PKH)
                .getLockingScript().getProgram();

        Optional<PluginRegistry.PluginIdentification> id = registry.identifyScript(nftScript);
        assertThat(id).isPresent();

        // Get the plugin and extract metadata
        var plugin = registry.getPlugin(id.get().pluginId()).orElseThrow();
        Map<String, Object> metadata = plugin.extractMetadata(nftScript);

        assertThat(metadata).containsKey("ownerAddress");
        String ownerAddr = metadata.get("ownerAddress").toString();
        assertThat(ownerAddr.startsWith("m") || ownerAddr.startsWith("n"))
                .as("testnet address should start with 'm' or 'n'").isTrue();
        assertThat(metadata).containsEntry("scriptType", "pp1_nft");
        assertThat(metadata).containsKey("tokenId");
    }

    @Test
    public void identifyScript_returnsEmpty_forNonTokenScript() {
        byte[] randomScript = new byte[]{0x76, (byte)0xa9, 0x14};  // truncated P2PKH
        Optional<PluginRegistry.PluginIdentification> id = registry.identifyScript(randomScript);
        assertThat(id).isEmpty();
    }
}
