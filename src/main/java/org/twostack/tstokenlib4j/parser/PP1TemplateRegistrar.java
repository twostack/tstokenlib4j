package org.twostack.tstokenlib4j.parser;

import org.twostack.bitcoin4j.script.ScriptTemplateRegistry;

/**
 * Registers all 6 PP1 script templates with the Bitcoin4J {@link ScriptTemplateRegistry}.
 *
 * <p>Call {@link #registerAll()} once at application startup. Registration order is
 * most-specific first (AT, SM, RNFT, RFT) before the base patterns (NFT, FT),
 * since {@link ScriptTemplateRegistry#identifyScript} returns the first match.</p>
 */
public class PP1TemplateRegistrar {

    public static void registerAll() {
        ScriptTemplateRegistry registry = ScriptTemplateRegistry.getInstance();
        // Most specific first
        registry.register(new PP1AtTemplate());
        registry.register(new PP1SmTemplate());
        registry.register(new PP1RnftTemplate());
        registry.register(new PP1RftTemplate());
        registry.register(new PP1NftTemplate());
        registry.register(new PP1FtTemplate());
        // Utility scripts
        registry.register(new ModP2PKHTemplate());
    }
}
