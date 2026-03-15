package org.twostack.tstokenlib4j.template;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Loads and caches {@link TemplateDescriptor} instances from JSON template files
 * on the classpath.
 *
 * <p>Templates are loaded lazily on first access and cached indefinitely in a
 * {@link java.util.concurrent.ConcurrentHashMap} for thread-safe reuse.
 *
 * <p>Usage:
 * <pre>{@code
 * TemplateDescriptor td = TemplateLoader.load("templates/nft/pp1_nft.json");
 * String hex = td.getHex(); // hex with {{placeholder}} markers
 * }</pre>
 *
 * <p>The {@link #load(String)} method throws {@link RuntimeException} if the template
 * is not found on the classpath or cannot be parsed.
 *
 * @see TemplateDescriptor
 */
public class TemplateLoader {

    private static final ConcurrentHashMap<String, TemplateDescriptor> cache = new ConcurrentHashMap<>();
    private static final ObjectMapper mapper = new ObjectMapper();

    public static TemplateDescriptor load(String resourcePath) {
        return cache.computeIfAbsent(resourcePath, path -> {
            try (InputStream is = TemplateLoader.class.getClassLoader().getResourceAsStream(path)) {
                if (is == null) {
                    throw new RuntimeException("Template not found on classpath: " + path);
                }
                return mapper.readValue(is, TemplateDescriptor.class);
            } catch (IOException e) {
                throw new RuntimeException("Failed to load template: " + path, e);
            }
        });
    }
}
