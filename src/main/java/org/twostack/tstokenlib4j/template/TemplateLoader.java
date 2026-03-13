package org.twostack.tstokenlib4j.template;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.ConcurrentHashMap;

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
