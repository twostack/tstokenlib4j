package org.twostack.tstokenlib4j.statemachine;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;

public class StateMachineDefinitions {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    public static StateMachineDefinition pp1SmFunnel() {
        return load("statemachine/pp1_sm_funnel.json");
    }

    public static StateMachineDefinition load(String resourcePath) {
        try (InputStream is = StateMachineDefinitions.class.getClassLoader()
                .getResourceAsStream(resourcePath)) {
            if (is == null) {
                throw new IllegalArgumentException("Resource not found: " + resourcePath);
            }
            return MAPPER.readValue(is, StateMachineDefinition.class);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load state machine definition: " + resourcePath, e);
        }
    }
}
