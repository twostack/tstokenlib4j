package org.twostack.tstokenlib4j.statemachine;

import com.fasterxml.jackson.annotation.JsonProperty;

public record StateDef(String name, @JsonProperty("isTerminal") boolean terminal, int encoding) {}
