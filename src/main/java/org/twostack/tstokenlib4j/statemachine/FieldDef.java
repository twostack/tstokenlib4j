package org.twostack.tstokenlib4j.statemachine;
import com.fasterxml.jackson.annotation.JsonProperty;
public record FieldDef(String name, int byteSize, FieldType type, @JsonProperty("isMutable") boolean mutable) {}
