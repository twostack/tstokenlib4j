package org.twostack.tstokenlib4j.statemachine;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import java.util.List;

@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
@JsonSubTypes({
    @JsonSubTypes.Type(value = GuardDef.FieldGuardDef.class, name = "field"),
    @JsonSubTypes.Type(value = GuardDef.DataGuardDef.class, name = "data"),
    @JsonSubTypes.Type(value = GuardDef.OracleGuardDef.class, name = "oracle"),
})
public sealed interface GuardDef permits GuardDef.FieldGuardDef, GuardDef.DataGuardDef, GuardDef.OracleGuardDef {

    record FieldGuardDef(String fieldName, GuardOp op, int constant, String description) implements GuardDef {}

    record DataGuardDef(int payloadOffset, int payloadLength, GuardOp op, int value, String description) implements GuardDef {}

    record OracleGuardDef(String oracleRole, List<DataGuardDef> dataGuards, String description) implements GuardDef {}
}
