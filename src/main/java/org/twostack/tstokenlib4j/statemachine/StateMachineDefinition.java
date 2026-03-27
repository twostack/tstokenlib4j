package org.twostack.tstokenlib4j.statemachine;
import java.util.List;
import java.util.Map;
public record StateMachineDefinition(
    String name,
    String description,
    Map<String, RoleDef> roles,
    Map<String, StateDef> states,
    List<TransitionDef> transitions,
    Map<String, FieldDef> customFields) {

    public boolean hasTimelock() {
        return transitions != null && transitions.stream().anyMatch(TransitionDef::usesTimelock);
    }
}
