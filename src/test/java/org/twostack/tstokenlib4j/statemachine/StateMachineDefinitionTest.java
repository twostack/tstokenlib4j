package org.twostack.tstokenlib4j.statemachine;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Test;

import static org.assertj.core.api.Assertions.*;

public class StateMachineDefinitionTest {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    @Test
    public void loadPP1SmFunnel() {
        StateMachineDefinition def = StateMachineDefinitions.pp1SmFunnel();

        assertThat(def.name()).isEqualTo("PP1_SM_Funnel");
        assertThat(def.description()).isEqualTo("The PP1 state machine funnel");
        assertThat(def.roles()).hasSize(3);
        assertThat(def.states()).hasSize(6);
        assertThat(def.transitions()).hasSize(5);
        assertThat(def.customFields()).hasSize(1);
        assertThat(def.hasTimelock()).isTrue();
    }

    @Test
    public void rolesDeserializeCorrectly() {
        StateMachineDefinition def = StateMachineDefinitions.pp1SmFunnel();

        RoleDef operator = def.roles().get("operator");
        assertThat(operator.name()).isEqualTo("operator");
        assertThat(operator.authType()).isEqualTo(AuthType.PKH);

        RoleDef counterparty = def.roles().get("counterparty");
        assertThat(counterparty.authType()).isEqualTo(AuthType.PKH);

        RoleDef rabin = def.roles().get("rabin");
        assertThat(rabin.authType()).isEqualTo(AuthType.Rabin);
    }

    @Test
    public void statesDeserializeWithEncodings() {
        StateMachineDefinition def = StateMachineDefinitions.pp1SmFunnel();

        assertThat(def.states().get("CREATED").encoding()).isEqualTo(0);
        assertThat(def.states().get("ENROLLED").encoding()).isEqualTo(1);
        assertThat(def.states().get("CONFIRMED").encoding()).isEqualTo(2);
        assertThat(def.states().get("CONVERTED").encoding()).isEqualTo(3);
        assertThat(def.states().get("SETTLED").encoding()).isEqualTo(4);
        assertThat(def.states().get("TIMED_OUT").encoding()).isEqualTo(5);
    }

    @Test
    public void terminalStatesIdentified() {
        StateMachineDefinition def = StateMachineDefinitions.pp1SmFunnel();

        assertThat(def.states().get("CREATED").terminal()).isFalse();
        assertThat(def.states().get("ENROLLED").terminal()).isFalse();
        assertThat(def.states().get("SETTLED").terminal()).isTrue();
        assertThat(def.states().get("TIMED_OUT").terminal()).isTrue();
    }

    @Test
    public void transitionsDeserializeCorrectly() {
        StateMachineDefinition def = StateMachineDefinitions.pp1SmFunnel();

        TransitionDef enroll = def.transitions().stream()
                .filter(t -> t.name().equals("enroll")).findFirst().orElseThrow();
        assertThat(enroll.fromStates()).containsExactly("CREATED");
        assertThat(enroll.toState()).isEqualTo("ENROLLED");
        assertThat(enroll.requiredSigners()).containsExactly("operator");
        assertThat(enroll.ownerAfter()).isEqualTo("operator");
        assertThat(enroll.usesTimelock()).isFalse();

        TransitionDef confirm = def.transitions().stream()
                .filter(t -> t.name().equals("confirm")).findFirst().orElseThrow();
        assertThat(confirm.fromStates()).containsExactly("ENROLLED", "CONFIRMED");
        assertThat(confirm.requiredSigners()).containsExactly("operator", "counterparty");
        assertThat(confirm.effects()).hasSize(2);
        assertThat(confirm.effects().get(0).type()).isEqualTo(EffectType.INCREMENT);
        assertThat(confirm.effects().get(1).type()).isEqualTo(EffectType.HASH_CHAIN);

        TransitionDef timeout = def.transitions().stream()
                .filter(t -> t.name().equals("timeout")).findFirst().orElseThrow();
        assertThat(timeout.usesTimelock()).isTrue();
    }

    @Test
    public void guardsDeserializePolymorphically() {
        StateMachineDefinition def = StateMachineDefinitions.pp1SmFunnel();

        TransitionDef convert = def.transitions().stream()
                .filter(t -> t.name().equals("convert")).findFirst().orElseThrow();
        assertThat(convert.guards()).hasSize(1);
        assertThat(convert.guards().get(0)).isInstanceOf(GuardDef.FieldGuardDef.class);

        GuardDef.FieldGuardDef guard = (GuardDef.FieldGuardDef) convert.guards().get(0);
        assertThat(guard.fieldName()).isEqualTo("checkpointCount");
        assertThat(guard.op()).isEqualTo(GuardOp.GT);
        assertThat(guard.constant()).isEqualTo(0);
    }

    @Test
    public void customFieldsDeserializeCorrectly() {
        StateMachineDefinition def = StateMachineDefinitions.pp1SmFunnel();

        assertThat(def.customFields()).containsKey("checkpointCount");
        FieldDef mc = def.customFields().get("checkpointCount");
        assertThat(mc.name()).isEqualTo("checkpointCount");
        assertThat(mc.byteSize()).isEqualTo(1);
        assertThat(mc.type()).isEqualTo(FieldType.COUNTER);
        assertThat(mc.mutable()).isTrue();
    }

    @Test
    public void roundTripThroughJson() throws Exception {
        StateMachineDefinition original = StateMachineDefinitions.pp1SmFunnel();
        String json = MAPPER.writeValueAsString(original);
        StateMachineDefinition restored = MAPPER.readValue(json, StateMachineDefinition.class);

        assertThat(restored.name()).isEqualTo(original.name());
        assertThat(restored.roles()).hasSize(original.roles().size());
        assertThat(restored.states()).hasSize(original.states().size());
        assertThat(restored.transitions()).hasSize(original.transitions().size());
        assertThat(restored.customFields()).hasSize(original.customFields().size());
        assertThat(restored.hasTimelock()).isEqualTo(original.hasTimelock());

        // Verify state encodings survive round-trip
        for (String key : original.states().keySet()) {
            assertThat(restored.states().get(key).encoding())
                    .isEqualTo(original.states().get(key).encoding());
        }
    }
}
