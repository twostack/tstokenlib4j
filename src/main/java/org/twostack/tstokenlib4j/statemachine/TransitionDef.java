package org.twostack.tstokenlib4j.statemachine;
import java.util.List;
public record TransitionDef(
    String name,
    List<String> fromStates,
    String toState,
    List<String> requiredSigners,
    String ownerAfter,
    List<GuardDef> guards,
    List<EffectDef> effects,
    boolean usesTimelock,
    String description) {}
