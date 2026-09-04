//! Motor de políticas: decide Allow/Deny/AskUser para una operación
//! solicitada por un caller identificado.
//!
//! TODO: cargar reglas desde YAML y mover el scope de "allow por app" a
//! "allow por operación+recurso concreto" (ver docs/threat-model.md,
//! riesgo de consent fatigue).

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    AskUser,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub executable: String,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

#[derive(Default)]
pub struct PolicyEngine {
    rules: HashMap<String, Rule>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.insert(rule.executable.clone(), rule);
    }

    /// Evalúa si `capability` está permitida para el ejecutable `caller_exe`.
    pub fn evaluate(&self, caller_exe: &str, capability: &str) -> Decision {
        match self.rules.get(caller_exe) {
            Some(rule) if rule.deny.iter().any(|d| d == capability) => Decision::Deny,
            Some(rule) if rule.allow.iter().any(|a| a == capability) => Decision::Allow,
            Some(_) => Decision::AskUser,
            None => Decision::Deny,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine_with_demo_rule() -> PolicyEngine {
        let mut engine = PolicyEngine::new();
        engine.add_rule(Rule {
            executable: "demo-client".into(),
            allow: vec!["demo.read".into()],
            deny: vec!["demo.admin".into()],
        });
        engine
    }

    #[test]
    fn allows_capability_explicitly_allowed() {
        let engine = engine_with_demo_rule();
        assert_eq!(engine.evaluate("demo-client", "demo.read"), Decision::Allow);
    }

    #[test]
    fn denies_capability_explicitly_denied() {
        let engine = engine_with_demo_rule();
        assert_eq!(engine.evaluate("demo-client", "demo.admin"), Decision::Deny);
    }

    #[test]
    fn asks_user_for_capability_with_no_explicit_rule() {
        let engine = engine_with_demo_rule();
        assert_eq!(engine.evaluate("demo-client", "demo.delete"), Decision::AskUser);
    }

    #[test]
    fn denies_by_default_for_unknown_caller() {
        // Este es el caso "evil-demo": mismo binario, ruta distinta, sin
        // regla propia -> denegado, no "ask user".
        let engine = engine_with_demo_rule();
        assert_eq!(engine.evaluate("evil-demo", "demo.read"), Decision::Deny);
    }

    #[test]
    fn deny_wins_over_allow_if_both_listed_for_same_capability() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(Rule {
            executable: "confused".into(),
            allow: vec!["demo.read".into()],
            deny: vec!["demo.read".into()],
        });
        assert_eq!(engine.evaluate("confused", "demo.read"), Decision::Deny);
    }
}
