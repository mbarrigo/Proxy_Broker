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
