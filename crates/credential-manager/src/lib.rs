//! Punto de contacto entre el daemon, el motor de políticas y los
//! adapters de proveedor. Define el contrato `ProviderAdapter` que
//! cualquier proveedor de credenciales debe implementar.
//!
//! Un adapter NUNCA decide si una operación está permitida — solo sabe
//! ejecutarla una vez el motor de políticas ya la autorizó. Esa
//! separación es deliberada (ver docs/threat-model.md).

use std::collections::HashMap;

pub use peer_identity::CallerIdentity;
use policy::{Decision, PolicyEngine};

#[derive(Debug, Clone)]
pub struct Operation {
    pub action: String,
    pub params: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct Capability {
    pub name: String,
    pub description: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("credencial no encontrada")]
    CredentialNotFound,
    #[error("error del proveedor: {0}")]
    Upstream(String),
    #[error("parámetros inválidos: {0}")]
    InvalidParams(String),
}

#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    #[error("operación denegada por política")]
    Denied,
    #[error("proveedor desconocido: {0}")]
    UnknownProvider(String),
    #[error(transparent)]
    Adapter(#[from] AdapterError),
}

pub trait ProviderAdapter: Send + Sync {
    /// Identificador único: "github", "ssh", "totp".
    fn id(&self) -> &str;

    /// Operaciones que este adapter sabe ejecutar — el motor de
    /// políticas las usa para saber qué puede permitir o denegar.
    fn capabilities(&self) -> Vec<Capability>;

    /// Ejecuta una operación YA autorizada por el motor de políticas.
    fn execute(
        &self,
        operation: &Operation,
        caller: &CallerIdentity,
    ) -> Result<serde_json::Value, AdapterError>;
}

pub struct CredentialManager {
    adapters: HashMap<String, Box<dyn ProviderAdapter>>,
    policy: PolicyEngine,
}

impl CredentialManager {
    pub fn new(policy: PolicyEngine) -> Self {
        Self {
            adapters: HashMap::new(),
            policy,
        }
    }

    pub fn register(&mut self, adapter: Box<dyn ProviderAdapter>) {
        self.adapters.insert(adapter.id().to_string(), adapter);
    }

    pub fn capabilities(&self) -> Vec<Capability> {
        self.adapters.values().flat_map(|a| a.capabilities()).collect()
    }

    pub fn dispatch(
        &self,
        provider: &str,
        operation: Operation,
        caller: &CallerIdentity,
    ) -> Result<serde_json::Value, DispatchError> {
        let adapter = self
            .adapters
            .get(provider)
            .ok_or_else(|| DispatchError::UnknownProvider(provider.to_string()))?;

        let capability = format!("{provider}.{}", operation.action);
        match self.policy.evaluate(&caller.exe_path.to_string_lossy(), &capability) {
            Decision::Allow => Ok(adapter.execute(&operation, caller)?),
            Decision::Deny => Err(DispatchError::Denied),
            Decision::AskUser => {
                // TODO: disparar el flujo de consentimiento en vez de
                // denegar por defecto (módulo 4 del blueprint).
                Err(DispatchError::Denied)
            }
        }
    }
}
