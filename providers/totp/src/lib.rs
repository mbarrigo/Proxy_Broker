//! Adaptador TOTP: genera códigos de un solo uso (RFC 6238) sin exponer
//! el seed.
//!
//! TODO: modo fuerte — el broker completa el login él mismo, sin
//! devolver ni seed ni OTP a la app (ver blueprint, sección TOTP).

use broker_core::{AdapterError, CallerIdentity, Capability, Operation, ProviderAdapter};

#[derive(Default)]
pub struct TotpAdapter;

impl TotpAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl ProviderAdapter for TotpAdapter {
    fn id(&self) -> &str {
        "totp"
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability {
            name: "totp.generate".into(),
            description: "Genera un código TOTP a partir del seed almacenado".into(),
        }]
    }

    fn execute(
        &self,
        _operation: &Operation,
        _caller: &CallerIdentity,
    ) -> Result<serde_json::Value, AdapterError> {
        Err(AdapterError::Upstream("adapter TOTP aún no implementado".into()))
    }
}
