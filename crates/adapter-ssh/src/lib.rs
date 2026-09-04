//! Adaptador SSH: firma vía el protocolo real de ssh-agent.
//!
//! TODO: implementar el protocolo ssh-agent para que clientes SSH reales
//! (`ssh -A`, `git push`, `ssh-add -l`) hablen con este adapter sin saber
//! que no es el ssh-agent estándar.

use credential_manager::{AdapterError, CallerIdentity, Capability, Operation, ProviderAdapter};

#[derive(Default)]
pub struct SshAdapter;

impl SshAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl ProviderAdapter for SshAdapter {
    fn id(&self) -> &str {
        "ssh"
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability {
            name: "ssh.sign".into(),
            description: "Firma un desafío con una clave gestionada por el broker".into(),
        }]
    }

    fn execute(
        &self,
        _operation: &Operation,
        _caller: &CallerIdentity,
    ) -> Result<serde_json::Value, AdapterError> {
        Err(AdapterError::Upstream("adapter SSH aún no implementado".into()))
    }
}
