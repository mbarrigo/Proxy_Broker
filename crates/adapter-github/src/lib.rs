//! Adaptador GitHub: OAuth 2.0 + PKCE, refresh de tokens y mapeo
//! semántico de un subconjunto deliberado de la API.
//!
//! TODO: flujo PKCE con loopback local; mapear cada Capability a la
//! petición REST/GraphQL real en http-relay.

use credential_manager::{AdapterError, CallerIdentity, Capability, Operation, ProviderAdapter};

#[derive(Default)]
pub struct GithubAdapter;

impl GithubAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl ProviderAdapter for GithubAdapter {
    fn id(&self) -> &str {
        "github"
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![
            Capability {
                name: "github.repos.read".into(),
                description: "Leer repositorios".into(),
            },
            Capability {
                name: "github.repos.write".into(),
                description: "Escribir en repositorios".into(),
            },
            Capability {
                name: "github.deployments.create".into(),
                description: "Crear deployments".into(),
            },
        ]
    }

    fn execute(
        &self,
        _operation: &Operation,
        _caller: &CallerIdentity,
    ) -> Result<serde_json::Value, AdapterError> {
        Err(AdapterError::Upstream("adapter GitHub aún no implementado".into()))
    }
}
