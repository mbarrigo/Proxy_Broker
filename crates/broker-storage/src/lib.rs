//! Abstracción sobre el almacén de secretos del sistema operativo
//! (Keychain / DPAPI+Credential Manager / Secret Service).
//!
//! TODO: implementación real por plataforma, previsiblemente sobre el
//! crate `keyring`. La variante en memoria de abajo es solo para poder
//! compilar y probar el resto del daemon mientras tanto — no cifra nada
//! y no debe usarse fuera de desarrollo local.

use std::collections::HashMap;
use std::sync::Mutex;

pub trait SecretStore: Send + Sync {
    fn put(&self, id: &str, secret: &[u8]) -> Result<(), StoreError>;
    fn get(&self, id: &str) -> Result<Vec<u8>, StoreError>;
    fn delete(&self, id: &str) -> Result<(), StoreError>;
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("secreto no encontrado: {0}")]
    NotFound(String),
    #[error("error del backend de almacenamiento: {0}")]
    Backend(String),
}

#[derive(Default)]
pub struct InMemoryStore {
    inner: Mutex<HashMap<String, Vec<u8>>>,
}

impl SecretStore for InMemoryStore {
    fn put(&self, id: &str, secret: &[u8]) -> Result<(), StoreError> {
        self.inner
            .lock()
            .map_err(|_| StoreError::Backend("lock envenenado".into()))?
            .insert(id.to_string(), secret.to_vec());
        Ok(())
    }

    fn get(&self, id: &str) -> Result<Vec<u8>, StoreError> {
        self.inner
            .lock()
            .map_err(|_| StoreError::Backend("lock envenenado".into()))?
            .get(id)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(id.to_string()))
    }

    fn delete(&self, id: &str) -> Result<(), StoreError> {
        self.inner
            .lock()
            .map_err(|_| StoreError::Backend("lock envenenado".into()))?
            .remove(id);
        Ok(())
    }
}
