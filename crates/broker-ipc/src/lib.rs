//! Transporte IPC: Unix domain socket (Linux/macOS) o Named Pipe
//! (Windows).
//!
//! TODO: framing del protocolo (length-prefixed CBOR) y creación
//! atómica del socket para evitar que otro proceso lo suplante antes
//! de que el daemon real arranque (ver docs/threat-model.md, riesgo de
//! broker impersonation).

pub struct IpcListener;

impl IpcListener {
    pub fn bind(_path: &str) -> Result<Self, IpcError> {
        Err(IpcError::NotImplemented)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("transporte IPC aún no implementado")]
    NotImplemented,
}
