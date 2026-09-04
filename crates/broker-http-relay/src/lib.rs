//! Motor de relay HTTP para proveedores bearer: construye la petición
//! final e inyecta el header `Authorization` en el último momento
//! posible. Validación TLS estricta, sin interceptar/descifrar tráfico
//! (nunca TLS MITM — ver docs/threat-model.md).
//!
//! TODO: cliente real sobre `rustls`.

#[derive(Default)]
pub struct HttpRelay;

impl HttpRelay {
    pub fn new() -> Self {
        Self
    }
}
