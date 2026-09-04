use std::io::BufReader;
use std::path::PathBuf;

use broker_core::{AdapterError, CallerIdentity, Capability, CredentialManager, DispatchError, Operation, ProviderAdapter};
use broker_ipc::{ListenerExt, Request, Response, ResponseStatus};
use broker_policy::{PolicyEngine, Rule};

/// Provider de juguete — no representa ninguna credencial real. Sirve
/// para probar el ciclo identidad -> política -> auditoría sin depender
/// todavía de SSH/TOTP/GitHub (ver docs/threat-model.md).
struct DemoAdapter;

impl ProviderAdapter for DemoAdapter {
    fn id(&self) -> &str {
        "demo"
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![
            Capability { name: "demo.read".into(), description: "Operación de lectura de prueba".into() },
            Capability { name: "demo.admin".into(), description: "Operación administrativa de prueba".into() },
        ]
    }

    fn execute(&self, operation: &Operation, _caller: &CallerIdentity) -> Result<serde_json::Value, AdapterError> {
        match operation.action.as_str() {
            "read" => Ok(serde_json::json!({ "data": "contenido de prueba" })),
            "admin" => Ok(serde_json::json!({ "data": "operación admin de prueba" })),
            other => Err(AdapterError::InvalidParams(format!("operación demo desconocida: {other}"))),
        }
    }
}

/// Ruta esperada de `examples/demo-client`, junto al propio binario del
/// daemon en `target/<profile>/` (mismo directorio de salida — cargo no
/// lo pone bajo `examples/` porque es un paquete propio, no un
/// `[[example]]` de otro). Solo para la política de la demo — un broker
/// real cargaría esto de un YAML (ver blueprint, Policy Engine).
fn expected_demo_client_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let profile_dir = exe.parent()?;
    let name = if cfg!(windows) { "demo-client.exe" } else { "demo-client" };
    Some(profile_dir.join(name))
}

fn main() {
    let mut policy = PolicyEngine::new();
    if let Some(demo_client) = expected_demo_client_path() {
        println!("política: confiando en demo-client como {}", demo_client.display());
        policy.add_rule(Rule {
            executable: demo_client.to_string_lossy().into_owned(),
            allow: vec!["demo.read".into()],
            deny: vec!["demo.admin".into()],
        });
    } else {
        println!("aviso: no se pudo resolver la ruta esperada de demo-client; todo será denegado");
    }

    let mut manager = CredentialManager::new(policy, Box::new(broker_audit::StdoutSink));
    manager.register(Box::new(DemoAdapter));
    manager.register(Box::new(provider_ssh::SshAdapter::new()));
    manager.register(Box::new(provider_totp::TotpAdapter::new()));
    manager.register(Box::new(provider_github::GithubAdapter::new()));

    let listener = match broker_ipc::bind() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("no se pudo abrir el socket ({}): {e}", broker_ipc::SOCKET_NAME);
            std::process::exit(1);
        }
    };

    println!("cred-broker-daemon escuchando en «{}» — Ctrl+C para salir", broker_ipc::SOCKET_NAME);

    loop {
        let stream = match listener.accept() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error aceptando conexión: {e}");
                continue;
            }
        };
        handle_connection(&manager, stream);
    }
}

fn handle_connection(manager: &CredentialManager, stream: broker_ipc::Stream) {
    let (pid, uid) = match broker_ipc::peer_creds(&stream) {
        Ok(creds) => {
            #[cfg(unix)]
            let uid = creds.euid();
            #[cfg(not(unix))]
            let uid = None;
            (creds.pid(), uid)
        }
        Err(e) => {
            eprintln!("no se pudieron leer las credenciales del peer: {e}");
            (None, None)
        }
    };
    let identity = CallerIdentity::new(pid, uid);

    let mut reader = BufReader::new(&stream);
    let request: Request = match broker_ipc::recv_message(&mut reader) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("petición inválida de pid={pid:?}: {e}");
            return;
        }
    };
    drop(reader);

    let response = handle_request(manager, &identity, request);
    if let Err(e) = broker_ipc::send_message(&stream, &response) {
        eprintln!("no se pudo responder a pid={pid:?}: {e}");
    }
}

fn handle_request(manager: &CredentialManager, identity: &CallerIdentity, request: Request) -> Response {
    if request.op == "hello" {
        return Response { status: ResponseStatus::Ok, result: serde_json::json!("world") };
    }

    let operation = Operation { action: request.op, params: request.params };
    match manager.dispatch(&request.provider, operation, identity) {
        Ok(result) => Response { status: ResponseStatus::Ok, result },
        Err(DispatchError::Denied) => Response { status: ResponseStatus::Denied, result: serde_json::Value::Null },
        Err(e) => Response { status: ResponseStatus::Error, result: serde_json::json!({ "message": e.to_string() }) },
    }
}
