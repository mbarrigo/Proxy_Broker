//! Cliente de prueba para el daemon. No representa una app real — es la
//! herramienta con la que comprobamos manualmente el ciclo
//! identidad -> política -> auditoría mientras se construye.
//!
//! Uso:
//!   demo-client hello              # comprobación de conectividad
//!   demo-client demo read          # debería dar ALLOW
//!   demo-client demo admin         # debería dar DENY

use std::io::BufReader;

use broker_ipc::{Request, Response};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let request = match args.as_slice() {
        [op] if op == "hello" => Request { provider: String::new(), op: "hello".into(), params: serde_json::Value::Null },
        [provider, op] => Request { provider: provider.clone(), op: op.clone(), params: serde_json::Value::Null },
        _ => {
            eprintln!("uso: demo-client hello | demo-client <provider> <operación>");
            std::process::exit(2);
        }
    };

    let stream = match broker_ipc::connect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("no se pudo conectar al broker ({}): {e}", broker_ipc::SOCKET_NAME);
            std::process::exit(1);
        }
    };

    if let Err(e) = broker_ipc::send_message(&stream, &request) {
        eprintln!("no se pudo enviar la petición: {e}");
        std::process::exit(1);
    }

    let mut reader = BufReader::new(&stream);
    match broker_ipc::recv_message::<Response>(&mut reader) {
        Ok(response) => {
            println!("{:?} -> {}", response.status, response.result);
        }
        Err(e) => {
            eprintln!("no se pudo leer la respuesta: {e}");
            std::process::exit(1);
        }
    }
}
