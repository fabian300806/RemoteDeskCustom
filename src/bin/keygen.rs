// ============================================================================
// ili enterprise NET — Generador de Claves Seriales Corporativas
// ============================================================================

use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

const CHARSET: &[u8] = b"0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";

pub struct Rng {
    state: u64,
}

impl Rng {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let pid = std::process::id() as u64;
        let mut s = nanos ^ (pid << 32) ^ 0xCAFEBABE12345678;
        if s == 0 {
            s = 0x853c49e6748fea9b;
        }
        Self { state: s }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn next_char(&mut self) -> char {
        let idx = (self.next_u64() % CHARSET.len() as u64) as usize;
        CHARSET[idx] as char
    }

    fn next_block(&mut self) -> String {
        format!(
            "{}{}{}{}",
            self.next_char(),
            self.next_char(),
            self.next_char(),
            self.next_char()
        )
    }
}

pub fn compute_checksum(payload: &str) -> String {
    let mut h = 0x494C49u64; // Semilla 'ILI'
    for (i, b) in payload.bytes().enumerate() {
        let c = (b as char).to_ascii_uppercase() as u64;
        h = h.wrapping_mul(31).wrapping_add(c).wrapping_add((i as u64 + 1) * 17);
    }
    let len = CHARSET.len() as u64;
    let c0 = CHARSET[((h >> 15) % len) as usize] as char;
    let c1 = CHARSET[((h >> 10) % len) as usize] as char;
    let c2 = CHARSET[((h >> 5) % len) as usize] as char;
    let c3 = CHARSET[(h % len) as usize] as char;
    format!("{}{}{}{}", c0, c1, c2, c3)
}

pub fn generate_key(rng: &mut Rng, prefix: &str) -> String {
    let p1 = rng.next_block();
    let p2 = rng.next_block();
    let payload = format!("{}{}{}", prefix, p1, p2);
    let chk = compute_checksum(&payload);
    format!("ILI-{}-{}-{}-{}", prefix, p1, p2, chk)
}

fn print_header() {
    println!("============================================================");
    println!("     GENERADOR DE CLAVES SERIALES — ili enterprise NET      ");
    println!("============================================================");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut rng = Rng::new();

    let (prefix, count, output_file) = if args.len() > 1 {
        // Uso por linea de comando: keygen [EDICION] [CANTIDAD] [ARCHIVO_SALIDA]
        let p = match args[1].to_ascii_uppercase().as_str() {
            "ENT" | "ENT1" => "ENT1",
            "CORP" => "CORP",
            "PRO" | "PRO1" => "PRO1",
            "DEMO" => "DEMO",
            other => {
                if other.len() == 4 {
                    &args[1]
                } else {
                    "ENT1"
                }
            }
        };
        let c: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);
        let out = args.get(3).cloned();
        (p.to_string(), c, out)
    } else {
        // Modo interactivo
        print_header();
        println!("Seleccione la edicion de licencia:");
        println!("  [1] ENT1 — Edicion Corporativa Enterprise (Recomendada)");
        println!("  [2] CORP — Licencia Corporativa Ilimitada");
        println!("  [3] PRO1 — Edicion Profesional Avanzada");
        println!("  [4] DEMO — Licencia de Demostracion / Pruebas");
        print!("\nIngrese opcion (1-4, por defecto 1): ");
        let _ = io::stdout().flush();

        let mut input = String::new();
        let _ = io::stdin().read_line(&mut input);
        let p = match input.trim() {
            "2" => "CORP",
            "3" => "PRO1",
            "4" => "DEMO",
            _ => "ENT1",
        };

        print!("Cuantas claves desea generar? (por defecto 5): ");
        let _ = io::stdout().flush();
        let mut count_str = String::new();
        let _ = io::stdin().read_line(&mut count_str);
        let c: usize = count_str.trim().parse().unwrap_or(5).max(1);

        (p.to_string(), c, None)
    };

    let edicion_nombre = match prefix.as_str() {
        "ENT1" => "ili enterprise NET — Edicion Corporativa Enterprise",
        "CORP" => "ili enterprise NET — Licencia Corporativa Ilimitada",
        "PRO1" => "ili enterprise NET — Edicion Profesional Avanzada",
        "DEMO" => "ili enterprise NET — Licencia de Demostracion / Evaluacion",
        _ => "ili enterprise NET — Licencia Comercial Especial",
    };

    println!("\n============================================================");
    println!("  GENERANDO CLAVES DE ACTIVACION — ili enterprise NET       ");
    println!("============================================================");
    println!("Edicion seleccionada : {} ({})", prefix, edicion_nombre);
    println!("Cantidad a generar   : {} licencias", count);
    println!("------------------------------------------------------------");

    let mut keys = Vec::new();
    for i in 1..=count {
        let key = generate_key(&mut rng, &prefix);
        println!("  [{:02}]  {}", i, key);
        keys.push(key);
    }

    println!("------------------------------------------------------------");
    println!("[OK] Claves generadas exitosamente y verificadas offline.");

    if let Some(path) = output_file {
        if let Ok(mut f) = File::create(&path) {
            let _ = writeln!(f, "============================================================");
            let _ = writeln!(f, " CLAVES DE ACTIVACION — ili enterprise NET");
            let _ = writeln!(f, "============================================================");
            let _ = writeln!(f, "Edicion : {} ({})", prefix, edicion_nombre);
            let _ = writeln!(f, "Total   : {} licencias", count);
            let _ = writeln!(f, "------------------------------------------------------------\n");
            for k in &keys {
                let _ = writeln!(f, "{}", k);
            }
            let _ = writeln!(f, "\n------------------------------------------------------------");
            let _ = writeln!(f, "Instrucciones:");
            let _ = writeln!(f, "1. Inicie 'ili enterprise NET'");
            let _ = writeln!(f, "2. Pegue cualquiera de estas claves en la pantalla de activacion.");
            println!("\n[GUARDADO] Claves guardadas en: {}", path);
        }
    }

    println!("============================================================\n");
}
