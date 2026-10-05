// ============================================================================
// ili enterprise NET — Módulo de Autenticación, Roles y Base de Datos Local
// ============================================================================

use std::path::PathBuf;
use std::fs;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const PEPPER: &str = "ILI_ENTERPRISE_NET_AUTH_PEPPER_2026_SECRET";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserRole {
    Admin,
    NetworkTech,
    DomainAdmin,
    FileOperator,
}

impl UserRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            UserRole::Admin => "admin",
            UserRole::NetworkTech => "network_tech",
            UserRole::DomainAdmin => "domain_admin",
            UserRole::FileOperator => "file_operator",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            UserRole::Admin => "Administrador",
            UserRole::NetworkTech => "Técnico de Red",
            UserRole::DomainAdmin => "Administrador de Dominio (AD)",
            UserRole::FileOperator => "Operador de Archivos",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            UserRole::Admin => "Acceso total a todos los módulos licenciados, gestión de usuarios y licencias.",
            UserRole::NetworkTech => "Acceso a escaneo de red, descubrimiento de dispositivos, puertos, WoL e instalador Office.",
            UserRole::DomainAdmin => "Acceso a Active Directory, gestión de usuarios, grupos, equipos y políticas de dominio.",
            UserRole::FileOperator => "Acceso a Servidor de Archivos, recursos compartidos, permisos NTFS, analizador de disco y VSS.",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "admin" | "administrador" => UserRole::Admin,
            "network_tech" | "tecnico_red" | "técnico de red" => UserRole::NetworkTech,
            "domain_admin" | "admin_ad" | "administrador de dominio (ad)" => UserRole::DomainAdmin,
            "file_operator" | "operador_archivos" | "operador de archivos" => UserRole::FileOperator,
            _ => UserRole::NetworkTech,
        }
    }

    pub fn can_access_network(&self) -> bool {
        matches!(self, UserRole::Admin | UserRole::NetworkTech)
    }

    pub fn can_access_ad(&self) -> bool {
        matches!(self, UserRole::Admin | UserRole::DomainAdmin)
    }

    pub fn can_access_fileserver(&self) -> bool {
        matches!(self, UserRole::Admin | UserRole::FileOperator)
    }

    #[allow(dead_code)]
    pub fn can_manage_users(&self) -> bool {
        matches!(self, UserRole::Admin)
    }

    #[allow(dead_code)]
    pub fn can_manage_licenses(&self) -> bool {
        matches!(self, UserRole::Admin)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserAccount {
    pub id: i64,
    pub username: String,
    pub full_name: String,
    pub role: UserRole,
    pub created_at: String,
    pub last_login: Option<String>,
}

fn hash_password_internal(password: &str, salt: &str) -> String {
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(password.as_bytes());
    h.update(PEPPER.as_bytes());
    let mut current = h.finalize().to_vec();

    // 10,000 rondas de estiramiento criptográfico con sal
    for i in 0..10_000 {
        let mut round = Sha256::new();
        round.update(&current);
        round.update(salt.as_bytes());
        round.update((i as u32).to_le_bytes());
        current = round.finalize().to_vec();
    }

    hex::encode(current)
}

fn generate_salt() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    let rand_seed = format!("{}-{}-ILI_SALT_SECURE", nanos, pid);
    let mut hasher = Sha256::new();
    hasher.update(rand_seed.as_bytes());
    let digest = hex::encode(hasher.finalize());
    digest[..16].to_string()
}

pub fn db_path() -> PathBuf {
    if let Ok(appdata) = std::env::var("APPDATA") {
        let dir = PathBuf::from(appdata).join("lili_enterprise_net");
        let _ = fs::create_dir_all(&dir);
        dir.join("auth.db")
    } else {
        PathBuf::from("auth.db")
    }
}

pub struct AuthDb {
    conn: Connection,
}

impl AuthDb {
    pub fn open() -> Result<Self, String> {
        let path = db_path();
        let conn = Connection::open(&path)
            .map_err(|e| format!("Error al abrir base de datos SQLite ({}): {}", path.display(), e))?;

        let _ = conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;"
        );

        conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                full_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_login TEXT
            );",
            [],
        ).map_err(|e| format!("Error al inicializar tabla de usuarios: {}", e))?;

        Ok(Self { conn })
    }

    pub fn count_users(&self) -> Result<usize, String> {
        let count: i64 = self.conn
            .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
            .map_err(|e| format!("Error al consultar usuarios: {}", e))?;
        Ok(count as usize)
    }

    pub fn register_user(
        &self,
        username: &str,
        full_name: &str,
        password: &str,
        role: UserRole,
    ) -> Result<UserAccount, String> {
        let clean_user = username.trim();
        let clean_name = full_name.trim();

        if clean_user.len() < 3 {
            return Err("El nombre de usuario debe tener al menos 3 caracteres.".into());
        }
        if clean_name.is_empty() {
            return Err("Por favor ingrese el nombre completo o identificación.".into());
        }
        if password.len() < 4 {
            return Err("La contraseña debe tener al menos 4 caracteres.".into());
        }

        let salt = generate_salt();
        let pass_hash = hash_password_internal(password, &salt);
        let now = chrono_now_str();

        self.conn.execute(
            "INSERT INTO users (username, full_name, password_hash, salt, role, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6);",
            params![
                clean_user,
                clean_name,
                pass_hash,
                salt,
                role.as_str(),
                now
            ],
        ).map_err(|e| {
            if e.to_string().contains("UNIQUE") {
                format!("El nombre de usuario '{}' ya se encuentra registrado.", clean_user)
            } else {
                format!("Error al registrar usuario: {}", e)
            }
        })?;

        let last_id = self.conn.last_insert_rowid();

        Ok(UserAccount {
            id: last_id,
            username: clean_user.to_string(),
            full_name: clean_name.to_string(),
            role,
            created_at: now,
            last_login: None,
        })
    }

    pub fn authenticate(&self, username: &str, password: &str) -> Result<UserAccount, String> {
        let clean_user = username.trim();
        if clean_user.is_empty() || password.is_empty() {
            return Err("Debe ingresar usuario y contraseña.".into());
        }

        let mut stmt = self.conn
            .prepare("SELECT id, username, full_name, password_hash, salt, role, created_at, last_login FROM users WHERE username = ?1")
            .map_err(|e| format!("Error en consulta SQL: {}", e))?;

        let user_row = stmt.query_row(params![clean_user], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
            ))
        });

        match user_row {
            Ok((id, uname, fname, stored_hash, salt, role_str, created, _)) => {
                let computed_hash = hash_password_internal(password, &salt);
                if computed_hash != stored_hash {
                    return Err("Contraseña incorrecta.".into());
                }

                let now = chrono_now_str();
                let _ = self.conn.execute(
                    "UPDATE users SET last_login = ?1 WHERE id = ?2",
                    params![now, id],
                );

                Ok(UserAccount {
                    id,
                    username: uname,
                    full_name: fname,
                    role: UserRole::from_str(&role_str),
                    created_at: created,
                    last_login: Some(now),
                })
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                Err(format!("El usuario '{}' no existe en el sistema.", clean_user))
            }
            Err(e) => Err(format!("Error de autenticación: {}", e)),
        }
    }

    pub fn list_users(&self) -> Result<Vec<UserAccount>, String> {
        let mut stmt = self.conn
            .prepare("SELECT id, username, full_name, role, created_at, last_login FROM users ORDER BY id ASC")
            .map_err(|e| format!("Error al preparar consulta: {}", e))?;

        let rows = stmt.query_map([], |row| {
            let role_str: String = row.get(3)?;
            Ok(UserAccount {
                id: row.get(0)?,
                username: row.get(1)?,
                full_name: row.get(2)?,
                role: UserRole::from_str(&role_str),
                created_at: row.get(4)?,
                last_login: row.get(5)?,
            })
        }).map_err(|e| format!("Error al listar usuarios: {}", e))?;

        let mut list = Vec::new();
        for r in rows {
            if let Ok(u) = r {
                list.push(u);
            }
        }
        Ok(list)
    }

    pub fn delete_user(&self, id: i64) -> Result<(), String> {
        let rows = self.conn
            .execute("DELETE FROM users WHERE id = ?1", params![id])
            .map_err(|e| format!("Error al eliminar usuario: {}", e))?;
        if rows == 0 {
            Err("Usuario no encontrado.".into())
        } else {
            Ok(())
        }
    }

    pub fn change_role(&self, id: i64, new_role: UserRole) -> Result<(), String> {
        self.conn.execute(
            "UPDATE users SET role = ?1 WHERE id = ?2",
            params![new_role.as_str(), id],
        ).map_err(|e| format!("Error al modificar rol: {}", e))?;
        Ok(())
    }
}

fn chrono_now_str() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let days = now / 86400;
    let time_of_day = now % 86400;
    let hours = (time_of_day / 3600) % 24;
    let minutes = (time_of_day % 3600) / 60;

    let mut y = 1970;
    let mut d = days;
    loop {
        let leap = if (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0) { 1 } else { 0 };
        let days_in_year = 365 + leap;
        if d < days_in_year {
            let months = [
                31, 28 + leap, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
            ];
            let mut m = 0;
            while m < 12 && d >= months[m] {
                d -= months[m];
                m += 1;
            }
            return format!("{:04}-{:02}-{:02} {:02}:{:02}", y, m + 1, d + 1, hours, minutes);
        }
        d -= days_in_year;
        y += 1;
    }
}
