use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use crate::cli::LogsArgs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficEntry {
    pub id: String,
    pub ts: DateTime<Utc>,
    pub host: String,
    pub method: String,
    pub url: String,
    pub req_headers: HashMap<String, String>,
    pub req_body: Option<String>,
    pub status: Option<u16>,
    pub res_headers: HashMap<String, String>,
    pub res_body: Option<String>,
    pub duration_ms: Option<u64>,
}

pub struct JsonLinesBackend {
    path: PathBuf,
}

impl JsonLinesBackend {
    pub fn new(data_dir: &PathBuf) -> Self {
        Self {
            path: data_dir.join("traffic.jsonl"),
        }
    }

    pub fn append(&self, entry: &TrafficEntry) -> Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .context("opening traffic log")?;
        let line = serde_json::to_string(entry)?;
        writeln!(f, "{}", line)?;
        Ok(())
    }
}

pub struct SqliteBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteBackend {
    pub fn new(data_dir: &PathBuf) -> Result<Self> {
        let conn = Connection::open(data_dir.join("traffic.db"))
            .context("opening sqlite db")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS traffic (
                id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                host TEXT NOT NULL,
                method TEXT NOT NULL,
                url TEXT NOT NULL,
                req_headers TEXT,
                req_body TEXT,
                status INTEGER,
                res_headers TEXT,
                res_body TEXT,
                duration_ms INTEGER
            );",
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn append(&self, e: &TrafficEntry) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO traffic VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            rusqlite::params![
                e.id,
                e.ts.to_rfc3339(),
                e.host,
                e.method,
                e.url,
                serde_json::to_string(&e.req_headers)?,
                e.req_body,
                e.status,
                serde_json::to_string(&e.res_headers)?,
                e.res_body,
                e.duration_ms,
            ],
        )?;
        Ok(())
    }
}

pub struct Store {
    jsonl: JsonLinesBackend,
    sqlite: Option<SqliteBackend>,
}

impl Store {
    pub fn new(data_dir: &PathBuf, use_sqlite: bool) -> Result<Arc<Self>> {
        let sqlite = if use_sqlite {
            Some(SqliteBackend::new(data_dir)?)
        } else {
            None
        };
        Ok(Arc::new(Self {
            jsonl: JsonLinesBackend::new(data_dir),
            sqlite,
        }))
    }

    pub fn record(&self, entry: TrafficEntry) {
        if let Err(e) = self.jsonl.append(&entry) {
            tracing::warn!("Failed to write jsonl: {e}");
        }
        if let Some(db) = &self.sqlite {
            if let Err(e) = db.append(&entry) {
                tracing::warn!("Failed to write sqlite: {e}");
            }
        }
    }
}

pub async fn query_logs(args: LogsArgs, data_dir: PathBuf) -> Result<()> {
    let path = data_dir.join("traffic.jsonl");
    if !path.exists() {
        eprintln!("No traffic log found at {}. Start the proxy first.", path.display());
        return Ok(());
    }

    let content = std::fs::read_to_string(&path)?;
    let mut entries: Vec<TrafficEntry> = content
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();

    if let Some(host) = &args.host {
        let h = host.to_lowercase();
        entries.retain(|e| e.host.to_lowercase().contains(&h));
    }
    if let Some(method) = &args.method {
        let m = method.to_uppercase();
        entries.retain(|e| e.method == m);
    }
    if let Some(status) = args.status {
        entries.retain(|e| e.status == Some(status));
    }

    let entries: Vec<_> = entries.into_iter().rev().take(args.limit).collect();

    if args.json {
        for e in entries.iter().rev() {
            println!("{}", serde_json::to_string(e)?);
        }
    } else {
        println!(
            "{:<36}  {:<6}  {:<20}  {:<6}  {}",
            "ID", "METHOD", "HOST", "STATUS", "URL"
        );
        println!("{}", "-".repeat(100));
        for e in entries.iter().rev() {
            println!(
                "{:<36}  {:<6}  {:<20}  {:<6}  {}",
                e.id,
                e.method,
                truncate(&e.host, 20),
                e.status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                truncate(&e.url, 60),
            );
        }
    }

    Ok(())
}

pub fn load_entry(data_dir: &PathBuf, id: &str) -> Result<TrafficEntry> {
    let path = data_dir.join("traffic.jsonl");
    let content = std::fs::read_to_string(&path).context("reading traffic log")?;
    content
        .lines()
        .filter(|l| !l.is_empty())
        .find_map(|l| {
            let e: TrafficEntry = serde_json::from_str(l).ok()?;
            if e.id == id { Some(e) } else { None }
        })
        .context(format!("no entry with id {id}"))
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}
