//! Reading traffic history back out of sqlite: paging, filtering, search,
//! lookup by id, and "everything after this id" for resuming `/feed`.
//!
//! Order is record order: sqlite's rowid, which increases as `Store::record`
//! inserts. Paging (`before`) and feed resume (`after`) both use it, so the
//! two agree and a cursor is stable. `ts` isn't used for ordering: entries
//! from concurrent connections are recorded slightly out of `ts` order.

use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::types::ToSql;
use rusqlite::{OptionalExtension, Row};
use serde::Deserialize;

use crate::storage::{Headers, SqliteBackend, TrafficEntry};
use taphttp_types::BodyEncoding;

/// Default and maximum page size for [`SqliteBackend::query`].
pub const DEFAULT_LIMIT: usize = 100;
pub const MAX_LIMIT: usize = 500;

/// A history query, as `GET /exchanges` takes it from the query string.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct HistoryQuery {
    /// Substring of the host, case-insensitive.
    pub host: Option<String>,
    /// Exact method, case-insensitive.
    pub method: Option<String>,
    pub status: Option<u16>,
    /// Substring of the URL or host, case-insensitive.
    pub q: Option<String>,
    /// Only entries with `ts` at or after this RFC 3339 time.
    pub since: Option<DateTime<Utc>>,
    /// Only entries with `ts` before this RFC 3339 time.
    pub until: Option<DateTime<Utc>>,
    /// Cursor: only entries recorded before the entry with this id.
    pub before: Option<String>,
    /// Page size; default [`DEFAULT_LIMIT`], capped at [`MAX_LIMIT`].
    pub limit: Option<usize>,
}

#[derive(Debug)]
pub enum HistoryError {
    /// `before` names an id that isn't in the database.
    UnknownCursor(String),
    Db(anyhow::Error),
}

impl From<rusqlite::Error> for HistoryError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Db(e.into())
    }
}

const COLUMNS: &str = "rowid, id, ts, host, method, url, req_headers, req_body, \
    req_body_encoding, status, res_headers, res_body, res_body_encoding, duration_ms, replay_of";

impl SqliteBackend {
    /// Newest first, filtered, at most `limit` entries.
    pub fn query(&self, q: &HistoryQuery) -> Result<Vec<TrafficEntry>, HistoryError> {
        let mut sql = format!("SELECT {COLUMNS} FROM traffic WHERE 1=1");
        let mut params: Vec<Box<dyn ToSql>> = Vec::new();

        if let Some(id) = &q.before {
            let rowid = self.rowid_of(id)?.ok_or_else(|| HistoryError::UnknownCursor(id.clone()))?;
            sql.push_str(" AND rowid < ?");
            params.push(Box::new(rowid));
        }
        if let Some(host) = &q.host {
            sql.push_str(r" AND host LIKE ? ESCAPE '\'");
            params.push(Box::new(like_pattern(host)));
        }
        if let Some(method) = &q.method {
            sql.push_str(" AND method = ?");
            params.push(Box::new(method.to_uppercase()));
        }
        if let Some(status) = q.status {
            sql.push_str(" AND status = ?");
            params.push(Box::new(status));
        }
        if let Some(text) = &q.q {
            sql.push_str(r" AND (url LIKE ? ESCAPE '\' OR host LIKE ? ESCAPE '\')");
            params.push(Box::new(like_pattern(text)));
            params.push(Box::new(like_pattern(text)));
        }
        if let Some(since) = q.since {
            sql.push_str(" AND ts_us >= ?");
            params.push(Box::new(since.timestamp_micros()));
        }
        if let Some(until) = q.until {
            sql.push_str(" AND ts_us < ?");
            params.push(Box::new(until.timestamp_micros()));
        }
        let limit = q.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
        sql.push_str(" ORDER BY rowid DESC LIMIT ?");
        params.push(Box::new(limit as i64));

        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut stmt = conn.prepare(&sql)?;
        let refs: Vec<&dyn ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let rows = stmt.query_map(refs.as_slice(), |r| row_to_entry(r).map(|(_, e)| e))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// One entry by id (indexed: `id` is the primary key).
    pub fn get(&self, id: &str) -> Result<Option<TrafficEntry>> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let found = conn
            .query_row(&format!("SELECT {COLUMNS} FROM traffic WHERE id = ?1"), [id], |r| {
                row_to_entry(r).map(|(_, e)| e)
            })
            .optional()?;
        Ok(found)
    }

    /// The record-order position of `id`, if it exists.
    pub fn rowid_of(&self, id: &str) -> rusqlite::Result<Option<i64>> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        conn.query_row("SELECT rowid FROM traffic WHERE id = ?1", [id], |r| r.get(0))
            .optional()
    }

    /// Up to `limit` entries recorded after position `rowid`, oldest first,
    /// with their positions (so a caller can page on).
    pub fn after(&self, rowid: i64, limit: usize) -> Result<Vec<(i64, TrafficEntry)>> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut stmt = conn.prepare(&format!(
            "SELECT {COLUMNS} FROM traffic WHERE rowid > ?1 ORDER BY rowid ASC LIMIT ?2"
        ))?;
        let rows = stmt.query_map(rusqlite::params![rowid, limit as i64], row_to_entry)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
}

/// `%text%` with LIKE's wildcards in `text` escaped, so `q=50%` means a
/// literal percent sign.
fn like_pattern(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('%');
    for c in text.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    out
}

fn row_to_entry(r: &Row) -> rusqlite::Result<(i64, TrafficEntry)> {
    let conversion = |i: usize, e: Box<dyn std::error::Error + Send + Sync>| {
        rusqlite::Error::FromSqlConversionFailure(i, rusqlite::types::Type::Text, e)
    };
    let headers = |i: usize| -> rusqlite::Result<Headers> {
        match r.get::<_, Option<String>>(i)? {
            Some(json) => serde_json::from_str(&json).map_err(|e| conversion(i, e.into())),
            None => Ok(Headers::new()),
        }
    };
    // NULL (rows from before v3) means utf8.
    let encoding = |i: usize| -> rusqlite::Result<BodyEncoding> {
        match r.get::<_, Option<String>>(i)?.as_deref() {
            None | Some("utf8") => Ok(BodyEncoding::Utf8),
            Some("base64") => Ok(BodyEncoding::Base64),
            Some(other) => Err(conversion(i, format!("unknown body encoding {other:?}").into())),
        }
    };
    let ts: String = r.get(2)?;
    let ts = DateTime::parse_from_rfc3339(&ts)
        .map_err(|e| conversion(2, e.into()))?
        .with_timezone(&Utc);
    let entry = TrafficEntry {
        id: r.get(1)?,
        ts,
        host: r.get(3)?,
        method: r.get(4)?,
        url: r.get(5)?,
        req_headers: headers(6)?,
        req_body: r.get(7)?,
        req_body_encoding: encoding(8)?,
        status: r.get(9)?,
        res_headers: headers(10)?,
        res_body: r.get(11)?,
        res_body_encoding: encoding(12)?,
        duration_ms: r.get(13)?,
        replay_of: r.get(14)?,
    };
    Ok((r.get(0)?, entry))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn entry(id: &str, host: &str, method: &str, status: u16, path: &str) -> TrafficEntry {
        TrafficEntry {
            id: id.into(),
            ts: Utc::now(),
            host: host.into(),
            method: method.into(),
            url: format!("https://{host}{path}"),
            req_headers: Headers::new(),
            req_body: None,
            req_body_encoding: BodyEncoding::Utf8,
            status: Some(status),
            res_headers: Headers::new(),
            res_body: None,
            res_body_encoding: BodyEncoding::Utf8,
            duration_ms: Some(1),
            replay_of: None,
        }
    }

    /// A db holding e0..e{n-1}, recorded in that order.
    fn db_with(n: usize) -> (TempDir, SqliteBackend) {
        let dir = TempDir::new().unwrap();
        let db = SqliteBackend::new(&dir.path().join("t.db")).unwrap();
        for i in 0..n {
            db.append(&entry(&format!("e{i}"), "api.example.com", "GET", 200, &format!("/item/{i}"))).unwrap();
        }
        (dir, db)
    }

    fn ids(entries: &[TrafficEntry]) -> Vec<&str> {
        entries.iter().map(|e| e.id.as_str()).collect()
    }

    #[test]
    fn query_is_newest_first_with_default_limit() {
        let (_d, db) = db_with(150);
        let page = db.query(&HistoryQuery::default()).unwrap();
        assert_eq!(page.len(), DEFAULT_LIMIT);
        assert_eq!(page[0].id, "e149");
        assert_eq!(page[99].id, "e50");
    }

    #[test]
    fn limit_is_capped() {
        let (_d, db) = db_with(MAX_LIMIT + 20);
        let q = HistoryQuery { limit: Some(10_000), ..Default::default() };
        assert_eq!(db.query(&q).unwrap().len(), MAX_LIMIT);
    }

    #[test]
    fn before_pages_back_without_gaps_or_overlap() {
        let (_d, db) = db_with(25);
        let mut seen = Vec::new();
        let mut before = None;
        loop {
            let q = HistoryQuery { limit: Some(10), before: before.clone(), ..Default::default() };
            let page = db.query(&q).unwrap();
            if page.is_empty() {
                break;
            }
            before = Some(page.last().unwrap().id.clone());
            seen.extend(page.into_iter().map(|e| e.id));
        }
        let expected: Vec<String> = (0..25).rev().map(|i| format!("e{i}")).collect();
        assert_eq!(seen, expected);
    }

    #[test]
    fn cursor_is_stable_while_new_entries_arrive() {
        let (_d, db) = db_with(10);
        let first = db.query(&HistoryQuery { limit: Some(3), ..Default::default() }).unwrap();
        assert_eq!(ids(&first), ["e9", "e8", "e7"]);
        db.append(&entry("new", "h", "GET", 200, "/")).unwrap();
        let q = HistoryQuery { limit: Some(3), before: Some("e7".into()), ..Default::default() };
        assert_eq!(ids(&db.query(&q).unwrap()), ["e6", "e5", "e4"]);
    }

    #[test]
    fn unknown_cursor_is_an_error() {
        let (_d, db) = db_with(3);
        let q = HistoryQuery { before: Some("nope".into()), ..Default::default() };
        assert!(matches!(db.query(&q), Err(HistoryError::UnknownCursor(id)) if id == "nope"));
    }

    #[test]
    fn filters_host_method_status_and_text_search() {
        let dir = TempDir::new().unwrap();
        let db = SqliteBackend::new(&dir.path().join("t.db")).unwrap();
        db.append(&entry("a", "API.example.com", "GET", 200, "/login")).unwrap();
        db.append(&entry("b", "api.example.com", "POST", 401, "/login")).unwrap();
        db.append(&entry("c", "cdn.other.io", "GET", 200, "/static/app.js")).unwrap();
        db.append(&entry("d", "api.example.com", "GET", 404, "/users/50%_off")).unwrap();

        let run = |q: HistoryQuery| ids(&db.query(&q).unwrap()).into_iter().map(String::from).collect::<Vec<_>>();
        assert_eq!(run(HistoryQuery { host: Some("example".into()), ..Default::default() }), ["d", "b", "a"]);
        assert_eq!(run(HistoryQuery { method: Some("post".into()), ..Default::default() }), ["b"]);
        assert_eq!(run(HistoryQuery { status: Some(200), ..Default::default() }), ["c", "a"]);
        assert_eq!(run(HistoryQuery { q: Some("LOGIN".into()), ..Default::default() }), ["b", "a"]);
        assert_eq!(run(HistoryQuery { q: Some("other.io".into()), ..Default::default() }), ["c"], "q matches host too");
        // LIKE wildcards in the search text are literal.
        assert_eq!(run(HistoryQuery { q: Some("50%_".into()), ..Default::default() }), ["d"]);
        assert_eq!(run(HistoryQuery { q: Some("_".into()), ..Default::default() }), ["d"]);
        assert_eq!(
            run(HistoryQuery { host: Some("example".into()), method: Some("GET".into()), status: Some(200), ..Default::default() }),
            ["a"]
        );
    }

    #[test]
    fn since_and_until_filter_on_ts() {
        let dir = TempDir::new().unwrap();
        let db = SqliteBackend::new(&dir.path().join("t.db")).unwrap();
        for (id, ts) in [("old", "2026-01-01T00:00:00Z"), ("mid", "2026-06-01T00:00:00.5Z"), ("new", "2026-11-01T00:00:00Z")] {
            let mut e = entry(id, "h", "GET", 200, "/");
            e.ts = ts.parse().unwrap();
            db.append(&e).unwrap();
        }
        let q = HistoryQuery {
            since: Some("2026-06-01T00:00:00Z".parse().unwrap()),
            until: Some("2026-11-01T00:00:00Z".parse().unwrap()),
            ..Default::default()
        };
        assert_eq!(ids(&db.query(&q).unwrap()), ["mid"], "since inclusive, until exclusive");
    }

    #[test]
    fn get_returns_the_full_v3_entry() {
        let dir = TempDir::new().unwrap();
        let db = SqliteBackend::new(&dir.path().join("t.db")).unwrap();
        let mut e = entry("full", "h", "POST", 201, "/x");
        e.req_headers.append("cookie", "a=1");
        e.res_headers.append("set-cookie", "s=1");
        e.res_headers.append("set-cookie", "t=2");
        e.set_req_body(b"text");
        e.set_res_body(&[0xff, 0x00, 0x80]);
        e.replay_of = Some("orig".into());
        e.ts = "2026-11-20T12:34:56.789012Z".parse().unwrap();
        db.append(&e).unwrap();

        assert_eq!(db.get("full").unwrap(), Some(e), "sqlite round-trip is exact");
        assert_eq!(db.get("missing").unwrap(), None);
    }

    #[test]
    fn after_returns_later_entries_oldest_first() {
        let (_d, db) = db_with(5);
        let from = db.rowid_of("e1").unwrap().unwrap();
        let got = db.after(from, 10).unwrap();
        assert_eq!(got.iter().map(|(_, e)| e.id.as_str()).collect::<Vec<_>>(), ["e2", "e3", "e4"]);
        assert!(got.windows(2).all(|w| w[0].0 < w[1].0));
        assert_eq!(db.after(from, 2).unwrap().len(), 2, "limit applies");
        assert_eq!(db.rowid_of("nope").unwrap(), None);
    }

    #[test]
    fn rows_from_a_v2_database_still_read() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("t.db");
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE traffic (id TEXT PRIMARY KEY, ts TEXT NOT NULL, host TEXT NOT NULL,
                    method TEXT NOT NULL, url TEXT NOT NULL, req_headers TEXT, req_body TEXT,
                    status INTEGER, res_headers TEXT, res_body TEXT, duration_ms INTEGER);
                 INSERT INTO traffic VALUES ('old','2026-01-01T00:00:00+00:00','h','GET','http://h/',
                    '{}',NULL,200,'{\"set-cookie\":\"a=1\"}','ok',5);",
            )
            .unwrap();
        }
        let db = SqliteBackend::new(&path).unwrap();
        let e = db.get("old").unwrap().unwrap();
        assert_eq!(e.res_headers.get("set-cookie"), Some("a=1"));
        assert_eq!(e.res_body_encoding, BodyEncoding::Utf8);
        assert_eq!(ids(&db.query(&HistoryQuery::default()).unwrap()), ["old"]);
    }

    #[test]
    fn like_pattern_escapes_wildcards() {
        assert_eq!(like_pattern("a%b_c\\d"), r"%a\%b\_c\\d%");
    }
}
