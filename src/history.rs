//! Reading traffic history back out of sqlite: paging, filtering, search,
//! lookup by id, and "everything after this id" for resuming `/feed`.
//!
//! Order is record order: sqlite's rowid, which increases as `Store::record`
//! inserts. Paging (`before`) and feed resume (`after`) both use it, so the
//! two agree and a cursor is stable. `ts` isn't used for ordering: entries
//! from concurrent connections are recorded slightly out of `ts` order.

use anyhow::Result;
use rusqlite::types::ToSql;
use rusqlite::{OptionalExtension, Row};
use serde::Deserialize;
use taphttp_types::Timestamp;

use crate::storage::{Headers, SqliteBackend, TrafficEntry};
use taphttp_types::{BodyEncoding, Origin};

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
    /// Status codes and/or classes: `404`, `4xx`, `401,403,5xx`.
    pub status: Option<StatusFilter>,
    /// Substring of the URL or host, case-insensitive.
    pub q: Option<String>,
    /// Only entries with `ts` at or after this RFC 3339 time.
    pub since: Option<Timestamp>,
    /// Only entries with `ts` before this RFC 3339 time.
    pub until: Option<Timestamp>,
    /// Only replays of the exchange with this id.
    pub replay_of: Option<String>,
    /// Only exchanges recorded this way.
    pub origin: Option<Origin>,
    /// Only refused exchanges (`true`) or only the rest (`false`).
    pub refused: Option<bool>,
    /// Cursor: only entries recorded before the entry with this id.
    pub before: Option<String>,
    /// Page size; default [`DEFAULT_LIMIT`], capped at [`MAX_LIMIT`].
    pub limit: Option<usize>,
}

/// A `status` filter: exact codes and/or classes (`4xx` = 400..=499),
/// comma-separated. Matches if any term matches.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatusFilter {
    pub codes: Vec<u16>,
    pub classes: Vec<u8>,
}

impl std::str::FromStr for StatusFilter {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let mut f = Self::default();
        for term in s.split(',').map(str::trim) {
            let lower = term.to_ascii_lowercase();
            if let Some(d) = lower.strip_suffix("xx").filter(|d| d.len() == 1) {
                match d.parse::<u8>() {
                    Ok(c @ 1..=5) => f.classes.push(c),
                    _ => return Err(format!("status class {term:?}: use 1xx to 5xx")),
                }
            } else {
                match term.parse::<u16>() {
                    Ok(c @ 100..=599) => f.codes.push(c),
                    _ => {
                        return Err(format!(
                        "status {term:?}: expected a code (404), a class (4xx), or a comma list"
                    ))
                    }
                }
            }
        }
        Ok(f)
    }
}

impl<'de> Deserialize<'de> for StatusFilter {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
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
    req_body_encoding, status, res_headers, res_body, res_body_encoding, duration_ms, replay_of, source, meta, error, origin, peer, refused";

impl SqliteBackend {
    /// Newest first, filtered, at most `limit` entries.
    pub fn query(&self, q: &HistoryQuery) -> Result<Vec<TrafficEntry>, HistoryError> {
        let mut sql = format!("SELECT {COLUMNS} FROM traffic WHERE 1=1");
        let mut params: Vec<Box<dyn ToSql>> = Vec::new();

        if let Some(id) = &q.before {
            let rowid = self
                .rowid_of(id)?
                .ok_or_else(|| HistoryError::UnknownCursor(id.clone()))?;
            sql.push_str(" AND rowid < ?");
            params.push(Box::new(rowid));
        }
        if let Some(of) = &q.replay_of {
            sql.push_str(" AND replay_of = ?");
            params.push(Box::new(of.clone()));
        }
        if let Some(origin) = q.origin {
            sql.push_str(" AND origin = ?");
            params.push(Box::new(crate::storage::origin_str(origin)));
        }
        if let Some(refused) = q.refused {
            sql.push_str(if refused {
                " AND refused = 1"
            } else {
                " AND (refused IS NULL OR refused = 0)"
            });
        }
        if let Some(host) = &q.host {
            sql.push_str(r" AND host LIKE ? ESCAPE '\'");
            params.push(Box::new(like_pattern(host)));
        }
        if let Some(method) = &q.method {
            sql.push_str(" AND method = ?");
            params.push(Box::new(method.to_uppercase()));
        }
        if let Some(status) = &q.status {
            let mut terms = Vec::new();
            for code in &status.codes {
                terms.push("status = ?");
                params.push(Box::new(*code));
            }
            for class in &status.classes {
                terms.push("(status >= ? AND status < ?)");
                params.push(Box::new(u16::from(*class) * 100));
                params.push(Box::new(u16::from(*class) * 100 + 100));
            }
            sql.push_str(&format!(" AND ({})", terms.join(" OR ")));
        }
        if let Some(text) = &q.q {
            sql.push_str(r" AND (url LIKE ? ESCAPE '\' OR host LIKE ? ESCAPE '\')");
            params.push(Box::new(like_pattern(text)));
            params.push(Box::new(like_pattern(text)));
        }
        if let Some(since) = q.since {
            sql.push_str(" AND ts_us >= ?");
            params.push(Box::new(since.unix_micros()));
        }
        if let Some(until) = q.until {
            sql.push_str(" AND ts_us < ?");
            params.push(Box::new(until.unix_micros()));
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
            .query_row(
                &format!("SELECT {COLUMNS} FROM traffic WHERE id = ?1"),
                [id],
                |r| row_to_entry(r).map(|(_, e)| e),
            )
            .optional()?;
        Ok(found)
    }

    /// The record-order position of `id`, if it exists.
    pub fn rowid_of(&self, id: &str) -> rusqlite::Result<Option<i64>> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        conn.query_row("SELECT rowid FROM traffic WHERE id = ?1", [id], |r| {
            r.get(0)
        })
        .optional()
    }

    /// Up to `limit` messages of exchange `id`, in sequence order, starting
    /// after `after` (a `seq`) if given.
    pub fn messages(
        &self,
        id: &str,
        after: Option<u64>,
        limit: usize,
    ) -> Result<Vec<taphttp_types::Message>> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let mut stmt = conn.prepare(
            "SELECT exchange_id, seq, ts, kind, direction, opcode, event, event_id, size,
                data, data_encoding, truncated
             FROM messages WHERE exchange_id = ?1 AND seq > ?2 ORDER BY seq ASC LIMIT ?3",
        )?;
        let after = after.map_or(-1, |a| i64::try_from(a).unwrap_or(i64::MAX));
        let rows = stmt.query_map(rusqlite::params![id, after, limit as i64], row_to_message)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
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
            Some(other) => Err(conversion(
                i,
                format!("unknown body encoding {other:?}").into(),
            )),
        }
    };
    let ts: String = r.get(2)?;
    let ts: Timestamp = ts.parse().map_err(|e| conversion(2, Box::new(e)))?;
    let replay_of: Option<String> = r.get(14)?;
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
        duration_ms: r
            .get::<_, Option<i64>>(13)?
            .and_then(|d| u64::try_from(d).ok()),
        source: r.get(15)?,
        meta: match r.get::<_, Option<String>>(16)? {
            Some(json) => serde_json::from_str(&json).map_err(|e| conversion(16, e.into()))?,
            None => Default::default(),
        },
        error: r.get(17)?,
        origin: match r.get::<_, Option<String>>(18)?.as_deref() {
            Some("proxy") => Origin::Proxy,
            Some("replay") => Origin::Replay,
            Some("send") => Origin::Send,
            // Filled in on open; only a row written since by an older
            // taphttp lacks it.
            None if replay_of.is_some() => Origin::Replay,
            None => Origin::Proxy,
            Some(other) => return Err(conversion(18, format!("unknown origin {other:?}").into())),
        },
        replay_of,
        peer: match r.get::<_, Option<String>>(19)? {
            Some(text) => Some(text.parse().map_err(|e| conversion(19, Box::new(e)))?),
            None => None,
        },
        refused: r.get::<_, Option<bool>>(20)?.unwrap_or(false),
    };
    Ok((r.get(0)?, entry))
}

fn row_to_message(r: &Row) -> rusqlite::Result<taphttp_types::Message> {
    fn parse<T: serde::de::DeserializeOwned>(r: &Row, i: usize) -> rusqlite::Result<T> {
        let s: String = r.get(i)?;
        serde_json::from_value(serde_json::Value::String(s)).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(i, rusqlite::types::Type::Text, e.into())
        })
    }
    let ts: String = r.get(2)?;
    Ok(taphttp_types::Message {
        exchange_id: r.get(0)?,
        seq: r.get::<_, i64>(1)?.try_into().unwrap_or(0),
        ts: ts.parse().map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e))
        })?,
        kind: parse(r, 3)?,
        direction: parse(r, 4)?,
        opcode: match r.get::<_, Option<String>>(5)? {
            Some(_) => Some(parse(r, 5)?),
            None => None,
        },
        event: r.get(6)?,
        event_id: r.get(7)?,
        size: r.get::<_, i64>(8)?.try_into().unwrap_or(0),
        data: r.get(9)?,
        data_encoding: parse(r, 10)?,
        truncated: r.get(11)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn entry(id: &str, host: &str, method: &str, status: u16, path: &str) -> TrafficEntry {
        TrafficEntry {
            id: id.into(),
            ts: Timestamp::now(),
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
            source: None,
            meta: Default::default(),
            error: None,
            origin: crate::storage::Origin::Proxy,
            peer: None,
            refused: false,
        }
    }

    /// A db holding e0..e{n-1}, recorded in that order.
    fn db_with(n: usize) -> (TempDir, SqliteBackend) {
        let dir = TempDir::new().unwrap();
        let db = SqliteBackend::new(&dir.path().join("t.db")).unwrap();
        for i in 0..n {
            db.append(&entry(
                &format!("e{i}"),
                "api.example.com",
                "GET",
                200,
                &format!("/item/{i}"),
            ))
            .unwrap();
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
        let q = HistoryQuery {
            limit: Some(10_000),
            ..Default::default()
        };
        assert_eq!(db.query(&q).unwrap().len(), MAX_LIMIT);
    }

    #[test]
    fn before_pages_back_without_gaps_or_overlap() {
        let (_d, db) = db_with(25);
        let mut seen = Vec::new();
        let mut before = None;
        loop {
            let q = HistoryQuery {
                limit: Some(10),
                before: before.clone(),
                ..Default::default()
            };
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
        let first = db
            .query(&HistoryQuery {
                limit: Some(3),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(ids(&first), ["e9", "e8", "e7"]);
        db.append(&entry("new", "h", "GET", 200, "/")).unwrap();
        let q = HistoryQuery {
            limit: Some(3),
            before: Some("e7".into()),
            ..Default::default()
        };
        assert_eq!(ids(&db.query(&q).unwrap()), ["e6", "e5", "e4"]);
    }

    #[test]
    fn unknown_cursor_is_an_error() {
        let (_d, db) = db_with(3);
        let q = HistoryQuery {
            before: Some("nope".into()),
            ..Default::default()
        };
        assert!(matches!(db.query(&q), Err(HistoryError::UnknownCursor(id)) if id == "nope"));
    }

    #[test]
    fn filters_host_method_status_and_text_search() {
        let dir = TempDir::new().unwrap();
        let db = SqliteBackend::new(&dir.path().join("t.db")).unwrap();
        db.append(&entry("a", "API.example.com", "GET", 200, "/login"))
            .unwrap();
        db.append(&entry("b", "api.example.com", "POST", 401, "/login"))
            .unwrap();
        db.append(&entry("c", "cdn.other.io", "GET", 200, "/static/app.js"))
            .unwrap();
        db.append(&entry("d", "api.example.com", "GET", 404, "/users/50%_off"))
            .unwrap();

        let run = |q: HistoryQuery| {
            ids(&db.query(&q).unwrap())
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            run(HistoryQuery {
                host: Some("example".into()),
                ..Default::default()
            }),
            ["d", "b", "a"]
        );
        assert_eq!(
            run(HistoryQuery {
                method: Some("post".into()),
                ..Default::default()
            }),
            ["b"]
        );
        assert_eq!(
            run(HistoryQuery {
                status: Some("200".parse().unwrap()),
                ..Default::default()
            }),
            ["c", "a"]
        );
        assert_eq!(
            run(HistoryQuery {
                q: Some("LOGIN".into()),
                ..Default::default()
            }),
            ["b", "a"]
        );
        assert_eq!(
            run(HistoryQuery {
                q: Some("other.io".into()),
                ..Default::default()
            }),
            ["c"],
            "q matches host too"
        );
        // LIKE wildcards in the search text are literal.
        assert_eq!(
            run(HistoryQuery {
                q: Some("50%_".into()),
                ..Default::default()
            }),
            ["d"]
        );
        assert_eq!(
            run(HistoryQuery {
                q: Some("_".into()),
                ..Default::default()
            }),
            ["d"]
        );
        assert_eq!(
            run(HistoryQuery {
                host: Some("example".into()),
                method: Some("GET".into()),
                status: Some("200".parse().unwrap()),
                ..Default::default()
            }),
            ["a"]
        );
    }

    #[test]
    fn status_filter_matches_codes_classes_and_lists() {
        let dir = TempDir::new().unwrap();
        let db = SqliteBackend::new(&dir.path().join("t.db")).unwrap();
        for (id, code) in [
            ("ok", 200),
            ("redir", 302),
            ("unauth", 401),
            ("forbid", 403),
            ("missing", 404),
            ("boom", 503),
        ] {
            db.append(&entry(id, "h", "GET", code, "/")).unwrap();
        }
        let run = |f: &str| {
            let q = HistoryQuery {
                status: Some(f.parse().unwrap()),
                ..Default::default()
            };
            ids(&db.query(&q).unwrap())
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        };
        assert_eq!(run("404"), ["missing"]);
        assert_eq!(run("4xx"), ["missing", "forbid", "unauth"]);
        assert_eq!(run("4XX"), ["missing", "forbid", "unauth"]);
        assert_eq!(run("401,403"), ["forbid", "unauth"]);
        assert_eq!(run("2xx,5xx"), ["boom", "ok"]);
        assert_eq!(run("302,5xx"), ["boom", "redir"]);
    }

    #[test]
    fn status_filter_pages_with_before() {
        let dir = TempDir::new().unwrap();
        let db = SqliteBackend::new(&dir.path().join("t.db")).unwrap();
        for i in 0..10 {
            db.append(&entry(
                &format!("e{i}"),
                "h",
                "GET",
                if i % 2 == 0 { 404 } else { 200 },
                "/",
            ))
            .unwrap();
        }
        let q = |before: Option<&str>| HistoryQuery {
            status: Some("4xx".parse().unwrap()),
            limit: Some(2),
            before: before.map(String::from),
            ..Default::default()
        };
        assert_eq!(ids(&db.query(&q(None)).unwrap()), ["e8", "e6"]);
        assert_eq!(ids(&db.query(&q(Some("e6"))).unwrap()), ["e4", "e2"]);
    }

    #[test]
    fn status_filter_rejects_garbage() {
        for bad in ["", "4x", "6xx", "0xx", "99", "600", "abc", "4xx,", "40x"] {
            assert!(bad.parse::<StatusFilter>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn source_round_trips_through_sqlite() {
        let dir = TempDir::new().unwrap();
        let db = SqliteBackend::new(&dir.path().join("t.db")).unwrap();
        let mut e = entry("s", "h", "GET", 200, "/");
        e.source = Some("agent.T-3".into());
        db.append(&e).unwrap();
        assert_eq!(
            db.get("s").unwrap().unwrap().source.as_deref(),
            Some("agent.T-3")
        );
    }

    #[test]
    fn meta_and_error_round_trip_through_sqlite() {
        let dir = TempDir::new().unwrap();
        let db = SqliteBackend::new(&dir.path().join("t.db")).unwrap();
        let mut e = entry("m", "h", "GET", 200, "/");
        e.meta.insert("actor".into(), "agent".into());
        e.meta.insert("task_id".into(), "T-3".into());
        e.status = None;
        e.error = Some("sending request: connection refused".into());
        db.append(&e).unwrap();
        let plain = entry("p", "h", "GET", 200, "/");
        db.append(&plain).unwrap();
        assert_eq!(db.get("m").unwrap().unwrap(), e);
        assert_eq!(db.get("p").unwrap().unwrap(), plain, "empty meta, no error");
    }

    #[test]
    fn replay_of_filter_finds_an_exchanges_replays_and_pages() {
        let dir = TempDir::new().unwrap();
        let db = SqliteBackend::new(&dir.path().join("t.db")).unwrap();
        db.append(&entry("orig", "h", "GET", 200, "/")).unwrap();
        db.append(&entry("other", "h", "GET", 200, "/")).unwrap();
        for (id, of) in [
            ("r1", "orig"),
            ("x1", "other"),
            ("r2", "orig"),
            ("r3", "orig"),
        ] {
            let mut e = entry(id, "h", "GET", 200, "/");
            e.replay_of = Some(of.into());
            db.append(&e).unwrap();
        }
        let q = |before: Option<&str>| HistoryQuery {
            replay_of: Some("orig".into()),
            limit: Some(2),
            before: before.map(String::from),
            ..Default::default()
        };
        assert_eq!(ids(&db.query(&q(None)).unwrap()), ["r3", "r2"]);
        assert_eq!(ids(&db.query(&q(Some("r2"))).unwrap()), ["r1"]);
        let none = HistoryQuery {
            replay_of: Some("r1".into()),
            ..Default::default()
        };
        assert!(db.query(&none).unwrap().is_empty());
    }

    #[test]
    fn replay_of_filter_uses_an_index() {
        let dir = TempDir::new().unwrap();
        let db = SqliteBackend::new(&dir.path().join("t.db")).unwrap();
        let conn = db.conn.lock().unwrap();
        let plan: String = conn
            .query_row(
                "EXPLAIN QUERY PLAN SELECT rowid FROM traffic WHERE replay_of = 'x'",
                [],
                |r| r.get(3),
            )
            .unwrap();
        assert!(plan.contains("traffic_replay_of"), "{plan}");
    }

    #[test]
    fn since_and_until_filter_on_ts() {
        let dir = TempDir::new().unwrap();
        let db = SqliteBackend::new(&dir.path().join("t.db")).unwrap();
        for (id, ts) in [
            ("old", "2026-01-01T00:00:00Z"),
            ("mid", "2026-06-01T00:00:00.5Z"),
            ("new", "2026-11-01T00:00:00Z"),
        ] {
            let mut e = entry(id, "h", "GET", 200, "/");
            e.ts = ts.parse().unwrap();
            db.append(&e).unwrap();
        }
        let q = HistoryQuery {
            since: Some("2026-06-01T00:00:00Z".parse().unwrap()),
            until: Some("2026-11-01T00:00:00Z".parse().unwrap()),
            ..Default::default()
        };
        assert_eq!(
            ids(&db.query(&q).unwrap()),
            ["mid"],
            "since inclusive, until exclusive"
        );
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

        assert_eq!(
            db.get("full").unwrap(),
            Some(e),
            "sqlite round-trip is exact"
        );
        assert_eq!(db.get("missing").unwrap(), None);
    }

    #[test]
    fn after_returns_later_entries_oldest_first() {
        let (_d, db) = db_with(5);
        let from = db.rowid_of("e1").unwrap().unwrap();
        let got = db.after(from, 10).unwrap();
        assert_eq!(
            got.iter().map(|(_, e)| e.id.as_str()).collect::<Vec<_>>(),
            ["e2", "e3", "e4"]
        );
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
    fn origin_round_trips_and_filters() {
        let dir = TempDir::new().unwrap();
        let db = SqliteBackend::new(&dir.path().join("t.db")).unwrap();
        let proxied = entry("p", "h", "GET", 200, "/");
        let mut replay = entry("r", "h", "GET", 200, "/");
        replay.replay_of = Some("p".into());
        replay.origin = Origin::Replay;
        let mut sent = entry("s", "h", "GET", 200, "/");
        sent.origin = Origin::Send;
        for e in [&proxied, &replay, &sent] {
            db.append(e).unwrap();
            assert_eq!(&db.get(&e.id).unwrap().unwrap(), e);
        }
        let only = |o| -> Vec<String> {
            db.query(&HistoryQuery {
                origin: Some(o),
                ..Default::default()
            })
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect()
        };
        assert_eq!(only(Origin::Send), ["s"]);
        assert_eq!(only(Origin::Replay), ["r"]);
        assert_eq!(only(Origin::Proxy), ["p"]);
    }

    #[test]
    fn peer_round_trips_v4_and_v6_addresses() {
        let dir = TempDir::new().unwrap();
        let db = SqliteBackend::new(&dir.path().join("t.db")).unwrap();
        for (id, peer) in [
            ("v4", Some("203.0.113.7:443")),
            ("v6", Some("[2001:db8::1]:8443")),
            ("none", None),
        ] {
            let mut e = entry(id, "h", "GET", 200, "/");
            e.peer = peer.map(|p| p.parse().unwrap());
            db.append(&e).unwrap();
            assert_eq!(db.get(id).unwrap().unwrap().peer, e.peer, "{id}");
        }
    }

    #[test]
    fn refused_round_trips_and_filters() {
        let dir = TempDir::new().unwrap();
        let db = SqliteBackend::new(&dir.path().join("t.db")).unwrap();
        let sent = entry("sent", "h", "GET", 200, "/");
        let mut refused = entry("no", "h", "GET", 200, "/");
        refused.status = None;
        refused.refused = true;
        refused.error = Some("refused: host not allowed".into());
        for e in [&sent, &refused] {
            db.append(e).unwrap();
            assert_eq!(&db.get(&e.id).unwrap().unwrap(), e);
        }
        let only = |r| -> Vec<String> {
            db.query(&HistoryQuery {
                refused: Some(r),
                ..Default::default()
            })
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect()
        };
        assert_eq!(only(true), ["no"]);
        assert_eq!(only(false), ["sent"]);
    }

    #[test]
    fn rows_from_before_v6_get_an_origin_from_replay_of() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("t.db");
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE traffic (id TEXT PRIMARY KEY, ts TEXT NOT NULL, host TEXT NOT NULL,
                    method TEXT NOT NULL, url TEXT NOT NULL, req_headers TEXT, req_body TEXT,
                    status INTEGER, res_headers TEXT, res_body TEXT, duration_ms INTEGER,
                    replay_of TEXT);
                 INSERT INTO traffic VALUES ('old','2026-01-01T00:00:00+00:00','h','GET','http://h/',
                    '[]',NULL,200,'[]','ok',5,NULL);
                 INSERT INTO traffic VALUES ('again','2026-01-01T00:00:01+00:00','h','GET','http://h/',
                    '[]',NULL,200,'[]','ok',5,'old');",
            )
            .unwrap();
        }
        let db = SqliteBackend::new(&path).unwrap();
        assert_eq!(db.get("old").unwrap().unwrap().origin, Origin::Proxy);
        assert_eq!(db.get("again").unwrap().unwrap().origin, Origin::Replay);
        assert_eq!(
            db.get("old").unwrap().unwrap().peer,
            None,
            "pre-v7: no peer"
        );
        let only = |o| -> Vec<String> {
            db.query(&HistoryQuery {
                origin: Some(o),
                ..Default::default()
            })
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect()
        };
        assert_eq!(only(Origin::Proxy), ["old"], "filled in on open");
        assert_eq!(only(Origin::Replay), ["again"]);
    }

    #[test]
    fn messages_page_in_sequence_order() {
        use taphttp_types::{Direction, Message, MessageKind};
        let dir = TempDir::new().unwrap();
        let db = SqliteBackend::new(&dir.path().join("t.db")).unwrap();
        let msg = |ex: &str, seq: u64| {
            let mut m = Message {
                exchange_id: ex.into(),
                seq,
                ts: "2026-11-24T00:00:00.5Z".parse().unwrap(),
                kind: MessageKind::Sse,
                direction: Direction::ServerToClient,
                opcode: None,
                event: Some("tick".into()),
                event_id: Some(seq.to_string()),
                size: 0,
                data: None,
                data_encoding: BodyEncoding::Utf8,
                truncated: false,
            };
            m.set_data(format!("data {seq}").as_bytes(), 4);
            m
        };
        for seq in [2, 0, 1, 3] {
            db.append_message(&msg("a", seq)).unwrap();
        }
        db.append_message(&msg("b", 0)).unwrap();
        let seqs = |after, limit| -> Vec<u64> {
            db.messages("a", after, limit)
                .unwrap()
                .into_iter()
                .map(|m| m.seq)
                .collect()
        };
        assert_eq!(seqs(None, 10), [0, 1, 2, 3]);
        assert_eq!(seqs(None, 2), [0, 1]);
        assert_eq!(seqs(Some(1), 10), [2, 3]);
        assert_eq!(
            db.messages("a", None, 10).unwrap()[1],
            msg("a", 1),
            "round-trips"
        );
        assert!(db.messages("none", None, 10).unwrap().is_empty());
    }

    #[test]
    fn like_pattern_escapes_wildcards() {
        assert_eq!(like_pattern("a%b_c\\d"), r"%a\%b\_c\\d%");
    }
}
