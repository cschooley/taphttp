//! What flows after the exchange (#26): WebSocket messages relayed between
//! client and upstream, and the events of a `text/event-stream` response,
//! each recorded as a [`Message`] on the exchange that opened them.

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, Incoming};
use hyper_util::rt::TokioIo;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use taphttp_types::{encode_body, Direction, Message, MessageKind, Opcode, Timestamp};
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::WebSocketStream;

use crate::storage::Store;

/// The most payload kept per message; `size` still says the full length.
pub const MESSAGE_CAP: usize = 1 << 20;

/// Records messages for one exchange, numbering them in the order seen.
#[derive(Clone)]
pub struct Recorder {
    store: Arc<Store>,
    exchange_id: String,
    seq: Arc<AtomicU64>,
}

impl Recorder {
    pub fn new(store: Arc<Store>, exchange_id: String) -> Self {
        Self {
            store,
            exchange_id,
            seq: Default::default(),
        }
    }

    fn message(&self, kind: MessageKind, direction: Direction) -> Message {
        Message {
            exchange_id: self.exchange_id.clone(),
            seq: self.seq.fetch_add(1, Ordering::SeqCst),
            ts: Timestamp::now(),
            kind,
            direction,
            opcode: None,
            event: None,
            event_id: None,
            size: 0,
            data: None,
            data_encoding: Default::default(),
            truncated: false,
        }
    }

    fn websocket(&self, direction: Direction, msg: &WsMessage) {
        let (opcode, payload): (Opcode, Vec<u8>) = match msg {
            WsMessage::Text(t) => (Opcode::Text, t.as_bytes().to_vec()),
            WsMessage::Binary(b) => (Opcode::Binary, b.to_vec()),
            WsMessage::Ping(b) => (Opcode::Ping, b.to_vec()),
            WsMessage::Pong(b) => (Opcode::Pong, b.to_vec()),
            // As on the wire: a 2-byte code, then the reason.
            WsMessage::Close(frame) => (
                Opcode::Close,
                frame
                    .as_ref()
                    .map(|f| {
                        let mut p = u16::from(f.code).to_be_bytes().to_vec();
                        p.extend_from_slice(f.reason.as_bytes());
                        p
                    })
                    .unwrap_or_default(),
            ),
            WsMessage::Frame(_) => return,
        };
        let mut m = self.message(MessageKind::Websocket, direction);
        m.opcode = Some(opcode);
        m.set_data(&payload, MESSAGE_CAP);
        self.store.record_message(m);
    }

    fn sse(&self, event: SseEvent) {
        let mut m = self.message(MessageKind::Sse, Direction::ServerToClient);
        m.event = event.event;
        m.event_id = event.id;
        m.size = event.size as u64;
        m.truncated = event.size > event.data.len();
        (m.data, m.data_encoding) = encode_body(&event.data);
        self.store.record_message(m);
    }
}

// ---------------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------------

/// Whether `headers` ask to upgrade to a WebSocket.
pub fn is_websocket_upgrade(headers: &hyper::HeaderMap) -> bool {
    headers
        .get_all(hyper::header::UPGRADE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case("websocket"))
}

/// Relay messages between the upgraded client and upstream connections
/// until either side closes (or `stop` resolves), recording each one if
/// `recorder` is set.
///
/// The relay re-frames: messages are passed whole, so a fragmented message
/// arrives as one. Extensions are not negotiated (the proxy strips
/// `Sec-WebSocket-Extensions`), so frames are never compressed.
pub async fn relay_websocket(
    client: hyper::upgrade::OnUpgrade,
    upstream: hyper::upgrade::OnUpgrade,
    recorder: Option<Recorder>,
    stop: impl std::future::Future<Output = ()>,
) {
    let (client, upstream) = match tokio::try_join!(client, upstream) {
        Ok(both) => both,
        Err(e) => {
            tracing::debug!("websocket upgrade failed: {e}");
            return;
        }
    };
    let client = WebSocketStream::from_raw_socket(TokioIo::new(client), Role::Server, None).await;
    let upstream =
        WebSocketStream::from_raw_socket(TokioIo::new(upstream), Role::Client, None).await;
    let (mut client_tx, mut client_rx) = client.split();
    let (mut upstream_tx, mut upstream_rx) = upstream.split();

    let up = {
        let recorder = recorder.clone();
        async move {
            while let Some(Ok(msg)) = client_rx.next().await {
                if let Some(r) = &recorder {
                    r.websocket(Direction::ClientToServer, &msg);
                }
                let close = msg.is_close();
                if upstream_tx.send(msg).await.is_err() || close {
                    break;
                }
            }
            let _ = upstream_tx.close().await;
        }
    };
    let down = async move {
        while let Some(Ok(msg)) = upstream_rx.next().await {
            if let Some(r) = &recorder {
                r.websocket(Direction::ServerToClient, &msg);
            }
            let close = msg.is_close();
            if client_tx.send(msg).await.is_err() || close {
                break;
            }
        }
        let _ = client_tx.close().await;
    };
    tokio::select! {
        _ = futures_util::future::join(up, down) => {}
        _ = stop => {}
    }
}

// ---------------------------------------------------------------------------
// Server-Sent Events
// ---------------------------------------------------------------------------

/// Whether a response is an event stream: streamed through, not buffered.
pub fn is_event_stream(headers: &hyper::HeaderMap) -> bool {
    headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("text/event-stream"))
}

/// One dispatched event.
#[derive(Debug, Clone, PartialEq)]
pub struct SseEvent {
    pub event: Option<String>,
    pub id: Option<String>,
    /// The `data:` lines joined with `\n`, at most the cap.
    pub data: Vec<u8>,
    /// The full length of the data.
    pub size: usize,
}

/// An incremental `text/event-stream` parser (the WHATWG HTML rules: lines
/// end with CRLF, LF or CR; a blank line dispatches; `:` starts a comment;
/// an event without data isn't dispatched). Memory is bounded by `cap`.
pub struct SseParser {
    cap: usize,
    line: Vec<u8>,
    after_cr: bool,
    started: bool,
    data: Vec<u8>,
    size: usize,
    has_data: bool,
    event: Option<String>,
    id: Option<String>,
}

impl SseParser {
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            line: Vec::new(),
            after_cr: false,
            started: false,
            data: Vec::new(),
            size: 0,
            has_data: false,
            event: None,
            id: None,
        }
    }

    /// Feed a chunk; returns the events it completed.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<SseEvent> {
        let mut out = Vec::new();
        for &b in chunk {
            if self.after_cr {
                self.after_cr = false;
                if b == b'\n' {
                    continue;
                }
            }
            match b {
                b'\r' => {
                    self.after_cr = true;
                    self.end_line(&mut out);
                }
                b'\n' => self.end_line(&mut out),
                // A field name plus `cap` bytes of value is all anyone keeps.
                _ if self.line.len() <= self.cap + 16 => self.line.push(b),
                _ => {}
            }
        }
        out
    }

    fn end_line(&mut self, out: &mut Vec<SseEvent>) {
        let mut line = std::mem::take(&mut self.line);
        if !self.started {
            self.started = true;
            if line.starts_with(b"\xEF\xBB\xBF") {
                line.drain(..3);
            }
        }
        if line.is_empty() {
            if self.has_data {
                out.push(SseEvent {
                    event: self.event.take(),
                    id: self.id.take(),
                    data: std::mem::take(&mut self.data),
                    size: self.size,
                });
            }
            self.event = None;
            self.id = None;
            self.data.clear();
            self.size = 0;
            self.has_data = false;
            return;
        }
        if line[0] == b':' {
            return;
        }
        let (field, value) = match line.iter().position(|&c| c == b':') {
            Some(i) => {
                let v = &line[i + 1..];
                (&line[..i], v.strip_prefix(b" ").unwrap_or(v))
            }
            None => (&line[..], &b""[..]),
        };
        match field {
            b"data" => {
                if self.has_data {
                    self.append(b"\n");
                }
                self.append(value);
                self.has_data = true;
            }
            b"event" => self.event = Some(String::from_utf8_lossy(value).into_owned()),
            b"id" if !value.contains(&0) => {
                self.id = Some(String::from_utf8_lossy(value).into_owned())
            }
            _ => {}
        }
    }

    fn append(&mut self, bytes: &[u8]) {
        self.size += bytes.len();
        let room = self.cap.saturating_sub(self.data.len());
        self.data.extend_from_slice(&bytes[..bytes.len().min(room)]);
    }
}

/// A response body passed through to the client as it arrives, with each
/// complete event recorded on the way.
pub struct SseTap {
    inner: Incoming,
    parse: Option<(SseParser, Recorder)>,
}

impl SseTap {
    /// `recorder` is `None` to pass the stream through unrecorded (a
    /// `--filter-host` miss, or a compressed stream taphttp can't read).
    pub fn new(inner: Incoming, recorder: Option<Recorder>) -> Self {
        Self {
            inner,
            parse: recorder.map(|r| (SseParser::new(MESSAGE_CAP), r)),
        }
    }

    pub fn boxed(self) -> crate::proxy::ProxyBody {
        BodyExt::boxed_unsync(BodyExt::map_err(self, Into::into))
    }
}

impl Body for SseTap {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        if let (Poll::Ready(Some(Ok(frame))), Some((parser, recorder))) = (&polled, &mut this.parse)
        {
            if let Some(data) = frame.data_ref() {
                for event in parser.push(data) {
                    recorder.sse(event);
                }
            }
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(event: Option<&str>, id: Option<&str>, data: &str) -> SseEvent {
        SseEvent {
            event: event.map(String::from),
            id: id.map(String::from),
            data: data.as_bytes().to_vec(),
            size: data.len(),
        }
    }

    #[test]
    fn parses_events_fields_comments_and_multiline_data() {
        let mut p = SseParser::new(1024);
        let got = p.push(
            b": a comment\n\
              event: update\nid: 7\ndata: first\ndata:second\n\n\
              data: plain\n\n\
              event: empty\n\n\
              retry: 10\nunknown: x\ndata\n\n",
        );
        assert_eq!(
            got,
            [
                ev(Some("update"), Some("7"), "first\nsecond"),
                ev(None, None, "plain"),
                // `event: empty` had no data, so nothing was dispatched;
                // a bare `data` line is an empty data line.
                ev(None, None, ""),
            ]
        );
    }

    #[test]
    fn handles_every_line_ending_and_chunk_boundary() {
        let stream = b"\xEF\xBB\xBFdata: a\r\n\r\ndata: b\r\rdata: c\n\n";
        let want = [
            ev(None, None, "a"),
            ev(None, None, "b"),
            ev(None, None, "c"),
        ];
        // All at once, and one byte at a time (a CRLF split across chunks
        // must not end two lines).
        let mut p = SseParser::new(1024);
        assert_eq!(p.push(stream), want);
        let mut p = SseParser::new(1024);
        let mut got = Vec::new();
        for b in stream {
            got.extend(p.push(&[*b]));
        }
        assert_eq!(got, want);
    }

    #[test]
    fn an_unfinished_event_is_not_dispatched() {
        let mut p = SseParser::new(1024);
        assert!(p.push(b"data: half").is_empty());
        assert!(p.push(b"\n").is_empty());
        assert_eq!(p.push(b"\n"), [ev(None, None, "half")]);
    }

    #[test]
    fn data_is_capped_but_size_is_counted_in_full() {
        let mut p = SseParser::new(4);
        let got = p.push(b"data: abcdef\ndata: gh\n\n");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].data, b"abcd");
        assert_eq!(got[0].size, "abcdef\ngh".len());
        // An endless line doesn't grow without bound.
        let mut p = SseParser::new(4);
        p.push(&[b'x'; 10_000]);
        assert!(p.line.len() <= 4 + 17);
    }

    #[test]
    fn detects_websocket_upgrades_and_event_streams() {
        let mut h = hyper::HeaderMap::new();
        h.insert("upgrade", "WebSocket".parse().unwrap());
        assert!(is_websocket_upgrade(&h));
        h.insert("upgrade", "h2c".parse().unwrap());
        assert!(!is_websocket_upgrade(&h));
        let mut h = hyper::HeaderMap::new();
        h.insert(
            "content-type",
            "Text/Event-Stream; charset=utf-8".parse().unwrap(),
        );
        assert!(is_event_stream(&h));
        h.insert("content-type", "text/plain".parse().unwrap());
        assert!(!is_event_stream(&h));
    }
}
