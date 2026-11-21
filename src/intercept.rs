use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// Sent from proxy to interceptor — one connection per event.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InterceptEvent {
    Request(RequestEvent),
    Response(ResponseEvent),
}

#[derive(Debug, Serialize)]
pub struct RequestEvent {
    pub id: String,
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ResponseEvent {
    pub id: String,
    pub request_id: String,
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

/// Received from interceptor — what the proxy should do next.
#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Decision {
    Forward(ForwardDecision),
    Drop(DropDecision),
}

/// Forward the event, applying any overrides present.
#[derive(Debug, Deserialize, Default)]
pub struct ForwardDecision {
    pub method: Option<String>,
    pub url: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub body: Option<String>,
    pub status: Option<u16>,
}

/// Drop the event and return this status (and optional body) to the client.
#[derive(Debug, Deserialize, Default)]
pub struct DropDecision {
    pub status: Option<u16>,
    pub body: Option<String>,
}

/// Connect to the intercept socket, send the event as a JSON line, and
/// block until the interceptor writes a decision back as a JSON line.
pub async fn pause(socket_path: &Path, event: &InterceptEvent) -> Result<Decision> {
    let stream = UnixStream::connect(socket_path)
        .await
        .context("connecting to intercept socket")?;
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    let msg = serde_json::to_string(event).context("serializing intercept event")?;
    writer.write_all(msg.as_bytes()).await?;
    writer.write_all(b"\n").await?;

    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .context("reading intercept decision")?;

    serde_json::from_str(line.trim()).context("parsing intercept decision")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    async fn mock_interceptor(socket_path: PathBuf, reply: &'static str) {
        let listener = UnixListener::bind(&socket_path).unwrap();
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (reader, mut writer) = tokio::io::split(stream);
            let mut reader = BufReader::new(reader);
            let mut _line = String::new();
            reader.read_line(&mut _line).await.ok();
            writer.write_all(reply.as_bytes()).await.ok();
            writer.write_all(b"\n").await.ok();
        });
    }

    fn request_event() -> InterceptEvent {
        InterceptEvent::Request(RequestEvent {
            id: "test-id".to_string(),
            method: "GET".to_string(),
            url: "https://example.com/".to_string(),
            headers: HashMap::new(),
            body: None,
        })
    }

    #[tokio::test]
    async fn forward_decision_is_parsed() {
        let dir = TempDir::new().unwrap();
        let socket_path = dir.path().join("intercept.sock");
        mock_interceptor(socket_path.clone(), r#"{"action":"forward"}"#).await;

        let decision = pause(&socket_path, &request_event()).await.unwrap();
        assert!(matches!(decision, Decision::Forward(_)));
    }

    #[tokio::test]
    async fn drop_decision_with_status_is_parsed() {
        let dir = TempDir::new().unwrap();
        let socket_path = dir.path().join("intercept.sock");
        mock_interceptor(socket_path.clone(), r#"{"action":"drop","status":403}"#).await;

        let decision = pause(&socket_path, &request_event()).await.unwrap();
        match decision {
            Decision::Drop(d) => assert_eq!(d.status, Some(403)),
            _ => panic!("expected drop"),
        }
    }

    #[tokio::test]
    async fn forward_with_modifications_is_parsed() {
        let dir = TempDir::new().unwrap();
        let socket_path = dir.path().join("intercept.sock");
        mock_interceptor(
            socket_path.clone(),
            r#"{"action":"forward","method":"POST","body":"injected"}"#,
        )
        .await;

        let decision = pause(&socket_path, &request_event()).await.unwrap();
        match decision {
            Decision::Forward(d) => {
                assert_eq!(d.method.as_deref(), Some("POST"));
                assert_eq!(d.body.as_deref(), Some("injected"));
            }
            _ => panic!("expected forward"),
        }
    }

    #[tokio::test]
    async fn response_event_is_serialized_with_correct_type_tag() {
        let dir = TempDir::new().unwrap();
        let socket_path = dir.path().join("intercept.sock");

        let received = std::sync::Arc::new(tokio::sync::Mutex::new(String::new()));
        let received_clone = received.clone();

        let listener = UnixListener::bind(&socket_path).unwrap();
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (reader, mut writer) = tokio::io::split(stream);
            let mut reader = BufReader::new(reader);
            let mut line = String::new();
            reader.read_line(&mut line).await.ok();
            *received_clone.lock().await = line;
            writer.write_all(b"{\"action\":\"forward\"}\n").await.ok();
        });

        let event = InterceptEvent::Response(ResponseEvent {
            id: "resp-id".to_string(),
            request_id: "req-id".to_string(),
            status: 200,
            headers: HashMap::new(),
            body: Some("hello".to_string()),
        });
        pause(&socket_path, &event).await.unwrap();

        let json: serde_json::Value = serde_json::from_str(&received.lock().await).unwrap();
        assert_eq!(json["type"], "response");
        assert_eq!(json["status"], 200);
        assert_eq!(json["request_id"], "req-id");
    }

    #[tokio::test]
    async fn unavailable_socket_returns_error() {
        let dir = TempDir::new().unwrap();
        let socket_path = dir.path().join("does-not-exist.sock");
        let result = pause(&socket_path, &request_event()).await;
        assert!(result.is_err());
    }
}
