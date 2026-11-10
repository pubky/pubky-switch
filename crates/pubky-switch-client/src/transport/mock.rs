//! A scripted [`Transport`] for unit tests. Test builds only (`test-support`).

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard};

use super::{BoxFuture, Request, Response, Transport, TransportError};

type Handler = Box<dyn Fn(&Request) -> Result<Response, TransportError> + Send + Sync>;

/// A transport that answers from a script and records every request it is given.
///
/// Each call takes the next scripted answer; once the script is empty it calls the handler,
/// if one is set, and otherwise answers [`TransportError::Other`].
#[derive(Default)]
pub struct MockTransport {
    script: Mutex<VecDeque<Result<Response, TransportError>>>,
    handler: Option<Handler>,
    requests: Mutex<Vec<Request>>,
}

impl std::fmt::Debug for MockTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MockTransport({} requests)", lock(&self.requests).len())
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl MockTransport {
    /// A transport with an empty script.
    pub fn new() -> Self {
        Self::default()
    }

    /// A transport that answers every request with `handler`, after any scripted answers.
    pub fn with_handler(
        handler: impl Fn(&Request) -> Result<Response, TransportError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            handler: Some(Box::new(handler)),
            ..Self::default()
        }
    }

    /// Script the next answer.
    pub fn push_response(&self, response: Response) {
        lock(&self.script).push_back(Ok(response));
    }

    /// Script the next failure.
    pub fn push_error(&self, error: TransportError) {
        lock(&self.script).push_back(Err(error));
    }

    /// Every request sent so far, in order.
    pub fn requests(&self) -> Vec<Request> {
        lock(&self.requests).clone()
    }

    /// The last request sent.
    pub fn last_request(&self) -> Option<Request> {
        lock(&self.requests).last().cloned()
    }
}

impl Transport for MockTransport {
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
        let scripted = lock(&self.script).pop_front();
        let answer = match scripted {
            Some(answer) => answer,
            None => match &self.handler {
                Some(handler) => handler(&request),
                None => Err(TransportError::Other("no scripted answer".into())),
            },
        };
        lock(&self.requests).push(request);
        Box::pin(async move { answer })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(path: &str) -> Request {
        Request {
            method: "GET".into(),
            origin: "https://switch.example".into(),
            path_and_query: path.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    #[tokio::test]
    async fn test_mock_transport_answers_in_script_order() {
        let mock = MockTransport::new();
        mock.push_response(Response {
            status: 200,
            headers: Vec::new(),
            body: b"1".to_vec(),
        });
        mock.push_error(TransportError::Timeout);
        assert_eq!(mock.send(request("/a")).await.unwrap().body, b"1");
        assert_eq!(
            mock.send(request("/b")).await.unwrap_err(),
            TransportError::Timeout
        );
        // An empty script without a handler fails.
        assert!(mock.send(request("/c")).await.is_err());
        let paths: Vec<String> = mock
            .requests()
            .into_iter()
            .map(|r| r.path_and_query)
            .collect();
        assert_eq!(paths, ["/a", "/b", "/c"]);
    }

    #[tokio::test]
    async fn test_mock_transport_falls_back_to_its_handler() {
        let mock = MockTransport::with_handler(|request| {
            Ok(Response {
                status: 200,
                headers: Vec::new(),
                body: request.path_and_query.clone().into_bytes(),
            })
        });
        assert_eq!(mock.send(request("/x")).await.unwrap().body, b"/x");
        assert_eq!(mock.last_request().unwrap().path_and_query, "/x");
    }
}
