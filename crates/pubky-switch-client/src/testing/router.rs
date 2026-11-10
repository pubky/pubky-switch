//! A transport that sends each request to the switch of its origin.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use super::ScriptedSwitch;
use crate::error::TransportError;
use crate::transport::{BoxFuture, Request, Response, Transport};

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A [`Transport`] that sends each request to the transport routed at its origin, and logs
/// every request. A request to an origin with no route fails to connect, as a service that
/// is unreachable.
#[derive(Default)]
pub struct Router {
    routes: Mutex<Vec<(String, Arc<dyn Transport>)>>,
    log: Mutex<Vec<String>>,
    /// Feed reads left before every further one fails to connect, when set.
    feeds_left: Mutex<Option<u64>>,
}

impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let origins: Vec<String> = lock(&self.routes).iter().map(|(o, _)| o.clone()).collect();
        write!(f, "Router({origins:?})")
    }
}

impl Router {
    /// A router with no routes.
    pub fn new() -> Self {
        Self::default()
    }

    /// Route `origin` to `transport`, in place of any route there.
    pub fn add(&self, origin: &str, transport: Arc<dyn Transport>) {
        let mut routes = lock(&self.routes);
        routes.retain(|(o, _)| o != origin);
        routes.push((origin.to_owned(), transport));
    }

    /// Route `origin` to `switch`, in place of any route there.
    pub fn add_switch(&self, origin: &str, switch: &Arc<ScriptedSwitch>) {
        self.add(origin, switch.transport());
    }

    /// Route nothing to `origin` any more: its service is unreachable.
    pub fn remove(&self, origin: &str) {
        lock(&self.routes).retain(|(o, _)| o != origin);
    }

    /// Fail every feed read after the next `reads` to connect, so a read that never ends
    /// fails.
    pub fn limit_feeds(&self, reads: u64) {
        *lock(&self.feeds_left) = Some(reads);
    }

    /// Every request sent, as `"METHOD origin path"`, in order.
    pub fn log(&self) -> Vec<String> {
        lock(&self.log).clone()
    }

    fn route(&self, request: &Request) -> Result<Arc<dyn Transport>, TransportError> {
        lock(&self.log).push(format!(
            "{} {} {}",
            request.method, request.origin, request.path_and_query
        ));
        if request.path_and_query.contains("/feed")
            && let Some(left) = lock(&self.feeds_left).as_mut()
        {
            if *left == 0 {
                return Err(TransportError::Connect("too many feed reads".into()));
            }
            *left -= 1;
        }
        lock(&self.routes)
            .iter()
            .find(|(origin, _)| *origin == request.origin)
            .map(|(_, transport)| Arc::clone(transport))
            .ok_or_else(|| TransportError::Connect("no such origin".into()))
    }
}

impl Transport for Router {
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, TransportError>> {
        let routed = self.route(&request);
        Box::pin(async move { routed?.send(request).await })
    }
}
