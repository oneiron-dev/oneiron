//! Router-owned admission for public, capability-free editor computation.
use super::*;
use axum::extract::Request;
use axum::middleware::Next;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub(super) struct EditorBudget {
    window: Mutex<(Instant, u32)>,
    slots: Arc<Semaphore>,
}
impl EditorBudget {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            window: Mutex::new((Instant::now(), 0)),
            slots: Arc::new(Semaphore::new(2)),
        })
    }
    fn admit(&self) -> Option<Arc<OwnedSemaphorePermit>> {
        let permit = self.slots.clone().try_acquire_owned().ok()?;
        let mut window = self.window.lock().ok()?;
        if window.0.elapsed() >= Duration::from_secs(60) {
            *window = (Instant::now(), 0);
        }
        if window.1 >= 60 {
            return None;
        }
        window.1 += 1;
        Some(Arc::new(permit))
    }
}

pub(super) async fn admit(
    State(budget): State<Arc<EditorBudget>>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(permit) = budget.admit() else {
        return (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, "60")]).into_response();
    };
    // Admit before body extraction. The geometry worker retains its own clone
    // even if the HTTP future is cancelled while parsing is still in progress.
    request.extensions_mut().insert(permit.clone());
    let response = next.run(request).await;
    drop(permit);
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use tower::ServiceExt;

    #[tokio::test]
    async fn public_editor_budget_refuses_before_body_parsing_and_is_router_local() {
        fn router() -> Router {
            Router::new()
                .route("/layout", post(|| async { StatusCode::OK }))
                .route_layer(axum::middleware::from_fn_with_state(
                    EditorBudget::new(),
                    admit,
                ))
        }
        let app = router();
        for _ in 0..60 {
            assert_eq!(
                app.clone()
                    .oneshot(Request::post("/layout").body(Body::empty()).unwrap())
                    .await
                    .unwrap()
                    .status(),
                StatusCode::OK
            );
        }
        let refused = app
            .oneshot(Request::post("/layout").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(refused.headers()[header::RETRY_AFTER], "60");
        assert_eq!(
            router()
                .oneshot(Request::post("/layout").body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
}
