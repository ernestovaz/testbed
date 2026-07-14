use log::{info, warn};
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(FilterRoot::default())
    });
}}

// ---------------------------------------------------------------------------
// Root Context (shared across requests within a worker)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FilterRoot {
    config: FilterConfig,
}

#[derive(Default, Clone)]
struct FilterConfig {
    /// Methods that are always blocked (deny list).
    blocked_methods: Vec<String>,
    /// If non-empty, only these methods are allowed (allow list takes priority).
    allowed_methods: Vec<String>,
    /// Log-only mode: observe but don't enforce.
    log_only: bool,
}

impl Context for FilterRoot {}

impl RootContext for FilterRoot {
    fn on_configure(&mut self, _config_size: usize) -> bool {
        if let Some(config_bytes) = self.get_plugin_configuration() {
            if let Ok(raw) = std::str::from_utf8(&config_bytes) {
                self.config = parse_config(raw);
                info!("filter configured: blocked={:?}, allowed={:?}, log_only={}",
                    self.config.blocked_methods,
                    self.config.allowed_methods,
                    self.config.log_only,
                );
            }
        }
        true
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(FilterStream {
            config: self.config.clone(),
            method: None,
        }))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

// ---------------------------------------------------------------------------
// Stream Context (per-request)
// ---------------------------------------------------------------------------

struct FilterStream {
    config: FilterConfig,
    method: Option<String>,
}

/// Minimal JSON-RPC request structure (only what we need to extract).
#[derive(Deserialize)]
struct JsonRpcRequest {
    method: String,
    #[allow(dead_code)]
    id: Option<serde_json::Value>,
}

impl Context for FilterStream {}

impl HttpContext for FilterStream {
    fn on_http_request_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        // Wait until we have the full body.
        if !end_of_stream {
            return Action::Pause;
        }

        // Read body bytes.
        let body = match self.get_http_request_body(0, body_size) {
            Some(b) => b,
            None => return Action::Continue,
        };

        // Parse just enough to extract the method name.
        let rpc_method = match serde_json::from_slice::<JsonRpcRequest>(&body) {
            Ok(req) => req.method,
            Err(_) => {
                // Not valid JSON-RPC -- let it pass (or block, depending on policy).
                warn!("failed to parse JSON-RPC request body");
                return Action::Continue;
            }
        };

        self.method = Some(rpc_method.clone());

        // --- Policy evaluation ---

        // 1. Allow list (if configured, only these methods pass)
        if !self.config.allowed_methods.is_empty()
            && !self.config.allowed_methods.contains(&rpc_method)
        {
            return self.deny(&rpc_method, "method not in allowlist");
        }

        // 2. Block list
        if self.config.blocked_methods.contains(&rpc_method) {
            return self.deny(&rpc_method, "method is blocked");
        }

        Action::Continue
    }

    fn on_log(&mut self) {
        if let Some(method) = &self.method {
            info!("request: method={}", method);
        }
    }
}

impl FilterStream {
    fn deny(&self, method: &str, reason: &str) -> Action {
        if self.config.log_only {
            warn!("WOULD DENY method={} reason={}", method, reason);
            return Action::Continue;
        }

        warn!("DENIED method={} reason={}", method, reason);

        // Respond with a JSON-RPC error directly from the filter.
        let error_body = format!(
            r#"{{"jsonrpc":"2.0","id":null,"error":{{"code":-32601,"message":"{}"}}}}"#,
            reason
        );

        self.send_http_response(
            403,
            vec![("content-type", "application/json")],
            Some(error_body.as_bytes()),
        );

        Action::Pause
    }
}

// ---------------------------------------------------------------------------
// Configuration parsing
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
struct RawConfig {
    #[serde(default)]
    blocked_methods: Vec<String>,
    #[serde(default)]
    allowed_methods: Vec<String>,
    #[serde(default)]
    log_only: bool,
}

fn parse_config(raw: &str) -> FilterConfig {
    match serde_json::from_str::<RawConfig>(raw) {
        Ok(c) => FilterConfig {
            blocked_methods: c.blocked_methods,
            allowed_methods: c.allowed_methods,
            log_only: c.log_only,
        },
        Err(e) => {
            warn!("failed to parse filter config: {}, using defaults", e);
            FilterConfig::default()
        }
    }
}
