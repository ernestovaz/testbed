use log::{info, warn};
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::Deserialize;
use serde_json::{json, Value};

const MAX_BODY_BYTES: usize = 64 * 1024;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(FilterRoot::default())
    });
}}

#[derive(Default)]
struct FilterRoot {
    config: FilterConfig,
}

#[derive(Clone, Default)]
struct FilterConfig {
    rules: Vec<Rule>,
    log_only: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    #[serde(rename = "match")]
    matcher: RuleMatch,
    action: RuleAction,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleMatch {
    operation: Option<String>,
    namespace: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum RuleAction {
    Allow,
    Block,
}

#[derive(Debug, Deserialize, PartialEq)]
struct JsonRpcRequest {
    jsonrpc: String,
    #[serde(default)]
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, PartialEq)]
struct OperationContext {
    operation: String,
    namespace: Option<String>,
    params: Value,
    id: Value,
}

#[derive(Debug, PartialEq)]
struct RuleVerdict {
    action: RuleAction,
    reason: String,
}

impl Context for FilterRoot {}

impl RootContext for FilterRoot {
    fn on_configure(&mut self, _config_size: usize) -> bool {
        let Some(config_bytes) = self.get_plugin_configuration() else {
            warn!("missing filter configuration");
            return false;
        };
        let Ok(raw) = std::str::from_utf8(&config_bytes) else {
            warn!("filter configuration is not UTF-8");
            return false;
        };

        match parse_config(raw) {
            Ok(config) => {
                info!(
                    "filter configured: rules={}, log_only={}",
                    config.rules.len(),
                    config.log_only
                );
                self.config = config;
                true
            }
            Err(error) => {
                warn!("invalid filter configuration: {error}");
                false
            }
        }
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(FilterStream {
            config: self.config.clone(),
            operation: None,
        }))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

struct FilterStream {
    config: FilterConfig,
    operation: Option<String>,
}

impl Context for FilterStream {}

impl HttpContext for FilterStream {
    fn on_http_request_headers(&mut self, _num_headers: usize, end_of_stream: bool) -> Action {
        if end_of_stream {
            return self.reject(400, -32600, "request body unavailable", Value::Null);
        }
        Action::Continue
    }

    fn on_http_request_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        if body_size > MAX_BODY_BYTES {
            return self.reject(
                413,
                -32600,
                "request body exceeds inspection limit",
                Value::Null,
            );
        }
        if !end_of_stream {
            return Action::Pause;
        }

        let Some(body) = self.get_http_request_body(0, body_size) else {
            return self.reject(400, -32600, "request body unavailable", Value::Null);
        };
        let context = match parse_json_rpc(&body) {
            Ok(context) => context,
            Err(reason) => return self.reject(400, -32600, reason, Value::Null),
        };

        self.operation = Some(context.operation.clone());
        let verdict = evaluate_rules(&context, &self.config.rules);
        if verdict.action == RuleAction::Allow {
            return Action::Continue;
        }
        if self.config.log_only {
            warn!(
                "WOULD BLOCK operation={} reason={}",
                context.operation, verdict.reason
            );
            return Action::Continue;
        }

        warn!(
            "BLOCKED operation={} reason={}",
            context.operation, verdict.reason
        );
        self.reject(403, -32601, &verdict.reason, context.id)
    }

    fn on_log(&mut self) {
        if let Some(operation) = &self.operation {
            info!("request: operation={operation}");
        }
    }
}

impl FilterStream {
    fn reject(&self, status: u32, code: i64, message: &str, id: Value) -> Action {
        let body = format_json_rpc_error(code, message, id);
        self.send_http_response(
            status,
            vec![("content-type", "application/json")],
            Some(&body),
        );
        Action::Pause
    }
}

fn parse_json_rpc(body: &[u8]) -> Result<OperationContext, &'static str> {
    let request: JsonRpcRequest =
        serde_json::from_slice(body).map_err(|_| "invalid JSON-RPC request")?;
    if request.jsonrpc != "2.0"
        || request.method.is_empty()
        || !matches!(
            &request.params,
            Value::Null | Value::Array(_) | Value::Object(_)
        )
        || !matches!(
            &request.id,
            Value::Null | Value::String(_) | Value::Number(_)
        )
    {
        return Err("invalid JSON-RPC request");
    }

    Ok(OperationContext {
        namespace: request
            .method
            .split_once('_')
            .map(|(namespace, _)| namespace.to_owned()),
        operation: request.method,
        params: request.params,
        id: request.id,
    })
}

fn evaluate_rules(context: &OperationContext, rules: &[Rule]) -> RuleVerdict {
    for rule in rules {
        let operation_matches = rule
            .matcher
            .operation
            .as_deref()
            .is_none_or(|operation| operation == "*" || operation == context.operation);
        let namespace_matches = rule
            .matcher
            .namespace
            .as_deref()
            .is_none_or(|namespace| context.namespace.as_deref() == Some(namespace));

        if operation_matches && namespace_matches {
            return RuleVerdict {
                action: rule.action,
                reason: format!("matched policy rule for {}", context.operation),
            };
        }
    }

    RuleVerdict {
        action: RuleAction::Block,
        reason: "no policy rule matched".to_owned(),
    }
}

fn format_json_rpc_error(code: i64, message: &str, id: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        }
    }))
    .expect("JSON-RPC error serialization cannot fail")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    rules: Vec<Rule>,
    #[serde(default)]
    log_only: bool,
}

fn parse_config(raw: &str) -> Result<FilterConfig, String> {
    let config: RawConfig = serde_json::from_str(raw).map_err(|error| error.to_string())?;
    if config.rules.is_empty() {
        return Err("at least one rule is required".to_owned());
    }
    if config
        .rules
        .iter()
        .any(|rule| rule.matcher.operation.is_none() && rule.matcher.namespace.is_none())
    {
        return Err("each rule must match an operation or namespace".to_owned());
    }

    Ok(FilterConfig {
        rules: config.rules,
        log_only: config.log_only,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(operation: &str) -> OperationContext {
        OperationContext {
            operation: operation.to_owned(),
            namespace: operation
                .split_once('_')
                .map(|(namespace, _)| namespace.to_owned()),
            params: Value::Array(vec![]),
            id: json!(1),
        }
    }

    fn rules() -> Vec<Rule> {
        vec![
            Rule {
                matcher: RuleMatch {
                    operation: None,
                    namespace: Some("debug".to_owned()),
                },
                action: RuleAction::Block,
            },
            Rule {
                matcher: RuleMatch {
                    operation: Some("*".to_owned()),
                    namespace: None,
                },
                action: RuleAction::Allow,
            },
        ]
    }

    #[test]
    fn parses_operation_context() {
        let parsed = parse_json_rpc(
            br#"{"jsonrpc":"2.0","id":7,"method":"eth_getBalance","params":["0x0"]}"#,
        )
        .unwrap();

        assert_eq!(parsed.operation, "eth_getBalance");
        assert_eq!(parsed.namespace.as_deref(), Some("eth"));
        assert_eq!(parsed.params, json!(["0x0"]));
        assert_eq!(parsed.id, json!(7));
    }

    #[test]
    fn rejects_malformed_and_batch_requests() {
        assert_eq!(parse_json_rpc(b"not json"), Err("invalid JSON-RPC request"));
        assert_eq!(
            parse_json_rpc(br#"[{"jsonrpc":"2.0","method":"eth_chainId"}]"#),
            Err("invalid JSON-RPC request")
        );
        assert_eq!(
            parse_json_rpc(br#"{"jsonrpc":"2.0","id":true,"method":"eth_chainId","params":[]}"#),
            Err("invalid JSON-RPC request")
        );
        assert_eq!(
            parse_json_rpc(br#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":"bad"}"#),
            Err("invalid JSON-RPC request")
        );
    }

    #[test]
    fn applies_first_matching_rule() {
        assert_eq!(
            evaluate_rules(&context("debug_traceTransaction"), &rules()).action,
            RuleAction::Block
        );
        assert_eq!(
            evaluate_rules(&context("eth_chainId"), &rules()).action,
            RuleAction::Allow
        );
    }

    #[test]
    fn blocks_when_no_rule_matches() {
        assert_eq!(
            evaluate_rules(&context("eth_chainId"), &[]).action,
            RuleAction::Block
        );
    }

    #[test]
    fn rejects_invalid_configuration() {
        assert!(parse_config(r#"{"rules":[]}"#).is_err());
        assert!(parse_config(r#"{"rules":[{"match":{},"action":"allow"}]}"#).is_err());
        assert!(
            parse_config(r#"{"rules":[{"match":{"operaton":"*"},"action":"allow"}]}"#).is_err()
        );
        assert!(parse_config(
            r#"{"rules":[{"match":{"operation":"*"},"action":"allow"}],"log_ony":true}"#
        )
        .is_err());
    }

    #[test]
    fn formats_json_rpc_error_with_request_id() {
        let error = format_json_rpc_error(-32601, "blocked", json!(7));
        let value: Value = serde_json::from_slice(&error).unwrap();

        assert_eq!(value["id"], json!(7));
        assert_eq!(value["error"]["code"], json!(-32601));
        assert_eq!(value["error"]["message"], json!("blocked"));
    }
}
