//! Model Context Protocol (MCP) JSON-RPC 2.0 protocol specifications and parsing.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{McpError, McpResult};

/// JSON-RPC 2.0 Request representation for Model Context Protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// JSON-RPC protocol version (must be "2.0").
    pub jsonrpc: String,
    /// Unique request ID (string, integer, or null).
    pub id: Value,
    /// Target RPC method name (e.g. "tools/call", "tools/list", "initialize").
    pub method: String,
    /// Optional RPC parameters payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// JSON-RPC 2.0 Response representation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// JSON-RPC protocol version ("2.0").
    pub jsonrpc: String,
    /// Matching request ID.
    pub id: Value,
    /// Successful result payload if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error object if invocation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 Error object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Standard or application-defined error code.
    pub code: i64,
    /// Human-readable error message.
    pub message: String,
    /// Optional supplementary error data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Typed parameters for an MCP `tools/call` invocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpToolCallParams {
    /// Tool name being invoked (e.g. "postgres_query", "stripe_payment").
    pub name: String,
    /// Tool arguments map.
    #[serde(default)]
    pub arguments: Value,
}

impl JsonRpcRequest {
    /// Parses a JSON-RPC request from a single-line JSON string.
    pub fn from_line(line: &str) -> McpResult<Self> {
        serde_json::from_str(line.trim())
            .map_err(|e| McpError::JsonRpcError(format!("Failed to parse JSON-RPC request: {}", e)))
    }

    /// Extracts typed `McpToolCallParams` if this request is a `tools/call`.
    pub fn extract_tool_call(&self) -> Option<McpToolCallParams> {
        if self.method != "tools/call" {
            return None;
        }
        let params = self.params.as_ref()?;
        serde_json::from_value(params.clone()).ok()
    }
}

impl JsonRpcResponse {
    /// Creates a successful response for a request ID.
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Creates an error response for a request ID.
    pub fn error(id: Value, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }

    /// Serializes the response to a single-line JSON string with newline.
    pub fn to_line(&self) -> McpResult<String> {
        let json = serde_json::to_string(self).map_err(|e| {
            McpError::JsonRpcError(format!("Failed to serialize JSON-RPC response: {}", e))
        })?;
        Ok(format!("{}\n", json))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_request_tool_call_extraction() {
        let raw = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"stripe_payment","arguments":{"amount":2500}}}"#;
        let req = JsonRpcRequest::from_line(raw).expect("Parsing failed");
        assert_eq!(req.method, "tools/call");

        let tool_call = req
            .extract_tool_call()
            .expect("Tool call extraction failed");
        assert_eq!(tool_call.name, "stripe_payment");
        assert_eq!(tool_call.arguments["amount"], 2500);
    }
}
