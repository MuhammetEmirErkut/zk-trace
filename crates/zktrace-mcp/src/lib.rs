//! # ZKTrace MCP (`zktrace-mcp`)
//!
//! Model Context Protocol (MCP) JSON-RPC 2.0 proxy and real-time Zero-Knowledge audit
//! interceptor for AI Agents and tool servers in the ZKTrace ecosystem.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(rust_2018_idioms)]

pub mod error;
pub mod interceptor;
pub mod protocol;
pub mod proxy;

/// Common imports for MCP interception and proxying.
pub mod prelude {
    pub use crate::error::{McpError, McpResult};
    pub use crate::interceptor::McpInterceptor;
    pub use crate::protocol::{
        JsonRpcError, JsonRpcRequest, JsonRpcResponse, McpToolCallParams,
    };
    pub use crate::proxy::{McpProxy, ProxyAction};
}

pub use prelude::*;
