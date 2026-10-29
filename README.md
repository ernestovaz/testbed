# Protocol-aware WASM filter testbed

Tier 1 development environment for the protocol-aware security filter described in the paper and thesis.
Ethereum JSON-RPC is the first protocol implementation and Anvil is the development backend.

## Architecture

```text
client → Envoy → JSON-RPC parser → operation rules → Anvil
```

The filter separates three responsibilities:

- parse a JSON-RPC request into an operation context;
- evaluate ordered operation or namespace rules;
- return a JSON-RPC error when a rule blocks the operation.

Rules are evaluated from top to bottom. Requests are blocked when no rule matches.
Malformed JSON-RPC, batch requests, and bodies larger than 64 KiB are rejected rather than bypassing inspection.

## Requirements

- Rust with the `wasm32-wasip1` target
- Docker with Compose
- `just`
- `curl`

## Development

```sh
just unit     # parser and policy tests
just build    # release WASM artifact
just check    # tests, WASM build, and Compose validation
just up       # build and start Envoy + Anvil
just test     # end-to-end policy assertions
just logs     # follow Envoy logs
just down
```

Send an individual request through the filter with `just rpc eth_chainId` or directly to Anvil with `just rpc-direct eth_chainId`.

## Current scope

This slice implements deterministic allow/block rules for JSON-RPC operations and namespaces.
Stateful rate limiting, anomaly detection, signatures, and additional protocol parsers are intentionally deferred until this baseline is measured and validated.
