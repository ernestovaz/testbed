# eth-rpc-filter testbed

## Architecture
- **Envoy** terminates HTTP, loads the WASM filter, proxies allowed requests to Anvil.
- **Filter** parses JSON-RPC body, extracts method name, evaluates policy (allow/block), returns 403 with JSON-RPC error for denied requests.
- **Anvil** provides a realistic JSON-RPC simulation
