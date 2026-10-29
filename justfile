# Testbed commands
# Usage: just <recipe>

# Default recipe: build the filter
default: build

# Build the WASM filter (release)
build:
    cd filter && cargo build --target wasm32-wasip1 --release

# Build the WASM filter (debug, faster compilation)
build-dev:
    cd filter && cargo build --target wasm32-wasip1

# Run host-side parser and policy tests
unit:
    cd filter && cargo test

# Validate the filter and Compose configuration without starting services
check: unit build
    docker compose config --quiet

# Start the testbed (Anvil + Envoy with filter)
up: build
    docker compose up -d

# Stop the testbed
down:
    docker compose down

# Restart Envoy only (after rebuilding the filter)
reload: build
    docker compose restart envoy

# View Envoy logs (follow)
logs:
    docker compose logs -f envoy

# View Anvil logs
logs-anvil:
    docker compose logs -f anvil

# Run smoke tests against the running proxy
test:
    ./scripts/smoke-test.sh

# Send a single JSON-RPC request through the proxy
rpc method params="[]":
    @curl -s http://localhost:10000 \
        -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"{{method}}","params":{{params}}}' | jq

# Send a request directly to Anvil (bypass filter)
rpc-direct method params="[]":
    @curl -s http://localhost:8545 \
        -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"{{method}}","params":{{params}}}' | jq

# Check Envoy stats
stats:
    @curl -s http://localhost:9901/stats | grep -E "wasm|json_rpc"

# Check filter .wasm binary size
size: build
    @ls -lh filter/target/wasm32-wasip1/release/eth_rpc_filter.wasm | awk '{print $$5, $$9}'

# Clean build artifacts
clean:
    cd filter && cargo clean
