#!/bin/bash

set -e

TERM_PURPLE='\033[0;35m'
TERM_BOLD='\033[1m'
TERM_RESET='\033[0m'

section() {
    echo -e "${TERM_PURPLE}${TERM_BOLD}=== $1 ===${TERM_RESET}"
}

# argument: "feature1,feature2,..."
test_only_features() {
    local features="$1"
    section "no default + $features"
    cargo test --lib --bins --tests --benches --no-default-features --features "$features" > /dev/null
}

test_additional_features() {
    local features="$1"
    section "default + $features"
    cargo test --lib --bins --tests --benches --features "$features" > /dev/null
}

section "All Default Features"
cargo test --all-targets > /dev/null

section "No Default Features"
cargo test --no-default-features > /dev/null

test_only_features "secp256k1"
test_only_features "ed25519"

section "Doc Tests"
cargo test --doc > /dev/null

echo -e "${TERM_PURPLE}${TERM_BOLD}=== All tests passed ===${TERM_RESET}"
