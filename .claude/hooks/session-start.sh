#!/bin/bash
# SessionStart hook for Claude Code cloud sessions: installs Go module
# dependencies and lint tooling so `go test` and golangci-lint work.
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel)}"

GOLANGCI_LINT_VERSION="v2.5.0"
GOBIN_DIR="$(go env GOPATH)/bin"

# Download module dependencies (uses the go.mod toolchain).
go mod download

# Install golangci-lint v2 if it is not already available.
if ! command -v golangci-lint >/dev/null 2>&1; then
  echo "Installing golangci-lint ${GOLANGCI_LINT_VERSION}"
  go install "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_LINT_VERSION}"
fi

# Make GOPATH/bin available for the rest of the session.
if [ -n "${CLAUDE_ENV_FILE:-}" ] && ! grep -qs "$GOBIN_DIR" "$CLAUDE_ENV_FILE"; then
  echo "export PATH=\"\$PATH:${GOBIN_DIR}\"" >> "$CLAUDE_ENV_FILE"
fi

# Warm the build cache so the first test or lint run is fast.
go build ./...
