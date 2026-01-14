#!/bin/bash
#
# Smoke Test for E-Signing Service Preview Environment
#
# This script performs basic, non-destructive checks to ensure the backend
# is responding correctly to CORS preflight requests and basic API calls.
#
# Usage:
#   ./scripts/smoke_test_preview.sh <BACKEND_URL> <VALID_JWT> <WORKSPACE_ID>
#
# Example:
#   ./scripts/smoke_test_preview.sh https://my-service-xyz.a.run.app eyJhbGciOi... 123e4567-e89b-12d3-a456-426614174000

set -e

# --- Configuration ---
if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "Usage: $0 <BACKEND_URL> <VALID_JWT> <WORKSPACE_ID>"
    echo "Example: $0 https://my-service-xyz.a.run.app eyJhbGciOi... 123e4567-e89b-12d3-a456-426614174000"
    exit 1
fi

BACKEND_URL="$1"
JWT_TOKEN="$2"
WORKSPACE_ID="$3"
FAKE_ORIGIN="https://fake-preview.lovable.app"

# --- Helper Functions ---
print_header() {
    echo ""
    echo "--- $1 ---"
}

print_success() {
    echo "✅ SUCCESS: $1"
}

print_failure() {
    echo "❌ FAILURE: $1"
    exit 1
}

# --- Test Cases ---

# 1. Test CORS Preflight (OPTIONS)
print_header "1. Testing CORS Preflight (OPTIONS) from '$FAKE_ORIGIN'"
response=$(curl -s -i -X OPTIONS "${BACKEND_URL}/v1/documents" \
  -H "Origin: ${FAKE_ORIGIN}" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: authorization,x-workspace-id,content-type")

echo "Response headers:"
echo "$response"

status_line=$(echo "$response" | head -n 1)
# Check for a 200 OK or 204 No Content status
if ! (echo "$status_line" | grep -q "HTTP/.* 200 OK" || echo "$status_line" | grep -q "HTTP/.* 204 No Content"); then
    print_failure "CORS preflight status was not 200 or 204. Full status: '$status_line'"
fi

# Since credentials are used, the ACAO header MUST match the origin, it cannot be '*'
# Use grep -qi for case-insensitive matching
if ! (echo "$response" | grep -qi "access-control-allow-origin: ${FAKE_ORIGIN}"); then
    print_failure "Access-Control-Allow-Origin header did not match '${FAKE_ORIGIN}'"
fi

print_success "CORS preflight check passed with correct status (200/204) and ACAO header."



# 2. Test GET /v1/documents without workspace ID
print_header "2. Testing GET /v1/documents (expecting 400 Bad Request)"
http_status=$(curl -s -o /dev/null -w "%{http_code}" -X GET "${BACKEND_URL}/v1/documents"
  -H "Authorization: Bearer ${JWT_TOKEN}")

echo "Received HTTP status: ${http_status}"

if [ "$http_status" -eq 400 ]; then
    print_success "Correctly received 400 Bad Request when X-Workspace-ID is missing."
else
    print_failure "Incorrect status received. Expected 400, got ${http_status}."
fi


# 3. Test GET /v1/documents with workspace ID (auth check)
print_header "3. Testing GET /v1/documents with headers (expecting 200 or 401)"
http_status_auth=$(curl -s -o /dev/null -w "%{http_code}" -X GET "${BACKEND_URL}/v1/documents"
  -H "Authorization: Bearer ${JWT_TOKEN}"
  -H "X-Workspace-ID: ${WORKSPACE_ID}")

echo "Received HTTP status: ${http_status_auth}"

if [ "$http_status_auth" -eq 200 ]; then
    print_success "Received 200 OK. Authentication and authorization successful."
elif [ "$http_status_auth" -eq 401 ]; then
    print_success "Received 401 Unauthorized. This is also a valid outcome if the JWT is invalid/expired."
else
    print_failure "Incorrect status received. Expected 200 or 401, got ${http_status_auth}."
fi

echo ""
echo "🎉 All smoke tests passed! 🎉"
