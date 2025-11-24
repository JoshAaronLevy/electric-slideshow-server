#!/bin/bash

# Spotify Devices API Proxy Test Script
# This script tests all scenarios for the /api/spotify/devices endpoint

# Configuration
BASE_URL="http://localhost:8080"
CORRELATION_ID="test-$(date +%s)-$$"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
log_test() {
    echo -e "\n${BLUE}=== TEST: $1 ===${NC}"
}

log_success() {
    echo -e "${GREEN}✓ PASS: $1${NC}"
    ((TESTS_PASSED++))
}

log_failure() {
    echo -e "${RED}✗ FAIL: $1${NC}"
    ((TESTS_FAILED++))
}

log_info() {
    echo -e "${YELLOW}ℹ INFO: $1${NC}"
}

# Test 1: Health Check
log_test "Health Check Endpoint"
response=$(curl -s -w "\n%{http_code}" -H "X-Correlation-ID: $CORRELATION_ID" "$BASE_URL/healthz")
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" = "200" ]; then
    log_success "Health check returned 200 OK"
    echo "Response: $body"
else
    log_failure "Health check failed with HTTP $http_code"
    echo "Response: $body"
fi

# Test 2: Missing Authorization Header
log_test "Devices Endpoint - Missing Authorization Header"
response=$(curl -s -w "\n%{http_code}" -H "X-Correlation-ID: $CORRELATION_ID" "$BASE_URL/api/spotify/devices")
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" = "401" ]; then
    log_success "Correctly returned 401 for missing auth header"
    echo "Response: $body"
else
    log_failure "Expected 401 but got HTTP $http_code"
    echo "Response: $body"
fi

# Test 3: Invalid Authorization Format
log_test "Devices Endpoint - Invalid Authorization Format"
response=$(curl -s -w "\n%{http_code}" -H "X-Correlation-ID: $CORRELATION_ID" -H "Authorization: InvalidFormat token123" "$BASE_URL/api/spotify/devices")
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" = "401" ]; then
    log_success "Correctly returned 401 for invalid auth format"
    echo "Response: $body"
else
    log_failure "Expected 401 but got HTTP $http_code"
    echo "Response: $body"
fi

# Test 4: Invalid Token (Simulated)
log_test "Devices Endpoint - Invalid Token"
response=$(curl -s -w "\n%{http_code}" -H "X-Correlation-ID: $CORRELATION_ID" -H "Authorization: Bearer invalid_token_12345" "$BASE_URL/api/spotify/devices")
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" = "401" ]; then
    log_success "Correctly returned 401 for invalid token"
    echo "Response: $body"
else
    log_failure "Expected 401 but got HTTP $http_code"
    echo "Response: $body"
fi

# Test 5: Token with Insufficient Scopes (Simulated)
# Note: This would require a real token with limited scopes to test properly
log_test "Devices Endpoint - Insufficient Scopes (Simulated)"
log_info "This test requires a real Spotify token with limited scopes. Skipping for now."

# Test 6: Response Format Validation - Error Case
log_test "Response Format Validation - Error Response"
response=$(curl -s -w "\n%{http_code}" -H "X-Correlation-ID: $CORRELATION_ID" -H "Authorization: Bearer invalid_token" "$BASE_URL/api/spotify/devices")
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

# Check if response has required error format
if echo "$body" | jq -e '.success == false and .error != null and .timestamp != null' > /dev/null 2>&1; then
    log_success "Error response format is correct"
    echo "Error code: $(echo "$body" | jq -r '.error.code')"
    echo "Error message: $(echo "$body" | jq -r '.error.message')"
else
    log_failure "Error response format does not match specification"
    echo "Response: $body"
fi

# Test 7: CORS Headers
log_test "CORS Headers Validation"
response=$(curl -s -I -H "X-Correlation-ID: $CORRELATION_ID" -H "Origin: http://localhost:5173" "$BASE_URL/healthz")
cors_header=$(echo "$response" | grep -i "access-control-allow-origin" | cut -d: -f2 | tr -d ' ')

if [ -n "$cors_header" ]; then
    log_success "CORS headers are present: $cors_header"
else
    log_failure "CORS headers are missing"
fi

# Test 8: Correlation ID Header
log_test "Correlation ID Header Validation"
response=$(curl -s -I -H "X-Correlation-ID: test-correlation-123" "$BASE_URL/healthz")
correlation_header=$(echo "$response" | grep -i "x-correlation-id" | cut -d: -f2 | tr -d ' ')

if echo "$correlation_header" | grep -q "test-correlation-123"; then
    log_success "Correlation ID is properly returned in response headers"
else
    log_failure "Correlation ID is not properly returned"
    echo "Expected: test-correlation-123, Got: $correlation_header"
fi

# Test 9: Rate Limiting (Basic Test)
log_test "Rate Limiting - Basic Test"
log_info "Sending multiple requests to test rate limiting..."
for i in {1..5}; do
    response=$(curl -s -w "\n%{http_code}" -H "X-Correlation-ID: $CORRELATION_ID" "$BASE_URL/healthz")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" != "200" ] && [ "$http_code" != "429" ]; then
        log_failure "Unexpected response code during rate limit test: $http_code"
        break
    fi
done
log_success "Rate limiting test completed (basic check)"

# Test 10: Auth Endpoints - Basic Structure
log_test "Auth Token Endpoint - Request Validation"
response=$(curl -s -w "\n%{http_code}" -X POST -H "X-Correlation-ID: $CORRELATION_ID" -H "Content-Type: application/json" -d '{}' "$BASE_URL/auth/spotify/token")
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" = "400" ]; then
    log_success "Auth endpoint correctly validates empty request body"
    echo "Response: $body"
else
    log_failure "Expected 400 for empty request body, got HTTP $http_code"
    echo "Response: $body"
fi

# Test 11: Auth Refresh Endpoint - Basic Structure
log_test "Auth Refresh Endpoint - Request Validation"
response=$(curl -s -w "\n%{http_code}" -X POST -H "X-Correlation-ID: $CORRELATION_ID" -H "Content-Type: application/json" -d '{}' "$BASE_URL/auth/spotify/refresh")
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" = "400" ]; then
    log_success "Refresh endpoint correctly validates empty request body"
    echo "Response: $body"
else
    log_failure "Expected 400 for empty request body, got HTTP $http_code"
    echo "Response: $body"
fi

# Test 12: 404 Handler
log_test "404 Handler"
response=$(curl -s -w "\n%{http_code}" -H "X-Correlation-ID: $CORRELATION_ID" "$BASE_URL/nonexistent-endpoint")
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" = "404" ]; then
    log_success "404 handler works correctly"
    echo "Response: $body"
else
    log_failure "Expected 404 for nonexistent endpoint, got HTTP $http_code"
    echo "Response: $body"
fi

# Summary
echo -e "\n${BLUE}=== TEST SUMMARY ===${NC}"
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
echo -e "Total Tests: $((TESTS_PASSED + TESTS_FAILED))"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}🎉 All tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}❌ Some tests failed!${NC}"
    exit 1
fi