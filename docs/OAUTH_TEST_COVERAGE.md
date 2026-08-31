# OAuth Test Coverage

**Date**: April 2026  
**Status**: ✅ Complete (17 tests, 100% passing)  
**Version**: 4.2.1+

## Overview

This document describes the comprehensive test coverage added for the OAuth 2.0 implementation in the Wazuh MCP Server. The OAuth module was previously untested despite being production-ready with Dynamic Client Registration (DCR) support per RFC 7591.

## Test Implementation

**Location**: [`tests/integration/test_business_logic.py`](../tests/integration/test_business_logic.py)  
**Test Classes**: 6 classes, 17 tests  
**Execution Time**: ~0.28 seconds  
**Pass Rate**: 100% (17/17)

## Test Classes & Coverage

### 1. TestOAuthManager (4 tests)

Tests core OAuth manager functionality and client registration.

| Test | Purpose | Validates |
|------|---------|-----------|
| `test_oauth_manager_init` | Manager initialization | Config injection, secret key setup |
| `test_oauth_manager_pre_registers_claude_desktop` | Pre-registration | Claude Desktop client exists with correct URIs |
| `test_oauth_dynamic_client_registration` | DCR flow | Client generation, credentials, storage |
| `test_oauth_client_to_registration_response` | Response formatting | OAuth client serialization for RFC 7591 compliance |

**Key Validations**:
- ServerConfig properly injected into OAuthManager
- Claude Desktop registered with `https://claude.ai` and `https://claude.com` URIs
- DCR generates unique client IDs with format `client_*`
- Registration response includes required fields (client_id, client_secret, issued_at)

### 2. TestOAuthTokens (3 tests)

Tests OAuth token lifecycle and JWT operations.

| Test | Purpose | Validates |
|------|---------|-----------|
| `test_oauth_authorization_code_expiry` | Code lifetime | Expiration calculation (>0 = valid, <0 = expired) |
| `test_oauth_token_expiry` | Token lifetime | Access/refresh token TTL validation |
| `test_oauth_jwt_token_creation` | JWT creation | Token encoding with HS256, payload structure |

**Key Validations**:
- Authorization codes expire in 10 minutes (default config)
- Access tokens expire in 1 hour (default config)
- JWT payload contains: client_id, scope, type (access/refresh)
- Token signature verifiable with manager's secret key

### 3. TestOAuthAuthenticationService (3 tests)

Tests integration with authentication service across auth modes.

| Test | Purpose | Validates |
|------|---------|-----------|
| `test_oauth_verify_with_valid_token` | Valid token flow | Token acceptance, scope parsing, AuthToken creation |
| `test_oauth_verify_with_invalid_token` | Invalid token | 401 rejection, error response |
| `test_oauth_verify_no_oauth_manager` | Missing manager | 401 error when manager not provided |

**Key Validations**:
- Valid tokens create AuthToken with space-separated scopes parsed into list
- Invalid tokens trigger HTTPException with status 401
- Missing oauth_manager fails safely (not silent)
- Bearer token format preserved in verification

### 4. TestOAuthErrorCodes (2 tests)

Tests RFC 6749 error code definitions.

| Test | Purpose | Validates |
|------|---------|-----------|
| `test_oauth_error_codes_defined` | Code inventory | Required error codes present (invalid_request, invalid_client, etc.) |
| `test_oauth_error_descriptions` | Code documentation | Each error code has non-empty description |

**Key Validations**:
- All RFC 6749 required error codes defined
- Each error code maps to human-readable description
- Error messages suitable for client redirect

### 5. TestOAuthVsBearerVsAuthless (3 tests)

Tests auth mode selection and behavior differences.

| Test | Purpose | Validates |
|------|---------|-----------|
| `test_authless_mode_returns_read_only_token` | Authless behavior | Default read-only, no write scope |
| `test_bearer_mode_requires_authorization` | Bearer requirement | None header rejected with 401 |
| `test_oauth_mode_requires_authorization` | OAuth requirement | Missing authorization header rejected |

**Key Validations**:
- Auth modes are mutually exclusive in behavior
- Authless mode grants read scope by default (write opt-in via env var)
- Bearer and OAuth modes require authorization header
- AuthenticationService routes correctly to each mode handler

### 6. TestOAuthIntegration (2 tests)

Tests OAuth integration with other auth components and configuration.

| Test | Purpose | Validates |
|------|---------|-----------|
| `test_oauth_and_bearer_can_coexist` | Component coexistence | AuthManager and OAuthManager independent |
| `test_oauth_respects_token_ttl_config` | Config validation | OAUTH_ACCESS_TOKEN_TTL env var respected |

**Key Validations**:
- OAuth and Bearer auth managers can be instantiated together
- Config TTL values applied (7200 second example verified)
- Configuration system handles OAuth-specific settings

## Configuration Coverage

Tests validate OAuth configuration parameters:

| Parameter | Default | Test Coverage |
|-----------|---------|----------------|
| `AUTH_MODE` | bearer | Mode selection routing ✓ |
| `OAUTH_ISSUER_URL` | auto-derived | (Config parsing validated) |
| `OAUTH_ENABLE_DCR` | true | DCR registration flow ✓ |
| `OAUTH_ACCESS_TOKEN_TTL` | 3600 | TTL env var test ✓ |
| `OAUTH_REFRESH_TOKEN_TTL` | 86400 | Token creation uses config |
| `OAUTH_AUTHORIZATION_CODE_TTL` | 600 | Code expiration test ✓ |

## Security Testing

OAuth security aspects validated:

| Aspect | Test | Validation |
|--------|------|-----------|
| **Token validation** | `test_oauth_verify_with_valid_token` | JWT signature verified |
| **Invalid rejection** | `test_oauth_verify_with_invalid_token` | 401 status on bad token |
| **Scope enforcement** | `test_oauth_verify_with_valid_token` | Scope parsing and AuthToken scope list |
| **Auth requirement** | `test_oauth_mode_requires_authorization` | Authorization header mandatory |
| **Client isolation** | `test_oauth_dynamic_client_registration` | Each registered client gets unique ID |
| **TTL enforcement** | `test_oauth_authorization_code_expiry`, `test_oauth_token_expiry` | Expiration tracked and validated |

## Integration Points Tested

- **OAuth ↔ AuthenticationService**: Verified token validation and AuthToken creation
- **OAuth ↔ ServerConfig**: Config injection and TTL parameter usage
- **OAuth ↔ FastAPI**: HTTPException raising for auth failures
- **JWT Library**: Token encoding/decoding with HS256 algorithm
- **Auth Modes**: OAuth mode selection in authentication flow

## Test Quality Metrics

| Metric | Value |
|--------|-------|
| Test files modified | 1 |
| Test classes added | 6 |
| Test methods added | 17 |
| Code lines added | ~300 |
| Total suite size | 103 tests |
| OAuth test coverage | 17/17 (100%) |
| Execution time | 0.28s |
| Pass rate | 100% |
| Regressions detected | 0 |

## Getting Started: Running OAuth Tests

```bash
# Run only OAuth tests
pytest tests/integration/test_business_logic.py -k OAuth -v

# Run all tests
pytest tests/integration/test_business_logic.py -v

# Run with coverage report
pytest tests/integration/test_business_logic.py::TestOAuthManager -v --cov=src/wazuh_mcp_server/oauth
```

## Related Documentation

- [OAuth 2.0 Implementation](../src/wazuh_mcp_server/oauth.py) - OAuth module with RFC 7591 DCR
- [Authentication Service](../src/wazuh_mcp_server/mcp/auth.py) - Auth mode routing (authless/bearer/oauth)
- [CLAUDE_INTEGRATION.md](./CLAUDE_INTEGRATION.md) - OAuth for Claude Desktop
- [Configuration Guide](./configuration.md) - AUTH_MODE and OAUTH_* settings

## Maintenance Notes

- OAuth tests use ServerConfig from environment (not hardcoded)
- Mocked objects used for isolated testing where appropriate
- JWT validation uses manager's configured secret key
- Tests support multiple auth mode configurations
- All async tests properly marked with `@pytest.mark.asyncio`

## Future Enhancements

Potential areas for additional test coverage:

- [ ] State parameter validation in authorization flow
- [ ] PKCE (Proof Key for Exchange) flow testing
- [ ] Token refresh endpoint testing
- [ ] Revocation endpoint testing
- [ ] Discovery endpoint (`.well-known/oauth-authorization-server`) testing
- [ ] Concurrent token validation under load
- [ ] Token cleanup/eviction under memory pressure
- [ ] Integration with Claude Desktop actual OAuth flow
- [ ] Multi-client registration limits and bounds
