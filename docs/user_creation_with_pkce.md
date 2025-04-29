# OpenID Connect User Creation Process with PKCE

This document outlines the step-by-step process of creating a new user through OpenID Connect with PKCE (Proof Key for Code Exchange) enabled.

## Prerequisites

1. OpenID Connect module installed and configured
2. PKCE support enabled in the OpenID Connect client configuration
3. Valid OpenID Connect provider configured with PKCE support
4. Required scopes configured (at minimum: `openid`, `email`)

## User Creation Flow

### 1. Initial Authorization Request

1. User clicks the OpenID Connect login button
2. System generates:
   - A random state token for CSRF protection
   - A code verifier (random string)
   - A code challenge (derived from code verifier)
3. User is redirected to the provider's authorization endpoint with:
   - `client_id`
   - `redirect_uri`
   - `response_type=code`
   - `scope` (configured scopes)
   - `state` (CSRF token)
   - `code_challenge` (PKCE)
   - `code_challenge_method=S256`

### 2. Token Exchange

1. Provider redirects back to our redirect endpoint with:
   - Authorization code
   - State parameter
2. System validates:
   - State token matches the one stored in session
   - State token is not expired (max 30 minutes)
3. System exchanges authorization code for tokens by sending:
   - `grant_type=authorization_code`
   - `code` (authorization code)
   - `redirect_uri`
   - `client_id`
   - `code_verifier` (original random string)

### 3. User Creation Process

1. System validates ID token and extracts claims
2. System retrieves user info from userinfo endpoint
3. System checks for existing user by:
   - First checking for matching `sub` claim
   - Then checking for matching email address
4. If no existing user found, creates new user with:
   - Generated username (from preferred_username or sub)
   - Email address from claims
   - Random password
   - Required roles (authenticated user)
   - OpenID Connect specific data:
     - `openid_connect_client` (provider name)
     - `openid_connect_sub` (subject identifier)
5. System connects the user account to the OpenID Connect provider by:
   - Creating authmap entry
   - Storing the `sub` claim
   - Storing the provider name

### 4. Session Establishment

1. System initializes user session
2. System sets up session variables:
   - `uid`
   - `roles`
   - `name`
3. System updates user's last login time
4. System redirects to original destination or home page

## Error Handling

The system handles various error conditions:

1. Invalid or missing tokens
2. Missing required claims (email)
3. Email address conflicts
4. Username conflicts
5. Database errors during user creation
6. Session initialization failures

## Logging

The module provides detailed logging at each step:

1. Authorization request details
2. Token exchange results
3. User creation process
4. Session establishment
5. Error conditions

## Security Considerations

1. PKCE provides additional security by:
   - Preventing authorization code interception
   - Ensuring the same client that initiated the flow completes it
2. State token prevents CSRF attacks
3. All tokens are validated before use
4. User data is sanitized before storage
5. Passwords are randomly generated and not exposed

## Configuration Requirements

1. Provider must support PKCE
2. Client must be configured with:
   - Valid redirect URIs
   - Required scopes
   - PKCE enabled
3. System must have:
   - Valid session handling
   - Proper timezone configuration
   - Required user fields configured

## Troubleshooting

Common issues and solutions:

1. **User not created**
   - Check logs for specific error messages
   - Verify required claims are present
   - Check database permissions

2. **Session not established**
   - Verify session configuration
   - Check user role assignments
   - Review session initialization logs

3. **PKCE errors**
   - Verify code verifier/challenge generation
   - Check provider PKCE support
   - Review token exchange logs

## Additional Resources

1. OpenID Connect Core Specification
2. PKCE RFC 7636
3. Module configuration documentation
4. Provider-specific documentation 