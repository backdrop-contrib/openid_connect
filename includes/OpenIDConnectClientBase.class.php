<?php

/**
 * @file
 * Base class for OpenID Connect clients.
 * 
 * This class implements the core OAuth 2.0 and OpenID Connect functionality:
 * 1. Client Configuration
 *    - Client ID and secret management
 *    - Endpoint configuration
 *    - Settings form handling
 * 
 * 2. Authorization Flow
 *    - Authorization request construction
 *    - State parameter generation
 *    - PKCE support (if enabled)
 * 
 * 3. Token Management
 *    - Authorization code exchange
 *    - Token validation
 *    - ID token processing
 * 
 * 4. User Information
 *    - Userinfo endpoint integration
 *    - Claims mapping
 *    - Profile data handling
 */

/**
 * Base class for OpenID Connect clients.
 * 
 * This abstract class provides the foundation for OpenID Connect client implementations.
 * It handles the core OAuth 2.0 and OpenID Connect protocol requirements:
 * 
 * - Authorization Code Flow
 * - Token Exchange
 * - ID Token Validation
 * - User Info Retrieval
 * 
 * Client implementations should extend this class and implement:
 * 1. getEndpoints() - Define provider-specific endpoints
 * 2. settingsForm() - Add provider-specific settings
 * 3. retrieveUserInfo() - Customize user info retrieval
 */
abstract class OpenIDConnectClientBase implements OpenIDConnectClientInterface {

  /**
   * The machine name of the client plugin.
   *
   * @var string
   */
  protected $name;

  /**
   * The human-readable name of the client plugin.
   *
   * @var string
   */
  protected $label;

  /**
   * Admin-provided configuration.
   *
   * @var array
   */
  protected $settings;

  /**
   * Constructs a new OpenIDConnectClientBase.
   *
   * @param string $name
   *   The machine name of the client plugin.
   * @param string $label
   *   The human-readable name of the client plugin.
   * @param array $settings
   *   Admin-provided configuration.
   */
  public function __construct($name, $label, array $settings) {
    watchdog('openid_connect', 'Initializing OpenID Connect client: %name', array('%name' => $name), WATCHDOG_DEBUG);
    $this->name = $name;
    $this->label = $label;
    $this->settings = $settings;
  }

  /**
   * {@inheritdoc}
   */
  public function getLabel() {
    return $this->label;
  }

  /**
   * {@inheritdoc}
   */
  public function getName() {
    return $this->name;
  }

  /**
   * {@inheritdoc}
   */
  public function getSetting($key, $default = NULL) {
    $value = isset($this->settings[$key]) ? $this->settings[$key] : $default;
    // Trim client_id and client_secret to prevent whitespace issues
    if (in_array($key, ['client_id', 'client_secret']) && $value !== NULL) {
      $value = trim($value);
    }
    return $value;
  }

  /**
   * {@inheritdoc}
   * 
   * Provides the base settings form for all OpenID Connect clients.
   * All clients require:
   * 1. Client ID - The OAuth client identifier
   * 2. Client Secret - The OAuth client secret
   * 
   * Child classes can extend this to add provider-specific settings.
   */
  public function settingsForm() {
    $form['client_id'] = array(
      '#title' => t('Client ID'),
      '#type' => 'textfield',
      '#default_value' => $this->getSetting('client_id'),
    );
    $form['client_secret'] = array(
      '#title' => t('Client secret'),
      '#type' => 'textarea',
      '#default_value' => $this->getSetting('client_secret'),
    );

    return $form;
  }

  /**
   * {@inheritdoc}
   * 
   * Validates the settings form:
   * 1. Trims whitespace from credentials
   * 2. Ensures required fields are not empty
   * 3. Validates credential format if needed
   */
  public function settingsFormValidate($form, &$form_state, $error_element_base) {
    // Trim whitespace from client_id and client_secret
    if (!empty($form_state['values']['client_id'])) {
      $form_state['values']['client_id'] = trim($form_state['values']['client_id']);
    }
    if (!empty($form_state['values']['client_secret'])) {
      $form_state['values']['client_secret'] = trim($form_state['values']['client_secret']);
    }
    
    // Validate that required fields are not empty after trimming
    if (empty($form_state['values']['client_id'])) {
      form_error($form[$error_element_base . 'client_id'], t('Client ID is required.'));
    }
    if (empty($form_state['values']['client_secret'])) {
      form_error($form[$error_element_base . 'client_secret'], t('Client secret is required.'));
    }
  }

  /**
   * {@inheritdoc}
   */
  public function settingsFormSubmit($form, &$form_state) {
    // No need to do anything, but make the function have a body anyway
    // so that it's callable by overriding methods.
  }

  /**
   * {@inheritdoc}
   * 
   * This method must be implemented by child classes to define:
   * 1. Authorization endpoint
   * 2. Token endpoint
   * 3. Userinfo endpoint
   * 4. Any other provider-specific endpoints
   */
  public function getEndpoints() {
    throw new Exception('Unimplemented method getEndpoints().');
  }

  /**
   * Generates a PKCE code verifier.
   *
   * @return string
   *   A random code verifier string that meets RFC 7636 requirements.
   * 
   * The code verifier is:
   * 1. A random string of 32 bytes
   * 2. Base64URL encoded
   * 3. Stored in session for token exchange
   */
  protected function generateCodeVerifier() {
    watchdog('openid_connect', 'Generating PKCE code verifier for client: %client', array('%client' => $this->name), WATCHDOG_DEBUG);
    
    // Generate a random string of 32 bytes (256 bits)
    $random_bytes = backdrop_random_bytes(32);
    
    // Base64URL encode the random bytes and remove padding
    $verifier = rtrim(strtr(base64_encode($random_bytes), '+/', '-_'), '=');
    
    // Store in session for token retrieval
    $_SESSION['openid_connect_pkce_code_verifier'] = $verifier;
    
    watchdog('openid_connect', 'Generated PKCE code verifier of length %length', 
      array('%length' => strlen($verifier)), WATCHDOG_DEBUG);
    
    return $verifier;
  }

  /**
   * Generates a PKCE code challenge from a verifier.
   *
   * @param string $verifier
   *   The code verifier.
   *
   * @return string
   *   The code challenge in base64url format.
   * 
   * The code challenge is:
   * 1. SHA256 hash of the verifier
   * 2. Base64URL encoded
   * 3. Used in authorization request
   */
  protected function generateCodeChallenge($verifier) {
    watchdog('openid_connect', 'Generating PKCE code challenge for client: %client', array('%client' => $this->name), WATCHDOG_DEBUG);
    
    // SHA256 hash the verifier
    $hash = hash('sha256', $verifier, true);
    
    // Base64URL encode the hash and remove padding
    $challenge = rtrim(strtr(base64_encode($hash), '+/', '-_'), '=');
    
    watchdog('openid_connect', 'Generated PKCE code challenge of length %length', 
      array('%length' => strlen($challenge)), WATCHDOG_DEBUG);
    
    return $challenge;
  }

  /**
   * {@inheritdoc}
   * 
   * Initiates the authorization flow by:
   * 1. Constructing the authorization URL
   * 2. Adding required parameters
   * 3. Redirecting to the provider
   * 
   * The authorization URL includes:
   * - response_type=code
   * - client_id
   * - redirect_uri
   * - scope (comma-separated)
   * - state (CSRF protection)
   * - PKCE parameters (if enabled)
   */
  public function authorize($scope = 'openid email') {
    $endpoints = $this->getEndpoints();
    $redirect_uri = OPENID_CONNECT_REDIRECT_PATH_BASE . '/' . $this->name;
    $absolute_redirect_uri = url($redirect_uri, array(
      'absolute' => TRUE,
      'https' => TRUE,
      'language' => LANGUAGE_NONE,
    ));
    
    // Generate and store state token
    $state = openid_connect_create_state_token();
    
    // Generate PKCE code verifier and challenge
    $code_verifier = $this->generateCodeVerifier();
    $code_challenge = $this->generateCodeChallenge($code_verifier);
    
    // Save destination URL if it exists
    openid_connect_save_destination();
    
    // Build authorization URL - order parameters as Doorkeeper expects
    $query_params = array(
      'response_type' => 'code',
      'client_id' => trim($this->getSetting('client_id')),
      'redirect_uri' => $absolute_redirect_uri,
      'scope' => $scope,
      'state' => $state,
      'code_challenge' => $code_challenge,
      'code_challenge_method' => 'S256',
    );
    
    // Use the configured authorization endpoint
    $authorization_url = $endpoints['authorization'] . '?' . 
      'response_type=' . $query_params['response_type'] . '&' .
      'client_id=' . $query_params['client_id'] . '&' .
      'redirect_uri=' . $query_params['redirect_uri'] . '&' .
      'scope=' . $query_params['scope'] . '&' .
      'state=' . $query_params['state'] . '&' .
      'code_challenge=' . $query_params['code_challenge'] . '&' .
      'code_challenge_method=' . $query_params['code_challenge_method'];

    // Clear $_GET['destination'] because we need to override it
    unset($_GET['destination']);
    
    // Use direct header redirect instead of backdrop_goto
    header('Location: ' . $authorization_url);
    exit;
  }

  /**
   * Gets the redirect URL for the current request.
   *
   * @return string
   *   The redirect URL.
   */
  public function getRedirectUrl() {
    $endpoints = $this->getEndpoints();
    return url($endpoints['redirect'], array('absolute' => TRUE));
  }

  /**
   * Retrieves tokens from the token endpoint.
   *
   * @param string $authorization_code
   *   Authorization code received from the authorization endpoint.
   *
   * @return array|bool
   *   Array with tokens (access_token, id_token, refresh_token) or FALSE if
   *   token retrieval failed.
   * 
   * This method:
   * 1. Validates the authorization code
   * 2. Constructs the token request
   * 3. Sends the request to the token endpoint
   * 4. Validates the response
   * 5. Returns the tokens
   */
  public function retrieveTokens($authorization_code) {
    watchdog('openid_connect', 'Starting token retrieval for client: %client', array('%client' => $this->name), WATCHDOG_DEBUG);
    
    // Validate authorization code
    if (empty($authorization_code)) {
      watchdog('openid_connect', 'Empty authorization code provided', array(), WATCHDOG_ERROR);
      return FALSE;
    }

    // Prepare token request - use exact same redirect URI construction as in authorize()
    $redirect_uri = OPENID_CONNECT_REDIRECT_PATH_BASE . '/' . $this->name;
    $absolute_redirect_uri = url($redirect_uri, array(
      'absolute' => TRUE,
      'language' => LANGUAGE_NONE,
    ));
    
    $endpoints = $this->getEndpoints();
    if (empty($endpoints['token'])) {
      watchdog('openid_connect', 'Token endpoint not configured for client: %client', array('%client' => $this->name), WATCHDOG_ERROR);
      return FALSE;
    }

    // Get client credentials
    $client_id = trim($this->getSetting('client_id'));
    $client_secret = trim($this->getSetting('client_secret'));
    
    if (empty($client_id) || empty($client_secret)) {
      watchdog('openid_connect', 'Missing client credentials', array(), WATCHDOG_ERROR);
      return FALSE;
    }
    
    // Build request parameters
    $request_params = array(
      'grant_type' => 'authorization_code',
      'code' => $authorization_code,
      'redirect_uri' => $absolute_redirect_uri,
      'client_id' => $client_id,
      'client_secret' => $client_secret,
    );

    watchdog('openid_connect', 'Token request parameters prepared: endpoint=%endpoint, redirect=%redirect, client_id=%client_id', 
      array(
        '%endpoint' => $endpoints['token'],
        '%redirect' => $absolute_redirect_uri,
        '%client_id' => $client_id
      ), WATCHDOG_DEBUG);

    // Prepare HTTP request
    $request_options = array(
      'headers' => array(
        'Content-Type' => 'application/x-www-form-urlencoded',
      ),
      'method' => 'POST',
      'data' => http_build_query($request_params, '', '&'),
      'timeout' => 30,
    );

    try {
      watchdog('openid_connect', 'Sending token request to: %endpoint with params: %params', 
        array(
          '%endpoint' => $endpoints['token'],
          '%params' => print_r($request_params, TRUE)
        ), WATCHDOG_DEBUG);
      
      $response = backdrop_http_request($endpoints['token'], $request_options);
      
      watchdog('openid_connect', 'Token response received. Code: %code, Error: %error, Data: %data', 
        array(
          '%code' => $response->code,
          '%error' => isset($response->error) ? $response->error : 'none',
          '%data' => isset($response->data) ? $response->data : 'none'
        ), WATCHDOG_DEBUG);
      
      // Check for network level errors
      if (isset($response->error)) {
        watchdog('openid_connect', 'HTTP error in token request: %error', array('%error' => $response->error), WATCHDOG_ERROR);
        return FALSE;
      }
      
      // Parse and validate response
      if ($response->code == 200) {
        $response_data = backdrop_json_decode($response->data);
        
        if (!is_array($response_data)) {
          watchdog('openid_connect', 'Invalid JSON response from token endpoint: %data', 
            array('%data' => $response->data), WATCHDOG_ERROR);
          return FALSE;
        }
        
        // Check for required tokens
        if (empty($response_data['access_token'])) {
          watchdog('openid_connect', 'No access token in response: %response', 
            array('%response' => print_r($response_data, TRUE)), WATCHDOG_ERROR);
          return FALSE;
        }
        
        watchdog('openid_connect', 'Successfully retrieved tokens for client: %client', array('%client' => $this->name), WATCHDOG_DEBUG);
        
        return array(
          'id_token' => isset($response_data['id_token']) ? $response_data['id_token'] : NULL,
          'access_token' => $response_data['access_token'],
          'refresh_token' => isset($response_data['refresh_token']) ? $response_data['refresh_token'] : NULL,
        );
      }
      else {
        watchdog('openid_connect', 'Token request failed with HTTP %code. Response: %response', 
          array(
            '%code' => $response->code,
            '%response' => isset($response->data) ? $response->data : 'No response data'
          ), WATCHDOG_ERROR);
        return FALSE;
      }
    }
    catch (Exception $e) {
      watchdog('openid_connect', 'Exception during token request: @message', array('@message' => $e->getMessage()), WATCHDOG_ERROR);
      return FALSE;
    }
  }

  /**
   * {@inheritdoc}
   * 
   * Decodes and validates the ID token:
   * 1. Splits the JWT into header, claims, and signature
   * 2. Decodes the claims section
   * 3. Returns the claims as an array
   */
  public function decodeIdToken($id_token) {
    watchdog('openid_connect', 'Decoding ID token for client: %client', array('%client' => $this->name), WATCHDOG_DEBUG);
    list($headerb64, $claims64, $signatureb64) = explode('.', $id_token);
    $claims64 = str_replace(array('-', '_'), array('+', '/'), $claims64);
    $claims64 = base64_decode($claims64);
    $claims = backdrop_json_decode($claims64);
    watchdog('openid_connect', 'Successfully decoded ID token for client: %client', 
      array('%client' => $this->name), WATCHDOG_DEBUG);
    return $claims;
  }

  /**
   * Retrieves user info from the userinfo endpoint.
   *
   * @param string $access_token
   *   Access token.
   *
   * @return array|bool
   *   User info array with standardized keys, or FALSE if retrieval failed.
   * 
   * This method:
   * 1. Validates the access token
   * 2. Makes a request to the userinfo endpoint
   * 3. Maps standard claims to user properties
   * 4. Returns the user info
   */
  public function retrieveUserInfo($access_token) {
    watchdog('openid_connect', 'Starting user info retrieval for client: %client', array('%client' => $this->name), WATCHDOG_DEBUG);
    
    if (empty($access_token)) {
      watchdog('openid_connect', 'Empty access token provided', array(), WATCHDOG_ERROR);
      return FALSE;
    }

    $endpoints = $this->getEndpoints();
    if (empty($endpoints['userinfo'])) {
      watchdog('openid_connect', 'User info endpoint not configured for client: %client', array('%client' => $this->name), WATCHDOG_ERROR);
      return FALSE;
    }

    // Prepare request options
    $request_options = array(
      'headers' => array(
        'Authorization' => 'Bearer ' . $access_token,
        'Accept' => 'application/json',
      ),
      'method' => 'GET',
      'timeout' => 15,
    );

    try {
      watchdog('openid_connect', 'Sending user info request to: %endpoint', array('%endpoint' => $endpoints['userinfo']), WATCHDOG_DEBUG);
      
      $response = backdrop_http_request($endpoints['userinfo'], $request_options);
      
      // Check for network level errors
      if (isset($response->error)) {
        watchdog('openid_connect', 'HTTP error in user info request: %error', array('%error' => $response->error), WATCHDOG_ERROR);
        return FALSE;
      }

      // Parse and validate response
      if ($response->code == 200) {
        $userinfo = backdrop_json_decode($response->data);
        
        if (!is_array($userinfo)) {
          watchdog('openid_connect', 'Invalid JSON response from userinfo endpoint: %data', 
            array('%data' => $response->data), WATCHDOG_ERROR);
          return FALSE;
        }

        // Validate required fields
        if (empty($userinfo['sub'])) {
          watchdog('openid_connect', 'Missing required "sub" claim in userinfo response: %response', 
            array('%response' => print_r($userinfo, TRUE)), WATCHDOG_ERROR);
          return FALSE;
        }

        // Map standard claims
        $mapped_userinfo = array();
        $claims_mapping = array(
          'sub' => 'sub',
          'name' => 'name',
          'given_name' => 'given_name',
          'family_name' => 'family_name',
          'email' => 'email',
          'email_verified' => 'email_verified',
          'locale' => 'locale',
          'picture' => 'picture',
        );

        foreach ($claims_mapping as $src => $dest) {
          if (isset($userinfo[$src])) {
            $mapped_userinfo[$dest] = $userinfo[$src];
          }
        }

        // Add any additional claims that might be useful
        foreach ($userinfo as $key => $value) {
          if (!isset($mapped_userinfo[$key])) {
            $mapped_userinfo[$key] = $value;
          }
        }

        watchdog('openid_connect', 'Successfully retrieved user info for sub: %sub', 
          array('%sub' => $mapped_userinfo['sub']), WATCHDOG_DEBUG);
        
        return $mapped_userinfo;
      }
      else {
        watchdog('openid_connect', 'User info request failed with HTTP %code. Response: %response', 
          array(
            '%code' => $response->code,
            '%response' => isset($response->data) ? $response->data : 'No response data'
          ), WATCHDOG_ERROR);
        return FALSE;
      }
    }
    catch (Exception $e) {
      watchdog('openid_connect', 'Exception during user info request: @message', array('@message' => $e->getMessage()), WATCHDOG_ERROR);
      return FALSE;
    }
  }

}
