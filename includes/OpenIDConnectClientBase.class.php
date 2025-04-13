<?php

/**
 * @file
 * Base class for OpenID Connect clients.
 */

/**
 * Base class for OpenID Connect clients.
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
    $this->name = $name;
    $this->label = $label;
    $this->settings = $settings;
    
    // Log client initialization
    watchdog('openid_connect', 'Initializing OpenID Connect client: @name (label: @label)', 
      array(
        '@name' => $name,
        '@label' => $label
      ), 
      WATCHDOG_DEBUG
    );
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
    return isset($this->settings[$key]) ? $this->settings[$key] : $default;
  }

  /**
   * {@inheritdoc}
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
   */
  public function settingsFormValidate($form, &$form_state, $error_element_base) {
    // No need to do anything, but make the function have a body anyway
    // so that it's callable by overriding methods.
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
   */
  public function getEndpoints() {
    throw new Exception('Unimplemented method getEndpoints().');
  }

  /**
   * Generates a PKCE code verifier.
   *
   * @return string
   *   A random code verifier string.
   */
  protected function generateCodeVerifier() {
    $verifier = backdrop_random_key(32);
    $_SESSION['openid_connect_code_verifier'] = $verifier;
    watchdog('openid_connect_' . $this->name, 'Generated PKCE code verifier: @verifier', array('@verifier' => $verifier), WATCHDOG_DEBUG);
    watchdog('openid_connect_' . $this->name, 'Step 1: Generated PKCE code verifier and stored in session', array(), WATCHDOG_INFO);
    return $verifier;
  }

  /**
   * Generates a PKCE code challenge from a verifier.
   *
   * @param string $verifier
   *   The code verifier.
   *
   * @return string
   *   The code challenge.
   */
  protected function generateCodeChallenge($verifier) {
    $challenge = base64_encode(hash('sha256', $verifier, TRUE));
    $challenge = rtrim(strtr($challenge, '+/', '-_'), '=');
    watchdog('openid_connect_' . $this->name, 'Generated PKCE code challenge: @challenge', array('@challenge' => $challenge), WATCHDOG_DEBUG);
    watchdog('openid_connect_' . $this->name, 'Step 2: Generated PKCE code challenge using SHA-256', array(), WATCHDOG_INFO);
    return $challenge;
  }

  /**
   * {@inheritdoc}
   */
  public function authorize($scope = 'openid email') {
    if (empty($this->name)) {
      watchdog('openid_connect', 'Client name is not set for OpenID Connect client', array(), WATCHDOG_ERROR);
      return FALSE;
    }
    
    watchdog('openid_connect_' . $this->name, 'Step 3: Starting authorization process with scope: @scope', array('@scope' => $scope), WATCHDOG_INFO);
    
    $redirect_uri = str_replace('-', '_', OPENID_CONNECT_REDIRECT_PATH_BASE) . '/' . $this->name;
    watchdog('openid_connect_' . $this->name, 'Base redirect URI path: @uri', array('@uri' => $redirect_uri), WATCHDOG_INFO);
    
    $absolute_redirect_uri = url($redirect_uri, array(
      'absolute' => TRUE,
      'language' => LANGUAGE_NONE,
      'https' => TRUE,
    ));
    watchdog('openid_connect_' . $this->name, 'Absolute redirect URI: @uri', array('@uri' => $absolute_redirect_uri), WATCHDOG_DEBUG);
    
    // Log the configured redirect URI from settings
    $configured_uri = $this->getSetting('redirect_uri');
    watchdog('openid_connect_' . $this->name, 'Configured redirect URI in settings: @uri', array('@uri' => $configured_uri), WATCHDOG_DEBUG);
    
    // Generate PKCE code verifier and challenge
    $code_verifier = $this->generateCodeVerifier();
    $code_challenge = $this->generateCodeChallenge($code_verifier);
    
    $url_options = array(
      'query' => array(
        'client_id' => $this->getSetting('client_id'),
        'response_type' => 'code',
        'scope' => $scope,
        'redirect_uri' => $absolute_redirect_uri,
        'state' => openid_connect_create_state_token(),
        'code_challenge' => $code_challenge,
        'code_challenge_method' => 'S256',
      ),
    );

    watchdog('openid_connect_' . $this->name, 'Authorization request parameters: @params', 
      array('@params' => print_r($url_options['query'], TRUE)), 
      WATCHDOG_DEBUG
    );

    try {
      $endpoints = $this->getEndpoints();
      if (empty($endpoints['authorization'])) {
        watchdog('openid_connect_' . $this->name, 'Authorization endpoint not found', array(), WATCHDOG_ERROR);
        return FALSE;
      }

      watchdog('openid_connect_' . $this->name, 'Step 4: Redirecting to authorization endpoint with PKCE parameters', array(), WATCHDOG_INFO);
      
      // Log the complete authorization URL for debugging
      $complete_url = $endpoints['authorization'] . '?' . backdrop_http_build_query($url_options['query']);
      watchdog('openid_connect_' . $this->name, 'Complete authorization URL: @url', 
        array('@url' => $complete_url), 
        WATCHDOG_DEBUG
      );
      
      // Clear $_GET['destination'] because we need to override it.
      unset($_GET['destination']);
      backdrop_goto($endpoints['authorization'], $url_options);
    }
    catch (Exception $e) {
      watchdog('openid_connect_' . $this->name, 'Error during authorization: @error', 
        array('@error' => $e->getMessage()), 
        WATCHDOG_ERROR
      );
      return FALSE;
    }
  }

  /**
   * {@inheritdoc}
   */
  public function retrieveTokens($authorization_code) {
    watchdog('openid_connect_' . $this->name, 'Step 5: Starting token retrieval with authorization code', array(), WATCHDOG_INFO);
    
    // Exchange `code` for access token and ID token.
    $redirect_uri = str_replace('-', '_', OPENID_CONNECT_REDIRECT_PATH_BASE) . '/' . $this->name;
    
    // Get the code verifier from session
    $code_verifier = isset($_SESSION['openid_connect_code_verifier']) ? $_SESSION['openid_connect_code_verifier'] : '';
    watchdog('openid_connect_' . $this->name, 'Retrieved PKCE code verifier from session: @verifier', 
      array('@verifier' => $code_verifier), 
      WATCHDOG_DEBUG
    );
    watchdog('openid_connect_' . $this->name, 'Step 6: Retrieved PKCE code verifier from session', array(), WATCHDOG_INFO);
    unset($_SESSION['openid_connect_code_verifier']);
    
    $post_data = array(
      'code' => $authorization_code,
      'client_id' => $this->getSetting('client_id'),
      'client_secret' => $this->getSetting('client_secret'),
      'redirect_uri' => url($redirect_uri, array(
        'absolute' => TRUE,
        'language' => LANGUAGE_NONE,
      )),
      'grant_type' => 'authorization_code',
      'code_verifier' => $code_verifier,
    );
    $request_options = array(
      'method' => 'POST',
      'data' => backdrop_http_build_query($post_data),
      'timeout' => 15,
      'headers' => array('Content-Type' => 'application/x-www-form-urlencoded'),
    );
    $endpoints = $this->getEndpoints();
    watchdog('openid_connect_' . $this->name, 'Requesting tokens from @endpoint with parameters: @params', 
      array(
        '@endpoint' => $endpoints['token'],
        '@params' => print_r($post_data, TRUE)
      ), 
      WATCHDOG_DEBUG
    );
    watchdog('openid_connect_' . $this->name, 'Step 7: Sending token request with PKCE code verifier', array(), WATCHDOG_INFO);
    
    $response = backdrop_http_request($endpoints['token'], $request_options);
    if (!isset($response->error) && $response->code == 200) {
      watchdog('openid_connect_' . $this->name, 'Successfully retrieved tokens from provider', array(), WATCHDOG_DEBUG);
      watchdog('openid_connect_' . $this->name, 'Step 8: Successfully received tokens from provider', array(), WATCHDOG_INFO);
      $response_data = backdrop_json_decode($response->data);
      $tokens = array(
        'id_token' => $response_data['id_token'],
        'access_token' => $response_data['access_token'],
      );
      if (array_key_exists('expires_in', $response_data)) {
        $tokens['expire'] = REQUEST_TIME + $response_data['expires_in'];
      }
      if (array_key_exists('refresh_token', $response_data)) {
        $tokens['refresh_token'] = $response_data['refresh_token'];
      }
      return $tokens;
    }
    else {
      openid_connect_log_request_error(__FUNCTION__, $this->name, $response);
      return FALSE;
    }
  }

  /**
   * {@inheritdoc}
   */
  public function decodeIdToken($id_token) {
    list($headerb64, $claims64, $signatureb64) = explode('.', $id_token);
    $claims64 = str_replace(array('-', '_'), array('+', '/'), $claims64);
    $claims64 = base64_decode($claims64);
    return backdrop_json_decode($claims64);
  }

  /**
   * {@inheritdoc}
   */
  public function retrieveUserInfo($access_token) {
    $request_options = array(
      'headers' => array(
        'Authorization' => 'Bearer ' . $access_token,
      ),
    );
    $endpoints = $this->getEndpoints();
    $response = backdrop_http_request($endpoints['userinfo'], $request_options);
    if (!isset($response->error) && $response->code == 200) {
      return backdrop_json_decode($response->data);
    }

    openid_connect_log_request_error(__FUNCTION__, $this->name, $response);

    return array();
  }

}
