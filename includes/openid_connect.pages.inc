<?php

/**
 * @file
 * Page callbacks for OpenID Connect.
 * 
 * This file handles the critical OAuth redirect endpoint where:
 * 1. Authorization code is received from the provider
 * 2. Token exchange occurs
 * 3. User authentication/registration is completed
 */

/**
 * Page callback: Page whereto OpenID Connect login provider redirects.
 * 
 * This is the main OAuth redirect handler that:
 * 1. Validates the state parameter (CSRF protection)
 * 2. Exchanges authorization code for tokens
 * 3. Processes the ID token and claims
 * 4. Handles user authentication or registration
 * 5. Manages user sessions
 * 
 * @param string $client_name
 *   The name of the OpenID Connect client plugin.
 */
function openid_connect_redirect_page($client_name) {
  // Start session if not already started
  if (!backdrop_session_started()) {
    backdrop_session_start();
    watchdog('openid_connect', 'Started new session in redirect page', array(), WATCHDOG_DEBUG);
  }

  watchdog('openid_connect', 'Redirect page called. Session status: %status, Session ID: %sid', 
    array(
      '%status' => session_status(),
      '%sid' => session_id()
    ), WATCHDOG_DEBUG);

  if (!isset($_GET['error']) && !isset($_GET['code'])) {
    watchdog('openid_connect', 'Missing code or error parameters', array(), WATCHDOG_ERROR);
    backdrop_set_message(t('Authentication failed. Please try logging in again.'), 'error');
    backdrop_goto('user/login', array('query' => array()));
    return;
  }

  if (isset($_GET['error'])) {
    watchdog('openid_connect', 'Authentication error: @error', array('@error' => $_GET['error']), WATCHDOG_ERROR);
    backdrop_set_message(t('Login failed: @error. Please try again.', array('@error' => $_GET['error'])), 'error');
    backdrop_goto('user/login', array('query' => array()));
    return;
  }

  $client = openid_connect_get_client($client_name);
  if (!$client) {
    watchdog('openid_connect', 'Invalid client: @client', array('@client' => $client_name), WATCHDOG_ERROR);
    backdrop_set_message(t('Authentication service is not properly configured. Please contact the site administrator.'), 'error');
    backdrop_goto('user/login', array('query' => array()));
    return;
  }

  // Verify the state parameter
  if (!isset($_GET['state'])) {
    watchdog('openid_connect', 'Missing state parameter', array(), WATCHDOG_ERROR);
    backdrop_set_message(t('Your login session has expired. Please try logging in again.'), 'error');
    backdrop_goto('user/login', array('query' => array()));
    return;
  }

  if (!isset($_SESSION['openid_connect_state'])) {
    watchdog('openid_connect', 'No state token in session. Session ID: %sid', 
      array('%sid' => session_id()), WATCHDOG_ERROR);
    backdrop_set_message(t('Your login session has expired. Please try logging in again.'), 'error');
    backdrop_goto('user/login', array('query' => array()));
    return;
  }

  watchdog('openid_connect', 'State verification - Received: %received, Session state: %session_state', 
    array(
      '%received' => $_GET['state'],
      '%session_state' => $_SESSION['openid_connect_state']
    ), WATCHDOG_DEBUG);

  if ($_GET['state'] !== $_SESSION['openid_connect_state']) {
    watchdog('openid_connect', 'State token mismatch. Expected: %expected, Received: %received',
      array(
        '%expected' => $_SESSION['openid_connect_state'],
        '%received' => $_GET['state']
      ), WATCHDOG_ERROR);
    backdrop_set_message(t('Your login session has expired or is invalid. Please try logging in again.'), 'error');
    backdrop_goto('user/login', array('query' => array()));
    return;
  }

  // Clear the state token after successful validation
  $state = $_SESSION['openid_connect_state'];
  unset($_SESSION['openid_connect_state']);
  unset($_SESSION['openid_connect_state_time']);

  // Use destination from session if available, default to 'user' if not set
  $destination = isset($_SESSION['openid_connect_destination']) ? $_SESSION['openid_connect_destination'] : array('path' => 'user', 'query' => array());
  unset($_SESSION['openid_connect_destination']);

  // Retrieve tokens and store the result
  $tokens = $client->retrieveTokens($_GET['code']);
  if (!$tokens) {
    watchdog('openid_connect', 'Failed to retrieve tokens', array(), WATCHDOG_ERROR);
    backdrop_set_message(t('Failed to complete authentication. Please try logging in again.'), 'error');
    backdrop_goto('user/login', array('query' => array()));
    return;
  }

  // Complete the authorization
  try {
    $success = openid_connect_complete_authorization($client, $tokens, $destination);
  }
  catch (Exception $e) {
    watchdog_exception('openid_connect', $e);
    backdrop_set_message(t('An error occurred during authentication. Please try logging in again.'), 'error');
    backdrop_goto('user/login', array('query' => array()));
    return;
  }

  if ($success) {
    // Ensure destination is properly structured
    if (is_string($destination)) {
      $path = $destination;
      $options = array('query' => array());
    }
    elseif (is_array($destination) && isset($destination['path'])) {
      $path = $destination['path'];
      $options = isset($destination['query']) ? array('query' => $destination['query']) : array('query' => array());
    }
    else {
      $path = 'user';
      $options = array('query' => array());
    }
    backdrop_goto($path, $options);
    return;
  }

  backdrop_set_message(t('Authentication failed. Please try logging in again.'), 'error');
  backdrop_goto('user/login', array('query' => array()));
  return;
}

/**
 * Access callback for the redirect page.
 * 
 * Validates:
 * 1. State parameter (CSRF protection)
 * 2. Client existence and configuration
 * 3. Client enabled status
 * 
 * @param string $client_name
 *   The name of the OpenID Connect client plugin.
 */
function openid_connect_redirect_access($client_name) {
  watchdog('openid_connect', 'Checking redirect access for client: %client', array('%client' => $client_name), WATCHDOG_DEBUG);
  
  // Check state token
  if (!isset($_SESSION['openid_connect_state'])) {
    watchdog('openid_connect', 'No state token in session', array(), WATCHDOG_ERROR);
    return FALSE;
  }
  if (!isset($_GET['state']) || $_GET['state'] !== $_SESSION['openid_connect_state']) {
    watchdog('openid_connect', 'State token mismatch. Session: %session, Request: %request', 
      array('%session' => $_SESSION['openid_connect_state'], '%request' => $_GET['state']), WATCHDOG_ERROR);
    return FALSE;
  }
  
  // Check client
  $client = openid_connect_get_client($client_name);
  if (!$client) {
    watchdog('openid_connect', 'Client not found: %client', array('%client' => $client_name), WATCHDOG_ERROR);
    return FALSE;
  }
  
  // Check if client is enabled
  $config = config('openid_connect.settings');
  $enabled_clients = $config->get('openid_connect_clients_enabled');
  if (empty($enabled_clients[$client_name])) {
    watchdog('openid_connect', 'Client not enabled: %client', array('%client' => $client_name), WATCHDOG_ERROR);
    return FALSE;
  }
  
  watchdog('openid_connect', 'Access granted for client: %client', array('%client' => $client_name), WATCHDOG_DEBUG);
  return TRUE;
}
