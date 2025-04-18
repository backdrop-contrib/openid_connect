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
  // Enhanced debugging - Log all request details
  watchdog('openid_connect', 'Starting redirect page callback for client: %client', array('%client' => $client_name), WATCHDOG_DEBUG);
  watchdog('openid_connect', 'REQUEST details: %request', array('%request' => print_r($_REQUEST, TRUE)), WATCHDOG_DEBUG);
  watchdog('openid_connect', 'SESSION details: %session', array('%session' => print_r($_SESSION, TRUE)), WATCHDOG_DEBUG);
  
  // Get OAuth parameters from the request
  $state = isset($_GET['state']) ? $_GET['state'] : '';
  $code = isset($_GET['code']) ? $_GET['code'] : '';
  
  watchdog('openid_connect', 'OAuth parameters - State: %state, Code: %code', array('%state' => $state, '%code' => $code), WATCHDOG_DEBUG);

  // Validate state
  if (!openid_connect_confirm_state_token($state)) {
    watchdog('openid_connect', 'State token validation failed', array(), WATCHDOG_ERROR);
    return FALSE;
  }
  watchdog('openid_connect', 'State token validated successfully', array(), WATCHDOG_DEBUG);
  
  // Get stored session parameters
  $parameters = array(
    'destination' => 'user',
    'op' => 'login',
    'connect_uid' => NULL,
  );
  foreach ($parameters as $key => $default) {
    if (isset($_SESSION['openid_connect_' . $key])) {
      $parameters[$key] = $_SESSION['openid_connect_' . $key];
      unset($_SESSION['openid_connect_' . $key]);
    }
  }
  watchdog('openid_connect', 'Session parameters: %params', array('%params' => print_r($parameters, TRUE)), WATCHDOG_DEBUG);

  // Handle destination
  $destination = $parameters['destination'];
  if (is_array($destination)) {
    $path = $destination[0];
    $options = $destination[1];
  }
  else {
    $path = $destination;
    $options = array();
  }
  watchdog('openid_connect', 'Destination path: %path, options: %options', array('%path' => $path, '%options' => print_r($options, TRUE)), WATCHDOG_DEBUG);

  // Get client
  $client = openid_connect_get_client($client_name);
  if (!$client) {
    watchdog('openid_connect', 'Invalid OpenID Connect client: %client', array('%client' => $client_name), WATCHDOG_ERROR);
    backdrop_set_message(t('Invalid OpenID Connect client.'), 'error');
    backdrop_goto($path, $options);
  }
  watchdog('openid_connect', 'Client loaded successfully: %client', array('%client' => $client_name), WATCHDOG_DEBUG);

  // Exchange code for tokens
  $tokens = $client->retrieveTokens($code);
  if (!$tokens) {
    watchdog('openid_connect', 'Failed to retrieve tokens for client: %client', array('%client' => $client_name), WATCHDOG_ERROR);
    backdrop_set_message(t('Could not retrieve tokens.'), 'error');
    backdrop_goto($path, $options);
  }
  watchdog('openid_connect', 'Retrieved tokens successfully for client: %client', array('%client' => $client_name), WATCHDOG_DEBUG);

  // Complete authorization
  try {
    $success = openid_connect_complete_authorization($client, $tokens, $destination);
    if ($success) {
      watchdog('openid_connect', 'Authorization completed successfully for client: %client', array('%client' => $client_name), WATCHDOG_DEBUG);
      backdrop_set_message(t('You have been successfully logged in.'));
    }
    else {
      watchdog('openid_connect', 'Authorization failed for client: %client', array('%client' => $client_name), WATCHDOG_ERROR);
      backdrop_set_message(t('Login failed.'), 'error');
    }
  }
  catch (Exception $e) {
    watchdog('openid_connect', 'Exception during authorization: @message', array('@message' => $e->getMessage()), WATCHDOG_ERROR);
    backdrop_set_message(t('Login failed: @message', array('@message' => $e->getMessage())), 'error');
  }

  // Final redirect
  watchdog('openid_connect', 'Redirecting to: %path', array('%path' => $path), WATCHDOG_DEBUG);
  backdrop_goto($path, $options);
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
