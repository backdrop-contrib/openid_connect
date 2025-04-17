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
  // Step 1: Log the start of the redirect process
  watchdog('openid_connect', 'Starting redirect page callback for client: %client', array('%client' => $client_name), WATCHDOG_DEBUG);
  
  // Step 2: Get OAuth parameters from the request
  $state = isset($_GET['state']) ? $_GET['state'] : '';
  $code = isset($_GET['code']) ? $_GET['code'] : '';
  
  // Step 3: Log received parameters for debugging
  watchdog('openid_connect', 'Received parameters - State: %state, Code length: %code_length', 
    array('%state' => $state, '%code_length' => strlen($code)), WATCHDOG_DEBUG);
  
  // Step 4: Retrieve stored session parameters
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

  // Step 5: Handle the destination
  $destination = $parameters['destination'];
  if (is_array($destination)) {
    $path = $destination[0];
    $options = $destination[1];
  }
  else {
    $path = $destination;
    $options = array();
  }

  // Step 6: Process the authorization code
  $client = openid_connect_get_client($client_name);
  if (!$client) {
    backdrop_set_message(t('Invalid OpenID Connect client.'), 'error');
    backdrop_goto($path, $options);
  }

  // Step 7: Exchange code for tokens
  $tokens = $client->retrieveTokens($code);
  if (!$tokens) {
    backdrop_set_message(t('Could not retrieve tokens.'), 'error');
    backdrop_goto($path, $options);
  }

  // Step 8: Process the tokens and authenticate the user
  $success = openid_connect_complete_authorization($client, $tokens, $parameters);
  if ($success) {
    backdrop_set_message(t('You have been successfully logged in.'));
  }
  else {
    backdrop_set_message(t('Log in failed.'), 'error');
  }

  // Step 9: Redirect to the destination
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
  // Check if we have a state token to validate.
  if (!isset($_SESSION['openid_connect_state'])) {
    watchdog('openid_connect', 'No state token found in session', array(), WATCHDOG_DEBUG);
    return FALSE;
  }

  // Check if the state token matches the one in the session.
  if (!isset($_GET['state']) || $_GET['state'] !== $_SESSION['openid_connect_state']) {
    watchdog('openid_connect', 'State token mismatch', array(), WATCHDOG_DEBUG);
    return FALSE;
  }

  // Check if the client exists and is enabled.
  $client = openid_connect_get_client($client_name);
  if (!$client) {
    watchdog('openid_connect', 'Client not found: %client', array('%client' => $client_name), WATCHDOG_DEBUG);
    return FALSE;
  }

  $config = config('openid_connect.settings');
  $enabled_clients = $config->get('openid_connect_clients_enabled');
  if (!isset($enabled_clients[$client_name]) || !$enabled_clients[$client_name]) {
    watchdog('openid_connect', 'Client not enabled: %client', array('%client' => $client_name), WATCHDOG_DEBUG);
    return FALSE;
  }

  watchdog('openid_connect', 'Access granted for client: %client', array('%client' => $client_name), WATCHDOG_DEBUG);
  return TRUE;
}
