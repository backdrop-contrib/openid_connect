<?php

/**
 * @file
 * Page callbacks for OpenID Connect.
 */

/**
 * Page callback: Page whereto OpenID Connect login provider redirects.
 */
function openid_connect_redirect_page($client_name) {
  watchdog('openid_connect_' . $client_name, 'Step 9: Processing redirect page for client: @client', array('@client' => $client_name), WATCHDOG_INFO);
  
  // Get parameters from the session.
  $parameters = isset($_SESSION['openid_connect_parameters']) ? $_SESSION['openid_connect_parameters'] : array();
  watchdog('openid_connect_' . $client_name, 'Retrieved parameters from session: @params', array('@params' => print_r($parameters, TRUE)), WATCHDOG_DEBUG);
  watchdog('openid_connect_' . $client_name, 'Step 10: Retrieved stored parameters from session', array(), WATCHDOG_INFO);
  
  // Get the client.
  $client = openid_connect_get_client($client_name);
  if (!$client || !isset($_GET['code'])) {
    watchdog('openid_connect_' . $client_name, 'Invalid request - missing client or authorization code', array(), WATCHDOG_ERROR);
    backdrop_set_message(t('Invalid request.'), 'error');
    backdrop_goto();
  }
  watchdog('openid_connect_' . $client_name, 'Step 11: Validated client and authorization code presence', array(), WATCHDOG_INFO);

  // Validate the state token.
  if (!openid_connect_confirm_state_token($_GET['state'])) {
    watchdog('openid_connect_' . $client_name, 'State token validation failed. Expected: @expected, Received: @received', 
      array(
        '@expected' => $_SESSION['openid_connect_state'],
        '@received' => $_GET['state']
      ), 
      WATCHDOG_ERROR
    );
    backdrop_set_message(t('Login failed. Invalid state token.'), 'error');
    backdrop_goto();
  }
  watchdog('openid_connect_' . $client_name, 'Step 12: Successfully validated state token', array(), WATCHDOG_INFO);

  // Check if we have an error response.
  if (isset($_GET['error'])) {
    if ($_GET['error'] == 'access_denied') {
      watchdog('openid_connect_' . $client_name, 'User denied access to the authorization request', array(), WATCHDOG_WARNING);
      backdrop_set_message(t('Login was denied.'), 'warning');
    }
    else {
      watchdog('openid_connect_' . $client_name, 'Authorization failed: @error', array('@error' => $_GET['error']), WATCHDOG_ERROR);
      backdrop_set_message(t('Login failed. Error: @error', array('@error' => $_GET['error'])), 'error');
    }
    backdrop_goto();
  }
  watchdog('openid_connect_' . $client_name, 'Step 13: No authorization errors detected', array(), WATCHDOG_INFO);

  // Get the tokens from the client.
  $tokens = $client->retrieveTokens($_GET['code']);
  if (isset($tokens['error'])) {
    watchdog('openid_connect_' . $client_name, 'Error retrieving tokens: @error', array('@error' => $tokens['error']), WATCHDOG_ERROR);
    backdrop_set_message(t('Login failed. Error: @error', array('@error' => $tokens['error'])), 'error');
    backdrop_goto();
  }
  watchdog('openid_connect_' . $client_name, 'Step 14: Successfully retrieved tokens from client', array(), WATCHDOG_INFO);

  // Complete the authorization.
  $destination = isset($parameters['destination']) ? $parameters['destination'] : '';
  if (openid_connect_complete_authorization($client, $tokens, $destination)) {
    watchdog('openid_connect_' . $client_name, 'Step 15: Authorization completed successfully', array(), WATCHDOG_INFO);
    backdrop_set_message(t('You have been logged in.'));
  }
  else {
    watchdog('openid_connect_' . $client_name, 'Authorization completion failed', array(), WATCHDOG_ERROR);
    backdrop_set_message(t('Login failed.'), 'error');
  }

  // Clear the session variables.
  unset($_SESSION['openid_connect_parameters']);
  unset($_SESSION['openid_connect_state']);

  // Redirect to the destination.
  if ($destination) {
    watchdog('openid_connect_' . $client_name, 'Step 16: Redirecting to destination: @destination', array('@destination' => $destination), WATCHDOG_INFO);
    backdrop_goto($destination);
  }
  else {
    watchdog('openid_connect_' . $client_name, 'Step 16: No destination specified, redirecting to user page', array(), WATCHDOG_INFO);
    backdrop_goto('user');
  }
}

/**
 * Access callback for the redirect page.
 */
function openid_connect_redirect_access($client_name) {
  // Check if the client exists and is enabled.
  $client = openid_connect_get_client($client_name);
  if (!$client) {
    watchdog('openid_connect', 'Access denied: Client @client does not exist', array('@client' => $client_name), WATCHDOG_WARNING);
    return FALSE;
  }

  $config = config('openid_connect.settings');
  $enabled_clients = $config->get('openid_connect_clients_enabled');
  if (!isset($enabled_clients[$client_name]) || !$enabled_clients[$client_name]) {
    watchdog('openid_connect', 'Access denied: Client @client is not enabled', array('@client' => $client_name), WATCHDOG_WARNING);
    return FALSE;
  }

  return TRUE;
}
