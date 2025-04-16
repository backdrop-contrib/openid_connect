<?php

/**
 * @file
 * Page callbacks for OpenID Connect.
 */

/**
 * Page callback: Page whereto OpenID Connect login provider redirects.
 */
function openid_connect_redirect_page($client_name) {
  watchdog('openid_connect', 'Starting redirect page callback for client: %client', array('%client' => $client_name), WATCHDOG_DEBUG);
  
  // Get state from URL parameter
  $state = isset($_GET['state']) ? $_GET['state'] : '';
  $code = isset($_GET['code']) ? $_GET['code'] : '';
  
  watchdog('openid_connect', 'Received parameters - State: %state, Code length: %code_length', 
    array('%state' => $state, '%code_length' => strlen($code)), WATCHDOG_DEBUG);
  
  // Get parameters from the session, and then clean up.
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
  $destination = $parameters['destination'];
  watchdog('openid_connect', 'Retrieved parameters: %params', array('%params' => print_r($parameters, TRUE)), WATCHDOG_DEBUG);

  $client = openid_connect_get_client($client_name);
  if (!isset($_GET['error']) && (!$client || !isset($_GET['code']))) {
    watchdog('openid_connect', 'Invalid request - missing client or code parameter', array(), WATCHDOG_DEBUG);
    // In case we don't have an error, but the client could not be loaded or
    // there is no state token specified, the URI is probably being visited
    // outside of the login flow.
    return MENU_NOT_FOUND;
  }

  $provider_param = array('@provider' => $client->getLabel());

  if (isset($_GET['error'])) {
    if ($_GET['error'] == 'access_denied') {
      watchdog('openid_connect', 'Access denied by user for provider: %provider', array('%provider' => $client->getLabel()), WATCHDOG_DEBUG);
      // If we have an "access_denied" error, that means the user hasn't granted
      // the authorization for the claims.
      backdrop_set_message(t('Logging in with @provider has been canceled.', $provider_param), 'warning');
    }
    else {
      // Any other error should be logged. E.g. invalid scope.
      $variables = array(
        '@error' => $_GET['error'],
        '@details' => isset($_GET['error_description']) ? $_GET['error_description'] : t('None'),
      );
      watchdog('openid_connect_' . $client_name, 'Authorization failed: @error. Details: @details', $variables, WATCHDOG_ERROR);
    }
  }
  else {
    watchdog('openid_connect', 'Processing login/connect operation for provider: %provider', array('%provider' => $client->getLabel()), WATCHDOG_DEBUG);
    // Process the login or connect operations.
    $tokens = $client->retrieveTokens($_GET['code']);
    
    if ($tokens) {
      watchdog('openid_connect', 'Successfully retrieved tokens for provider: %provider', array('%provider' => $client->getLabel()), WATCHDOG_DEBUG);
      if ($parameters['op'] === 'login') {
        watchdog('openid_connect', 'Starting login authorization for provider: %provider', array('%provider' => $client->getLabel()), WATCHDOG_DEBUG);
        $success = openid_connect_complete_authorization($client, $tokens, $destination);
        if (!$success) {
          backdrop_set_message(t('Logging in with @provider could not be completed due to an error.', $provider_param), 'error');
        }
      }
      elseif ($parameters['op'] === 'connect' && $parameters['connect_uid'] === $GLOBALS['user']->uid) {
        watchdog('openid_connect', 'Starting account connection for provider: %provider', array('%provider' => $client->getLabel()), WATCHDOG_DEBUG);
        $success = openid_connect_connect_current_user($client, $tokens);
        if ($success) {
          backdrop_set_message(t('Account successfully connected with @provider.', $provider_param));
        }
        else {
          backdrop_set_message(t('Connecting with @provider could not be completed due to an error.', $provider_param), 'error');
        }
      }
    }
    else {
      watchdog('openid_connect', 'Failed to retrieve tokens for provider: %provider', array('%provider' => $client->getLabel()), WATCHDOG_ERROR);
    }
  }

  // It's possible to set 'options' in the redirect destination.
  if (is_array($destination)) {
    watchdog('openid_connect', 'Redirecting to array destination: %path', array('%path' => $destination[0]), WATCHDOG_DEBUG);
    backdrop_goto($destination[0], $destination[1]);
  }
  else {
    watchdog('openid_connect', 'Redirecting to destination: %path', array('%path' => $destination), WATCHDOG_DEBUG);
    backdrop_goto($destination);
  }
}

/**
 * Access callback for the redirect page.
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
