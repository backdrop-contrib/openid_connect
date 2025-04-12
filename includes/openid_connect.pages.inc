<?php

/**
 * @file
 * Page callbacks for OpenID Connect.
 */

/**
 * Page callback: Page whereto OpenID Connect login provider redirects.
 */
function openid_connect_redirect_page($client_name) {
  watchdog('openid_connect_' . $client_name, 'Processing redirect page for client: @client', array('@client' => $client_name), WATCHDOG_DEBUG);
  
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
  watchdog('openid_connect_' . $client_name, 'Retrieved parameters from session: @params', array('@params' => print_r($parameters, TRUE)), WATCHDOG_DEBUG);

  $client = openid_connect_get_client($client_name);
  if (!isset($_GET['error']) && (!$client || !isset($_GET['code']))) {
    watchdog('openid_connect_' . $client_name, 'Invalid request - missing client, code, or error parameter', array(), WATCHDOG_ERROR);
    return MENU_NOT_FOUND;
  }

  // Validate state token before proceeding
  if (!isset($_GET['state']) || !isset($_SESSION['openid_connect_state']) || $_GET['state'] !== $_SESSION['openid_connect_state']) {
    watchdog('openid_connect_' . $client_name, 'Invalid state token provided. Expected: @expected, Received: @received', 
      array(
        '@expected' => isset($_SESSION['openid_connect_state']) ? $_SESSION['openid_connect_state'] : 'not set',
        '@received' => isset($_GET['state']) ? $_GET['state'] : 'not set'
      ), 
      WATCHDOG_ERROR
    );
    backdrop_set_message(t('Invalid state token. Please try logging in again.'), 'error');
    backdrop_goto('user/login');
    return;
  }

  // Delete the state token after validation
  unset($_SESSION['openid_connect_state']);
  watchdog('openid_connect_' . $client_name, 'State token validated successfully', array(), WATCHDOG_DEBUG);

  $provider_param = array('@provider' => $client->getLabel());

  if (isset($_GET['error'])) {
    if ($_GET['error'] == 'access_denied') {
      watchdog('openid_connect_' . $client_name, 'User denied authorization request', array(), WATCHDOG_INFO);
      backdrop_set_message(t('Logging in with @provider has been canceled.', $provider_param), 'warning');
    }
    else {
      $variables = array(
        '@error' => $_GET['error'],
        '@details' => isset($_GET['error_description']) ? $_GET['error_description'] : t('None'),
      );
      watchdog('openid_connect_' . $client_name, 'Authorization failed: @error. Details: @details', $variables, WATCHDOG_ERROR);
    }
  }
  else {
    watchdog('openid_connect_' . $client_name, 'Received authorization code: @code', array('@code' => $_GET['code']), WATCHDOG_DEBUG);
    
    // Process the login or connect operations.
    $tokens = $client->retrieveTokens($_GET['code']);
    if ($tokens) {
      watchdog('openid_connect_' . $client_name, 'Successfully retrieved tokens from client', array(), WATCHDOG_DEBUG);
      
      if ($parameters['op'] === 'login') {
        $success = openid_connect_complete_authorization($client, $tokens, $destination);
        if (!$success) {
          watchdog('openid_connect_' . $client_name, 'Failed to complete authorization', array(), WATCHDOG_ERROR);
          backdrop_set_message(t('Logging in with @provider could not be completed due to an error.', $provider_param), 'error');
        }
        else {
          watchdog('openid_connect_' . $client_name, 'Successfully completed authorization', array(), WATCHDOG_INFO);
        }
      }
      elseif ($parameters['op'] === 'connect' && $parameters['connect_uid'] === $GLOBALS['user']->uid) {
        $success = openid_connect_connect_current_user($client, $tokens);
        if ($success) {
          watchdog('openid_connect_' . $client_name, 'Successfully connected user account', array(), WATCHDOG_INFO);
          backdrop_set_message(t('Account successfully connected with @provider.', $provider_param));
        }
        else {
          watchdog('openid_connect_' . $client_name, 'Failed to connect user account', array(), WATCHDOG_ERROR);
          backdrop_set_message(t('Connecting with @provider could not be completed due to an error.', $provider_param), 'error');
        }
      }
    }
    else {
      watchdog('openid_connect_' . $client_name, 'Failed to retrieve tokens from client', array(), WATCHDOG_ERROR);
    }
  }

  // It's possible to set 'options' in the redirect destination.
  if (is_array($destination)) {
    watchdog('openid_connect_' . $client_name, 'Redirecting to: @path with options: @options', 
      array(
        '@path' => $destination[0],
        '@options' => print_r($destination[1], TRUE)
      ), 
      WATCHDOG_DEBUG
    );
    backdrop_goto($destination[0], $destination[1]);
  }
  else {
    watchdog('openid_connect_' . $client_name, 'Redirecting to: @path', array('@path' => $destination), WATCHDOG_DEBUG);
    backdrop_goto($destination);
  }
}

/**
 * Access callback for the redirect page.
 */
function openid_connect_redirect_access($client_name) {
  // Check if we have a state token to validate.
  if (!isset($_SESSION['openid_connect_state'])) {
    return FALSE;
  }

  // Check if the state token matches the one in the session.
  if (!isset($_GET['state']) || $_GET['state'] !== $_SESSION['openid_connect_state']) {
    return FALSE;
  }

  // Check if the client exists and is enabled.
  $client = openid_connect_get_client($client_name);
  if (!$client) {
    return FALSE;
  }

  $config = config('openid_connect.settings');
  $enabled_clients = $config->get('openid_connect_clients_enabled');
  if (!isset($enabled_clients[$client_name]) || !$enabled_clients[$client_name]) {
    return FALSE;
  }

  return TRUE;
}
