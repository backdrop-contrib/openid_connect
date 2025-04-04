<?php

/**
 * @file
 * Page callbacks for OpenID Connect.
 */

/**
 * Page callback: Page whereto OpenID Connect login provider redirects.
 */
function openid_connect_redirect_page($client_name) {
  // Delete the state token, since it's already been confirmed.
  unset($_SESSION['openid_connect_state']);

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

  $client = openid_connect_get_client($client_name);
  if (!isset($_GET['error']) && (!$client || !isset($_GET['code']))) {
    // In case we don't have an error, but the client could not be loaded or
    // there is no state token specified, the URI is probably being visited
    // outside of the login flow.
    return MENU_NOT_FOUND;
  }

  $provider_param = array('@provider' => $client->getLabel());

  if (isset($_GET['error'])) {
    if ($_GET['error'] == 'access_denied') {
      // If we have an "access denied" error, that means the user hasn't granted
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
    // Process the login or connect operations.
    $tokens = $client->retrieveTokens($_GET['code']);
    if ($tokens) {
      if ($parameters['op'] === 'login') {
        $success = openid_connect_complete_authorization($client, $tokens, $destination);
        if (!$success) {
          backdrop_set_message(t('Logging in with @provider could not be completed due to an error.', $provider_param), 'error');
        }
      }
      elseif ($parameters['op'] === 'connect' && $parameters['connect_uid'] === $GLOBALS['user']->uid) {
        $success = openid_connect_connect_current_user($client, $tokens);
        if ($success) {
          backdrop_set_message(t('Account successfully connected with @provider.', $provider_param));
        }
        else {
          backdrop_set_message(t('Connecting with @provider could not be completed due to an error.', $provider_param), 'error');
        }
      }
    }
  }

  // It's possible to set 'options' in the redirect destination.
  if (is_array($destination)) {
    backdrop_goto($destination[0], $destination[1]);
  }
  else {
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
