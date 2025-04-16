<?php

/**
 * @file
 * Forms for OpenID Connect.
 */

/**
 * Form builder: Log in with an external account.
 */
function openid_connect_login_form($form, &$form_state) {
  watchdog('openid_connect', 'Building login form in openid_connect_login_form', array(), WATCHDOG_DEBUG);
  form_load_include($form_state, 'inc', 'openid_connect', 'includes/openid_connect.forms');

  foreach (openid_connect_get_plugins(TRUE) as $client) {
    $form['openid_connect_client_' . $client['name'] . '_login'] = array(
      '#type' => 'submit',
      '#value' => t('Log in with @client_title', array('@client_title' => $client['title'])),
      '#name' => $client['name'],
    );
    watchdog('openid_connect', 'Added login button for client: %client', array('%client' => $client['name']), WATCHDOG_DEBUG);
  }

  return $form;
}

/**
 * Form submit handler: Log in with an OpenID Connect login provider.
 */
function openid_connect_login_form_submit($form, &$form_state) {
  watchdog('openid_connect', 'Processing login form submit in openid_connect_login_form_submit', array(), WATCHDOG_DEBUG);
  openid_connect_save_destination();

  $client_name = $form_state['triggering_element']['#name'];
  watchdog('openid_connect', 'Login initiated for client: %client', array('%client' => $client_name), WATCHDOG_DEBUG);
  $client = openid_connect_get_client($client_name);
  $scopes = openid_connect_get_scopes();
  $_SESSION['openid_connect_op'] = 'login';
  $client->authorize($scopes);
}

/**
 * Form builder: Connect an external account to your existing Backdrop account.
 */
function openid_connect_connect_form($form, &$form_state, $account) {
  watchdog('openid_connect', 'Building connect form in openid_connect_connect_form for user: %uid', array('%uid' => $account->uid), WATCHDOG_DEBUG);
  form_load_include($form_state, 'inc', 'openid_connect', 'includes/openid_connect.forms');

  $form_state['account'] = $account;

  $clients = openid_connect_get_plugins(TRUE);
  watchdog('openid_connect', 'Found %count available clients', array('%count' => count($clients)), WATCHDOG_DEBUG);

  $form['help'] = array(
    '#prefix' => '<p class="description">',
    '#suffix' => '</p>',
  );

  if (empty($clients)) {
    watchdog('openid_connect', 'No external account providers available', array(), WATCHDOG_DEBUG);
    $form['help']['#markup'] = t('No external account providers are available.');
    return $form;
  }
  elseif ($GLOBALS['user']->uid == $account->uid) {
    watchdog('openid_connect', 'User viewing own account connection form', array(), WATCHDOG_DEBUG);
    $form['help']['#markup'] = t('You can connect your account with these external providers.');
  }

  $connected_accounts = openid_connect_get_connected_accounts($account);
  watchdog('openid_connect', 'Found %count connected accounts', array('%count' => count($connected_accounts)), WATCHDOG_DEBUG);

  foreach ($clients as $client) {
    $form[$client['name']] = array(
      '#type' => 'fieldset',
      '#title' => t('Provider: @title', array('@title' => $client['title'])),
    );
    $fieldset = $form[$client['name']];
    $connected = isset($connected_accounts[$client['name']]);
    $fieldset['status'] = array(
      '#type' => 'item',
      '#title' => t('Status'),
      '#markup' => t('Not connected'),
    );
    if ($connected) {
      watchdog('openid_connect', 'Account already connected to client: %client', array('%client' => $client['name']), WATCHDOG_DEBUG);
      $fieldset['status']['#markup'] = t('Connected as %sub', array(
        '%sub' => $connected_accounts[$client['name']],
      ));
      $fieldset['openid_connect_client_' . $client['name'] . '_disconnect'] = array(
        '#type' => 'submit',
        '#value' => t('Disconnect from @client_title', array('@client_title' => $client['title'])),
        '#name' => 'disconnect__' . $client['name'],
      );
    }
    else {
      watchdog('openid_connect', 'Account not connected to client: %client', array('%client' => $client['name']), WATCHDOG_DEBUG);
      $fieldset['status']['#markup'] = t('Not connected');
      $fieldset['openid_connect_client_' . $client['name'] . '_connect'] = array(
        '#type' => 'submit',
        '#value' => t('Connect with @client_title', array('@client_title' => $client['title'])),
        '#name' => 'connect__' . $client['name'],
        '#access' => $GLOBALS['user']->uid == $account->uid,
      );
    }
  }

  return $form;
}

/**
 * Submit callback for the connect account form.
 *
 * Connect the current user's Backdrop account to an external provider.
 */
function openid_connect_connect_form_submit($form, &$form_state) {
  watchdog('openid_connect', 'Processing connect form submit in openid_connect_connect_form_submit', array(), WATCHDOG_DEBUG);
  list($op, $client_name) = explode('__', $form_state['triggering_element']['#name'], 2);
  watchdog('openid_connect', 'Operation: %op for client: %client', array('%op' => $op, '%client' => $client_name), WATCHDOG_DEBUG);

  if ($op === 'disconnect') {
    watchdog('openid_connect', 'Initiating disconnect for client: %client', array('%client' => $client_name), WATCHDOG_DEBUG);
    openid_connect_disconnect_account($form_state['account'], $client_name);
    $client = openid_connect_get_client($client_name);
    backdrop_set_message(t('Account successfully disconnected from @client.', array('@client' => $client->getLabel())));
    return;
  }

  global $user;

  if ($user->uid !== $form_state['account']->uid) {
    watchdog('openid_connect', 'User %uid attempted to connect another user\'s account', array('%uid' => $user->uid), WATCHDOG_WARNING);
    backdrop_set_message(t("You cannot connect another user's account."), 'error');
    return;
  }

  watchdog('openid_connect', 'Initiating connect for client: %client', array('%client' => $client_name), WATCHDOG_DEBUG);
  openid_connect_save_destination();

  $client = openid_connect_get_client($client_name);
  $scopes = openid_connect_get_scopes();
  $_SESSION['openid_connect_op'] = $op;
  $_SESSION['openid_connect_connect_uid'] = $user->uid;
  $client->authorize($scopes);
}
