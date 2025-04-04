<?php

/**
 * @file
 * Administrative UI and functions for the OpenID Connect module.
 */

/**
 * Form builder: Main administrative form.
 */
function openid_connect_admin_form($form, &$form_state) {
  $config = config('openid_connect.settings');
  $client_plugins = openid_connect_get_plugins();
  $options = array();
  foreach ($client_plugins as $client_plugin) {
    $options[$client_plugin['name']] = $client_plugin['title'];
  }

  $form['#tree'] = TRUE;
  $form['openid_connect_clients_enabled'] = array(
    '#title' => t('Enabled OpenID Connect clients'),
    '#description' => t('Choose enabled OpenID Connect clients.'),
    '#type' => 'checkboxes',
    '#options' => $options,
    '#default_value' => $config->get('openid_connect_clients_enabled'),
  );
  foreach ($client_plugins as $client_plugin) {
    $client = openid_connect_get_client($client_plugin['name']);

    $element = 'openid_connect_clients_enabled[' . $client_plugin['name'] . ']';
    $form['clients'][$client_plugin['name']] = array(
      '#title' => $client_plugin['title'],
      '#type' => 'fieldset',
      '#states' => array(
        'visible' => array(
          ':input[name="' . $element . '"]' => array('checked' => TRUE),
        ),
      ),
    );
    $form['clients'][$client_plugin['name']] += $client->settingsForm();
  }

  $form['openid_connect_always_save_userinfo'] = array(
    '#title' => t('Save user claims on every login'),
    '#description' => t('If disabled, user claims will only be saved when the account is first created.'),
    '#type' => 'checkbox',
    '#default_value' => $config->get('openid_connect_always_save_userinfo'),
  );

  if (config_get('system.core', 'user_pictures')) {
    $form['openid_connect_user_pictures'] = array(
      '#title' => t('Fetch user profile picture from login provider'),
      '#description' => t('Whether the user profile picture from the login provider should be fetched and saved locally.'),
      '#type' => 'checkbox',
      '#default_value' => $config->get('openid_connect_user_pictures'),
    );
  }

  $form['openid_connect_connect_existing_users'] = array(
    '#title' => t('Automatically connect existing users'),
    '#description' => t('If disabled, authentication will fail for existing email addresses. Enabling this option will allow logging into existing accounts, which may be a security risk if the identity provider does not have in place adequate procedures to guarantee that users really own the e-mail addresses used.'),
    '#type' => 'checkbox',
    // This is FALSE to reflect the default behaviour of historical installs.
    // Given the install base there is a high likelyhood that existing sites
    // are using the module as the single account creation process.
    '#default_value' => $config->get('openid_connect_connect_existing_users'),
  );

  $form['userinfo_mapping'] = array(
    '#title' => t('User claims mapping'),
    '#type' => 'fieldset',
  );

  $user_entity_wrapper = entity_metadata_wrapper('user');
  $claims = openid_connect_claims_options();
  $properties = $user_entity_wrapper->getPropertyInfo();
  $properties_skip = _openid_connect_user_properties_to_skip();
  foreach ($properties as $property_name => $property) {
    if (isset($properties_skip[$property_name])) {
      continue;
    }
    // Always map the timezone.
    $default_value = 0;
    if ($property_name == 'timezone') {
      $default_value = 'zoneinfo';
    }

    $form['userinfo_mapping']['openid_connect_userinfo_mapping_property_' . $property_name] = array(
      '#type' => 'select',
      '#title' => $property['label'],
      '#description' => $property['description'],
      '#options' => $claims,
      '#empty_value' => 0,
      '#empty_option' => t('- No mapping -'),
      '#default_value' => $config->get('openid_connect_userinfo_mapping_property_' . $property_name),
    );
  }

  $form['actions']['#type'] = 'actions';
  $form['actions']['submit'] = array(
    '#type' => 'submit',
    '#value' => t('Save configuration'),
  );

  return $form;
}

/**
 * Validation handler for openid_connect_admin_form.
 */
function openid_connect_admin_form_validate($form, &$form_state) {
  $enabled_clients = $form_state['values']['openid_connect_clients_enabled'];
  $enabled_clients = array_filter($enabled_clients);
  foreach ($enabled_clients as $client_name) {
    // Give the client a chance to validate the submitted values.
    $client = openid_connect_get_client($client_name);
    $fake_form = $form['clients'][$client_name];
    $fake_form_state = array('values' => $form_state['values']['clients'][$client_name]);
    $error_element_base = 'clients][' . $client_name . '][';
    $client->settingsFormValidate($fake_form, $fake_form_state, $error_element_base);
  }
}

/**
 * Submit handler for openid_connect_admin_form.
 */
function openid_connect_admin_form_submit($form, &$form_state) {
  $config = config('openid_connect.settings');
  
  $enabled_clients = $form_state['values']['openid_connect_clients_enabled'];
  $enabled_clients = array_filter($enabled_clients);
  $config->set('openid_connect_clients_enabled', $enabled_clients);

  foreach ($enabled_clients as $client_name) {
    // Give the client a chance to modify the submitted values.
    $client = openid_connect_get_client($client_name);
    $fake_form = $form['clients'][$client_name];
    $fake_form_state = array('values' => $form_state['values']['clients'][$client_name]);
    $client->settingsFormSubmit($fake_form, $fake_form_state);

    // Save the settings.
    $config->set('openid_connect_client_' . $client_name, $fake_form_state['values']);
  }

  $claims = array();
  foreach ($form_state['values']['userinfo_mapping'] as $variable => $claim) {
    if (!empty($claim)) {
      $claims[] = $claim;
      // TODO This variable was probably removed in Backdrop without replacement.
      $config->set($variable, $claim); 
    }
    else {
      // TODO This variable was probably removed in Backdrop without replacement.
      $config->clear($variable);
    }
  }
  $config->set('openid_connect_userinfo_mapping_claims', $claims);

  $default_enabled = array(
    'openid_connect_always_save_userinfo',
    'openid_connect_user_pictures',
    'openid_connect_connect_existing_users',
  );
  foreach ($default_enabled as $variable) {
    if (isset($form_state['values'][$variable])) {
      // TODO This variable was probably removed in Backdrop without replacement.
      $config->set($variable, $form_state['values'][$variable]);
    }
  }
  
  $config->save();
}

