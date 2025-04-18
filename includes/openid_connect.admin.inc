/**
 * Form builder: OpenID Connect admin form.
 */
function openid_connect_admin_form($form, &$form_state) {
  $config = config('openid_connect.settings');

  if (config_get('system.core', 'user_pictures')) {
    $form['openid_connect_user_pictures'] = array(
      '#title' => t('Fetch user profile picture from login provider'),
      '#description' => t('Whether the user profile picture from the login provider should be fetched and saved locally.'),
      '#type' => 'checkbox',
      '#default_value' => $config->get('user_pictures'),
    );
  }

  $form['always_save_userinfo'] = array(
    '#title' => t('Save user claims on every login'),
    '#description' => t('If disabled, user claims will only be saved when the account is first created.'),
    '#type' => 'checkbox',
    '#default_value' => $config->get('always_save_userinfo'),
  );

  $form['connect_existing_users'] = array(
    '#title' => t('Automatically connect existing users'),
    '#description' => t('If disabled, authentication will fail for existing email addresses. Enabling this option will allow logging into existing accounts, which may be a security risk if the identity provider does not have in place adequate procedures to guarantee that users really own the e-mail addresses used.'),
    '#type' => 'checkbox',
    '#default_value' => $config->get('connect_existing_users'),
  );

  $form['userinfo_mapping'] = array(
    '#title' => t('User claims mapping'),
    '#type' => 'fieldset',
  );

  $properties = _openid_connect_user_properties_to_skip();
  $claims = openid_connect_claims_options();
  
  // Get user entity fields
  $fields = field_info_instances('user', 'user');
  foreach ($fields as $field_name => $field) {
    if (isset($properties[$field_name])) {
      continue;
    }
    
    $form['userinfo_mapping']['openid_connect_userinfo_mapping_property_' . $field_name] = array(
      '#type' => 'select',
      '#title' => $field['label'],
      '#description' => isset($field['description']) ? $field['description'] : '',
      '#options' => $claims,
      '#empty_value' => 0,
      '#empty_option' => t('- No mapping -'),
      '#default_value' => $config->get('userinfo_mapping_property_' . $field_name),
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
 * Submit handler for openid_connect_admin_form.
 */
function openid_connect_admin_form_submit($form, &$form_state) {
  $config = config('openid_connect.settings');
  
  if (isset($form_state['values']['openid_connect_user_pictures'])) {
    $config->set('user_pictures', $form_state['values']['openid_connect_user_pictures']);
  }
  
  $config->set('always_save_userinfo', $form_state['values']['always_save_userinfo']);
  $config->set('connect_existing_users', $form_state['values']['connect_existing_users']);

  $claims = array();
  foreach ($form_state['values'] as $key => $value) {
    if (strpos($key, 'openid_connect_userinfo_mapping_property_') === 0 && !empty($value)) {
      $field_name = substr($key, strlen('openid_connect_userinfo_mapping_property_'));
      $config->set('userinfo_mapping_property_' . $field_name, $value);
      $claims[] = $value;
    }
  }
  
  if (!empty($claims)) {
    $config->set('userinfo_mapping_claims', $claims);
  }
  else {
    $config->clear('userinfo_mapping_claims');
  }

  $config->save();
  backdrop_set_message(t('The configuration options have been saved.'));
}

/**
 * Returns user properties that can be skipped when mapping user profile info.
 */
function _openid_connect_user_properties_to_skip() {
  $properties_to_skip = array(
    'name', 'mail', 'uid', 'url', 'edit_url', 'last_access', 'last_login', 'created', 'roles', 'status', 'theme',
  );
  return backdrop_map_assoc($properties_to_skip);
} 
