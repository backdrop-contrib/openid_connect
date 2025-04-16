<?php

/**
 * Generic OpenID Connect client.
 */
class OpenIDConnectClientGeneric extends OpenIDConnectClientBase {

  /**
   * {@inheritdoc}
   */
  public function getLabel() {
    return t('Generic');
  }

  /**
   * {@inheritdoc}
   */
  public function getEndpoints() {
    $endpoints = array(
      'authorization' => $this->getSetting('authorization_endpoint'),
      'token' => $this->getSetting('token_endpoint'),
      'userinfo' => $this->getSetting('userinfo_endpoint'),
      'redirect' => 'openid-connect/generic',
    );

    return $endpoints;
  }

  /**
   * {@inheritdoc}
   */
  public function settingsForm() {
    $form = parent::settingsForm();

    $form['authorization_endpoint'] = array(
      '#title' => t('Authorization endpoint'),
      '#type' => 'textfield',
      '#default_value' => $this->getSetting('authorization_endpoint'),
      '#required' => TRUE,
    );
    $form['token_endpoint'] = array(
      '#title' => t('Token endpoint'),
      '#type' => 'textfield',
      '#default_value' => $this->getSetting('token_endpoint'),
      '#required' => TRUE,
    );
    $form['userinfo_endpoint'] = array(
      '#title' => t('UserInfo endpoint'),
      '#type' => 'textfield',
      '#default_value' => $this->getSetting('userinfo_endpoint'),
      '#required' => TRUE,
    );

    return $form;
  }
} 