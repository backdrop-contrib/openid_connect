<?php

/**
 * @file
 * An example implementation of OpenID Connect client.
 */

/**
 * Custom OpenID Connect client.
 */
class OpenIDConnectClientExample extends OpenIDConnectClientBase {

  /**
   * {@inheritdoc}
   */
  public function settingsForm() {
    $form = parent::settingsForm();
    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function getEndpoints() {
    return array(
      'authorization' => 'https://example.com/oauth2/authorize',
      'token' => 'https://example.com/oauth2/token',
      'userinfo' => 'https://example.com/oauth2/UserInfo',
    );
  }

}
