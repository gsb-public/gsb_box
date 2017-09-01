<?php

/**
 * Functions related to dvent admin 
 */
/**
 * Admin configuration form for dvent
 */
function gsb_box_settings_form($form, $form_state) {

    $form['box'] = array(
      '#title'=>'Box Api Configuration',
      '#type' => 'fieldset',
     );
    $form['box']['box_client_id'] = array(
      '#title'=>'Box Client ID',
      '#type' => 'textfield',
      '#default_value' =>variable_get('box_client_id'),
      '#required' => TRUE,
    );
    $form['box']['box_client_secret'] = array(
      '#title'=>'Box Client Secret',
      '#type' => 'textfield',
      '#default_value' =>variable_get('box_client_secret'),
      '#required' => TRUE,
    );
    $form['box']['box_enterprise_id'] = array(
      '#title'=>'Box Enterprise Id',
      '#type' => 'textfield',
      '#default_value' =>variable_get('box_enterprise_id'),
      '#required' => TRUE,
    );
    $form['box']['box_user_id'] = array(
      '#title'=>'Box User Id',
      '#type' => 'textfield',
      '#default_value' =>variable_get('box_user_id'),
      '#required' => TRUE,
    );
     $form['box']['box_sub_type'] = array(
      '#title'=>'Box Sub Type',
      '#type' => 'textfield',
      '#default_value' =>variable_get('box_sub_type'),
      '#required' => TRUE,
    );
     $form['box']['box_key_id'] = array(
      '#title'=>'Box Key Id',
      '#type' => 'textfield',
      '#default_value' =>variable_get('box_key_id'),
      '#required' => TRUE,
    );
     $form['box']['box_api_token_url'] = array(
      '#title'=>'Box Api Token URL',
      '#type' => 'textfield',
      '#default_value' =>variable_get('box_api_token_url'),
      '#required' => TRUE,
    );
    $form['box']['box_passphrase'] = array(
      '#title'=>'Box Passphrase',
      '#type' => 'textfield',
      '#default_value' =>variable_get('box_passphrase'),
      '#required' => TRUE,
    );
     $form['box']['box_grant_type'] = array(
      '#title'=>'Box Grant Type',
      '#type' => 'textfield',
      '#default_value' =>variable_get('box_grant_type'),
      '#required' => TRUE,
    );
    $form['box']['box_access_token_url'] = array(
      '#title'=>'Box Access Token URL',
      '#type' => 'textfield',
      '#default_value' =>variable_get('box_access_token_url'),
      '#required' => TRUE,
    );
   /*$form['box']['box_private_key'] = array(
      '#title'=>'Box Api Private Key',
      '#type' => 'textarea',
      '#default_value' =>variable_get('box_private_key'),
      '#required' => TRUE,
    );*/
    return system_settings_form($form, $form_state);
}
