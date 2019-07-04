<?php

/**
 * Functions related to GSB Box admin 
 */
/**
 * Admin configuration form for Box
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
     $form['box']['box_case_folder_id'] = array(
      '#title'=>'Box Case Folder Id',
      '#type' => 'textfield',
      '#default_value' =>variable_get('box_case_folder_id'),
      '#required' => TRUE,
    );
    $form['box']['box_workingpaper_folder_id'] = array(
      '#title'=>'Box Working Paper Folder Id',
      '#type' => 'textfield',
      '#default_value' =>variable_get('box_workingpaper_folder_id'),
      '#required' => TRUE,
    );
    $form['box']['box_syllabi_folder_id'] = array(
      '#title'=>'Box Syllabi Folder Id',
      '#type' => 'textfield',
      '#default_value' =>variable_get('box_syllabi_folder_id'),
      '#required' => TRUE,
    );
   /* $form['box']['box_private_key'] = array(
      '#title'=>'Box Api Private Key',
      '#type' => 'textarea',
      '#default_value' =>variable_get('box_private_key'),
      '#required' => TRUE,
    );*/
     $form['box']['box_cron_to_email'] = array(
      '#title'=>'Email(To Address)',
      '#type' => 'textfield',
      '#default_value' =>variable_get('box_cron_to_email'),
      '#description' => t('Use comma separated values. When cron job execute mail sends out to the email address.')
    );
    $form['box']['box_cron_email_subject'] = array(
      '#title'=>'Email Subject',
      '#type' => 'textfield',
      '#default_value' =>variable_get('box_cron_email_subject')
    );
    return system_settings_form($form, $form_state);
}
