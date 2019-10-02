<?php
namespace JwtToken;
require_once('vendor/autoload.php');
use Zend\Config\Config;
use Zend\Config\Factory;
use Zend\Http\PhpEnvironment\Request;
use Firebase\JWT\JWT;
date_default_timezone_set("UTC"); 

class JwtToken
{

    /**
     * Private Key
     * @var type string
     */
    private $privatetKey;

   /**
     * Client Id
     * @var type string
     */
    private $clientId;

    /**
     * Client Secret
     * @var type string
     */
    private $clientSecret;

    /**
     * Box User Id
     * @var type string
     */
    private $boxUserId;
   
   /**
     * Box EnterPrise Id
     * @var type string
     */
    private $boxEnterPriseId;

    /**
     * Box Sub Type
     * @var type string
     */
    private $boxSubType;

    /**
     * Box Key Id
     * @var type string
     */
    private $boxKeyId;

    /**
     * Api Token Url
     * @var type string
     */
    private $apiTokenUrl;

     /**
     * passphrase
     * @var type string
     */
    private $passPhrase;
    /**
     * Create a configured instance to use the Box Token.
     *
    */
    public function __construct($data=array())
    {
        if (empty($data['private_key'])) {
            throw new \RuntimeException('No private key provided');
        }
        else
        $this->privatetKey = $data['private_key'];

        if (empty($data['client_id'])) {
            throw new \RuntimeException('No client id provided');
        }
        else
        $this->clientId = $data['client_id'];

        $this->clientSecret = $data['client_secret'];
        

        if (empty($data['enter_prise_id'])) {
            throw new \RuntimeException('No enterprise id provided');
        }
        else
        $this->boxEnterPriseId = $data['enter_prise_id'];

       if (empty($data['user_id'])) {
            throw new \RuntimeException('No user id provided');
        }
        else
        $this->boxUserId    = $data['user_id'];

        if (empty($data['box_sub_type'])) {
            throw new \RuntimeException('No box syb type provided');
        }
        else
        $this->boxSubType = $data['box_sub_type'];

        if (empty($data['key_id'])) {
            throw new \RuntimeException('No box sub type provided');
        }
        else
        $this->boxKeyId = $data['key_id'];

       if (empty($data['api_token_url'])) {
            throw new \RuntimeException('No key id provided');
        }
        else
        $this->apiTokenUrl = $data['api_token_url'];

       if(empty($data['passphrase'])) {
            throw new \RuntimeException('No passphrase provided');
        }
        else
        $this->passPhrase = $data['passphrase'];
  
    }

    public function create_jwt_token()
    {
       date_default_timezone_set("UTC"); 
       $tokenId    = base64_encode(random_bytes(32));
       $issuedAt   = time();
       $notBefore  = $issuedAt + 10;             //Adding 10 seconds
       $expire     = $issuedAt + 60;            // Adding 60 seconds   
       $data = [
                  'iss'  => $this->clientId,       // client id
                  'sub'  => $this->boxUserId ,       // Json Token Id: an unique identifier for the token
                  'box_sub_type'=> $this->boxSubType, 
                  'aud'  => $this->apiTokenUrl, 
                  'jti'  => $tokenId,           
                  'exp'  => $expire ,
                  //'iat'  => $issuedAt,
                  //'nbf'  => $notBefore,
                 ]; 
      $privateKey = openssl_pkey_get_private($this->privatetKey, $this->passPhrase);
      $jwt_result = array();
      try 
      {

          $jwt = JWT::encode(
              $data,      //Data to be encoded in the JWT
              $privateKey, // The signing key
              'RS256' ,   // Algorithm used to sign the token, 
              $this->boxKeyId
              );
           $jwt_result['jwt'] =  $jwt;
           $jwt_result['response'] = "Success";
           $jwt_result['iat'] = date("Y-m-d H:i:s", $issuedAt);
           $jwt_result['nbf'] = date("Y-m-d H:i:s",  $notBefore);
           $jwt_result['exp'] = date("Y-m-d H:i:s", $expire);
           
      } 
      catch (Exception $e) {
         $jwt_result['jwt'] =  '';
         $jwt_result['response'] = 'Caught exception: '.$e->getMessage();
         // return 'Caught exception: '.$e->getMessage();
      }
      return json_encode($jwt_result);

    }
  
}