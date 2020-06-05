<?php
/**
 * @copyright   Copyright (C) 2005 - 2013 Open Source Matters, Inc. All rights reserved.
 * @license     GNU General Public License version 2 or later.
 */

defined('_JEXEC') or die;

use Firebase\JWT\JWT;

/**
 * Mylib plugin class.
 *
 * @package     Joomla.plugin
 * @subpackage  System.mylib
 */
class plgAuthenticationOpenIDConnectAuth extends JPlugin
{
    /**
     * This method should handle any authentication and report back to the subject
     * This example uses simple authentication - it checks if the password is the reverse
     * of the username (and the user exists in the database).
     *
     * @access    public
     * @param     array     $credentials    Array holding the user credentials ('username' and 'password')
     * @param     array     $options        Array of extra options
     * @param     object    $response       Authentication response object
     * @return    boolean
     * @since 1.5
     */
    function onUserAuthenticate( $credentials, $options, &$response )
    {
        $app = JFactory::getApplication();
        $params = $app->getParams('com_openidconnect');
        $kid = $params->get('kid');
        $cert = $params->get('cert');
        
        $token_endpoint = $params->get('authorization_server_endpoint') . '/token';
        $success = false;

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $token_endpoint);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); // FIXME: Testing only
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // FIXME: Testing only
        curl_setopt($ch, CURLOPT_POST, true);
        $post_params = array(
            'grant_type' => 'password',
            'client_id' => $params->get('client_id'),
            'username' => $credentials['username'],
            'password' => $credentials['password']);
        $client_secret = $params->get('client_secret');
        if ($client_secret) {
            $post_params['client_secret'] = $params->get('client_secret');
        }
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post_params));
        $result = curl_exec($ch);
        $jresult = json_decode($result);
        if (curl_errno($ch)) {
            JLog::add('curl error: ' . curl_error($ch), JLog::ERROR, 'openid-connect');
        }
        curl_close($ch);

        if (isset($jresult->access_token)) {
            $decoded_token = null;
            try { // to decode the access token
                $decoded_token = JWT::decode($jresult->access_token, [$kid => $cert], array('RS256'));
            } catch (Exception $e) {
                JLog::add('JWT Decode exception: ' . $e->getMessage() . "\nToken was: " . $jresult->access_token, JLog::ERROR, 'openid-connect');
            }
            if ($decoded_token) {
                OpenIDConnectHelper::setTokens($jresult->access_token, $jresult->refresh_token);
                
                $user = OpenIDConnectHelper::getOrCreateUserFromToken($decoded_token);
                if ($user) {
                    OpenIDConnectHelper::updateUserRoles($decoded_token);
                    $success = true;
                }
            }
        } else {
            JLog::add('unexpected response: ' . $result, JLog::ERROR, 'openid-connect');
        }

        if ($success) {
            $response->status = JAuthentication::STATUS_SUCCESS;
        } else {
            $response->status = JAuthentication::STATUS_FAILURE;
        }
    }
}
