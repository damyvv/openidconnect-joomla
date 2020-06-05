<?php
/**
 * @copyright   Copyright (C) 2005 - 2013 Open Source Matters, Inc. All rights reserved.
 * @license     GNU General Public License version 2 or later.
 */

defined('_JEXEC') or die;

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
        $token_endpoint = $params->get('authorization_server_endpoint') . '/token';

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

        var_dump($result);
        die();
    }
}
