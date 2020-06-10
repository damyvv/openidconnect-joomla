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
class plgSystemOpenIDConnect extends JPlugin
{
    /**
     * Method to register custom library.
     *
     * return  void
     */
    public function onAfterInitialise()
    {
        // Load dependencies for the applications/plugins
        JLoader::discover('Firebase\\JWT\\', JPATH_LIBRARIES . '/openidconnectjwt/php-jwt/src');
        JLoader::discover('', JPATH_LIBRARIES . '/openidconnect/src');
        JLoader::import('openidconnectuser', JPATH_LIBRARIES . '/openidconnectuser/src');

        // Token refresh
        $decoded_token = OpenIDConnectHelper::getAccessToken();
        if (isset($decoded_token->exp)) {
            $expiry = $decoded_token->exp;
            $now = time();
            $app = JFactory::getApplication();
            if ($expiry - $now <= 0) {
                // Token expired, so we want to refresh
                $params = $app->getParams('com_openidconnect');
                $token_endpoint = $params->get('authorization_server_endpoint') . '/token';
                $kid = $params->get('kid');
                $cert = $params->get('cert');

                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $token_endpoint);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                if ($params->get('disable_ssl_check') == 1) {
                    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
                    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
                }
                curl_setopt($ch, CURLOPT_POST, true);
                $post_params = array(
                    'grant_type' => 'refresh_token',
                    'client_id' => $params->get('client_id'),
                    'refresh_token' => OpenIDConnectHelper::getRefreshToken());
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
                        $decoded_token = Firebase\JWT\JWT::decode($jresult->access_token, [$kid => $cert], array('RS256'));
                        $expiry = $decoded_token->exp;
                        OpenIDConnectHelper::setTokens($decoded_token, $jresult->refresh_token);
                        OpenIDConnectHelper::updateUserRoles($decoded_token);
                    } catch (Exception $e) {
                        JLog::add('JWT Decode exception: ' . $e->getMessage() . "\nToken was: " . $jresult->access_token, JLog::ERROR, 'openid-connect');
                    }
                } else {
                    JLog::add('unexpected response: ' . $result, JLog::ERROR, 'openid-connect');
                }
            }
            if ($expiry - $now <= 0) {
                // Token still expired, so logout. Session expired.
                $app->logout();
                JFactory::getApplication()->enqueueMessage('Your session expired. Please log in again.', 'error');
            }
        }
    }
}
