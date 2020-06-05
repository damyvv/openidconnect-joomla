<?php
/**
 * @package     Joomla.Site
 * @subpackage  com_openidconnect
 *
 * @copyright   2020 Coval B.V.
 * @license     GNU General Public License version 3 or later; see LICENSE
 */

// No direct access to this file
defined('_JEXEC') or die('Restricted access');

use Joomla\CMS\Factory;
use Firebase\JWT\JWT;

/**
 * OpenID Connect Component Controller
 *
 * @since  0.0.1
 */
class OpenIDConnectController extends JControllerLegacy
{
    private $component_uri = 'index.php?option=com_openidconnect';

    function display($cacheable = false, $urlparams = array()) {
        $app = JFactory::getApplication();
        $params = $app->getParams('com_openidconnect');

        $kid = $params->get('kid');
        $cert = $params->get('cert');

        $base_url = JUri::base();
        $code = Factory::getApplication()->input->get('code', '');
        if ($code) {
            $success = false;
            $token_endpoint = $params->get('authorization_server_endpoint') . '/token';
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $token_endpoint);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); // FIXME: Testing only
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // FIXME: Testing only
            curl_setopt($ch, CURLOPT_POST, true);
            $post_params = array(
                'grant_type' => 'authorization_code',
                'code' => $code,
                'client_id' => $params->get('client_id'),
                'redirect_uri' => '/' . $this->component_uri);
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
                        JFactory::getSession()->set('user', $user);
                        OpenIDConnectHelper::updateUserRoles($decoded_token);
                        $success = true;
                    }
                }
            } else {
                JLog::add('unexpected response: ' . $result, JLog::ERROR, 'openid-connect');
            }

            if (!$success) {
                Factory::getApplication()->enqueueMessage('Oops! Something went wrong while logging you in. Please try again later. Contact the system administrator if the problem persists.', 'error');
                $this->setRedirect($base_url);
            } else {
                $this->setRedirect($base_url . $params->get('after_login_redirect_uri'));
            }
        }
    }

    function login() {
        $app = JFactory::getApplication();
        $params = $app->getParams('com_openidconnect');
        $base_url = JUri::base();
        $client_id = 'joomla';
        $response_type = 'code';
        $this->setRedirect($params->get('authorization_server_endpoint') . '/auth' . 
            '?client_id=' . $client_id .
            '&response_type=' . $response_type .
            '&redirect_uri=' . '/' . $this->component_uri);
        return;
    }

    function logout() {
        $app = JFactory::getApplication();
        $params = $app->getParams('com_openidconnect');
        Factory::getApplication()->logout();
        $base_url = JUri::base();
        $this->setRedirect($params->get('authorization_server_endpoint') . '/logout' .
            '?redirect_uri=' . $base_url);
        return;
    }
}
