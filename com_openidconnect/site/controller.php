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

/**
 * OpenID Connect Component Controller
 *
 * @since  0.0.1
 */
class OpenIDConnectController extends JControllerLegacy
{
    private $redirect_uri = 'index.php?option=com_openidconnect';

    function display($cacheable = false, $urlparams = array()) {
        $kid = 'OZ08_xCclcekK77XNXhLllMWBF0qOjobOaC6w_6kZvI';
        $cert = '
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2ilEg9wmdi4RJFKT7ynV
NI6VjGgc3A1XJ6lFtZ7/E3qbymOM8aU1rbprrg5PzYUvRS15aNafrO5N5xnQT8jA
KpZe+/7rHlFFj2KA1wvlmsx/dfXhgw5kjf1jnqZxa8T4A3uJ/UPx/awQewXw0YgR
MrvL6kvhwwfucWw6ffG6NdZM5RDUxbFZewEsVSisY+5jNy4BnodayG/AgguzrnR6
g3M38/plhL7yj8Wb4HjikP8zbuXft82IM77F8wK940zqsyO/LwxOY2jDf9hCHIZc
Vxaee2mhIv5ptEjf21IiX/MMwPGyRVjdi8G1Pl3m0V6ooQQmC5dulwBWvhD6CrIe
uwIDAQAB
-----END PUBLIC KEY-----';

        $base_url = JUri::base();
        $code = Factory::getApplication()->input->get('code', '');
        if ($code) {
            $success = false;
            $token_endpoint = 'https://192.168.56.4/auth/realms/acvz/protocol/openid-connect/token';
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $token_endpoint);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false); // FIXME: Testing only
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // FIXME: Testing only
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query(array(
                'grant_type' => 'authorization_code',
                'code' => $code,
                'client_id' => 'joomla',
                'client_secret' => 'b776c724-2274-40a0-9b97-ecfb612a7a3b',
                'redirect_uri' => $base_url . $this->redirect_uri
            )));
            $result = curl_exec($ch);
            $jresult = json_decode($result);
            if (curl_errno($ch)) {
                JLog::add('curl error: ' . curl_error($ch), JLog::ERROR, 'openid-connect');
            }
            curl_close($ch);
            if (isset($jresult->access_token)) {
                JLoader::discover('Firebase\\JWT\\', JPATH_LIBRARIES . '/openidconnectjwt/php-jwt/src');
                try {
                    $user = Firebase\JWT\JWT::decode($jresult->access_token, [$kid => $cert], array('RS256'));
                    var_dump($user);
                    die();
                } catch (Exception $e) {
                    JLog::add('JWT Decode exception: ' . $e->getMessage() . "\nToken was: " . $jresult->access_token, JLog::ERROR, 'openid-connect');
                }
            } else {
                JLog::add('unexpected response: ' . $result, JLog::ERROR, 'openid-connect');
            }

            if (!$success) {
                Factory::getApplication()->enqueueMessage('Oops! Something went wrong while logging you in. Please try again later. Contact the system administrator if the problem persists.', 'error');
            }

            $this->setRedirect($base_url);
        }
    }

    function login() {
        $base_url = JUri::base();
        $client_id = 'joomla';
        $response_type = 'code';
        $this->setRedirect('https://192.168.56.4/auth/realms/acvz/protocol/openid-connect/auth' . 
            '?client_id=' . $client_id .
            '&response_type=' . $response_type .
            '&redirect_uri=' . $base_url . $this->redirect_uri);
        return;
    }
}
