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
                // Load the user and set as active
                $user = new OpenIDConnectUser();
                if ($user->load_from_token($jresult->access_token, $jresult->refresh_token)) {
                    JFactory::getSession()->set('user', $user);
                    $success = true;
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
