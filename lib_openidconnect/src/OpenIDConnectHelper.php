<?php
/**
 * @copyright   2020 Coval B.V.
 * @license     GNU General Public License version 3 or later; see LICENSE
 */

class OpenIDConnectHelper
{
    private const OIDC_TABLE_NAME = '#__openidconnect_users';

    public static function getOrCreateUserFromToken($decoded_token) {
        $user = self::getUserFromToken($decoded_token);
        if ($user) {
            return $user;
        }
        $user = self::createUserFromToken($decoded_token);
        return $user;
    }

    public static function createUserFromToken($decoded_token) {
        $user = new JUser;
        $user_data = array(
            "username" => $decoded_token->preferred_username,
            "name" => $decoded_token->name,
            "email" => $decoded_token->email,
            "block" => 0,
            "activated" => 1,
            "is_guest" => 0
        );
        if (!$user->bind($user_data)) {
            JLog::add('Could not bind user data. Error: ' . $user->getError(), JLog::ERROR, 'openid-connect');
            $user = null;
        } else {
            if (!$user->save()) {
                JLog::add('Failed to save user. Error: ' . $user->getError(), JLog::ERROR, 'openid-connect');
                $user = null;
            } else {
                $db = JFactory::getDbo();
                $query = $db->getQuery(true);
                $query->insert(self::OIDC_TABLE_NAME)
                        ->set('user_id = ' . $user->id)
                        ->set('oidc_uuid = ' . $db->quote($decoded_token->sub));
                $db->setQuery($query);
                $db->query();
            }
        }
        return $user;
    }

    public static function updateUserRoles($decoded_token) {
        $app = JFactory::getApplication();
        $params = $app->getParams('com_openidconnect');
        $client_id = $params->get('client_id');
        $user = self::getUserFromToken($decoded_token);

        $db = JFactory::getDbo();
        $db->setQuery('SELECT id FROM #__usergroups' . ' WHERE LOWER(title) LIKE \'guest\'');
        $groups = array($db->loadObject()->id);
        
        if (isset($decoded_token->resource_access->$client_id->roles)) {
            $roles = $decoded_token->resource_access->$client_id->roles;
            $groups = array();
            foreach ($roles as $role) {
                $db->setQuery('SELECT id FROM #__usergroups' . ' WHERE LOWER(title) LIKE LOWER(' . $db->quote($role) . ')');
                $group_id = $db->loadObject()->id;
                if ($group_id) {
                    array_push($groups, $group_id);
                }
            }
        }
        JUserHelper::setUserGroups($user->id, $groups);
    }

    public static function getUserFromToken($decoded_token) {
        $user_table = JUser::getTable()->getTableName();
        $db = JFactory::getDbo();
        $query = $db->getQuery(true);
        $query->select($user_table . '.id' . ',' . self::OIDC_TABLE_NAME . '.oidc_uuid');
        $query->from($user_table);
        $query->join('INNER', self::OIDC_TABLE_NAME . ' ON ' . self::OIDC_TABLE_NAME . '.user_id' . 
            '=' . $user_table . '.id');
        $query->where(self::OIDC_TABLE_NAME . '.oidc_uuid' . ' LIKE ' . $db->quote($decoded_token->sub));

        $db->setQuery($query);
        
        $query_result = $db->loadObject();
        if (!$query_result) {
            return null;
        }
        $user_id = $query_result->id;
        return JFactory::getUser($user_id);
    }

    public static function setTokens($access_token, $refresh_token) {
        JFactory::getSession()->set('oidc_access_token', json_encode($access_token));
        JFactory::getSession()->set('oidc_refresh_token', $refresh_token);
    }

    public static function getAccessToken() {
        return json_decode(JFactory::getSession()->get('oidc_access_token'));
    }

    public static function getRefreshToken() {
        return JFactory::getSession()->get('oidc_refresh_token');
    }
}
