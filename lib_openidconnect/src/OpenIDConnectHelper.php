<?php
/**
 * @copyright   2020 Coval B.V.
 * @license     GNU General Public License version 3 or later; see LICENSE
 */

class OpenIDConnectHelper
{
    private const OIDC_TABLE_NAME = 'openidconnect_users';

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
}
