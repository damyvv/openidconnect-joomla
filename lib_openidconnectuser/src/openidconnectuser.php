<?php
/**
 * Joomla! Content Management System
 *
 * @copyright  Copyright (C) 2005 - 2020 Open Source Matters, Inc. All rights reserved.
 * @license    GNU General Public License version 2 or later; see LICENSE.txt
 */

defined('JPATH_PLATFORM') or die;

use Joomla\CMS\Access\Access;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\CMS\Table\Table;
use Joomla\Registry\Registry;
use Joomla\Utilities\ArrayHelper;
use Joomla\CMS\User\UserWrapper;

/**
 * User class.  Handles all application interaction with a user
 *
 * @since  1.7.0
 */
class OpenIDConnectUser extends JUser
{
	public $access_token = null;

	public $refresh_token = null;

	/**
	 * Constructor activating the default information of the language
	 *
	 * @param   integer      $identifier  The primary key of the user to load (optional).
	 * @param   UserWrapper  $userHelper  The UserWrapper for the static methods. [@deprecated 4.0]
	 *
	 * @since   1.7.0
	 */
	public function __construct($access_token = null, $refresh_token = null, UserWrapper $userHelper = null)
	{
		if (null === $userHelper)
		{
			$userHelper = new UserWrapper;
		}

		$this->userHelper = $userHelper;

		// Create the user parameters object
		$this->_params = new Registry;

		// Initialise to empty user
		$this->id = 0;
		$this->sendEmail = 0;
		$this->aid = 0;
		$this->guest = 1;

		if ($access_token) {
			// TODO: Fill user with token information
			$this->load_from_token($access_token, $refresh_token);
		}
	}

	/**
	 * Method to check User object authorisation against an access control
	 * object and optionally an access extension object
	 *
	 * @param   string  $action     The name of the action to check for permission.
	 * @param   string  $assetname  The name of the asset on which to perform the action.
	 *
	 * @return  boolean  True if authorised
	 *
	 * @since   1.7.0
	 */
	public function authorise($action, $assetname = null)
	{
		// Make sure we only check for core.admin once during the run.
		if ($this->isRoot === null)
		{
			$this->isRoot = false;

			// Check for the configuration file failsafe.
			$rootUser = \JFactory::getConfig()->get('root_user');

			// The root_user variable can be a numeric user ID or a username.
			if (is_numeric($rootUser) && $this->id > 0 && $this->id == $rootUser)
			{
				$this->isRoot = true;
			}
			elseif ($this->username && $this->username == $rootUser)
			{
				$this->isRoot = true;
			}
			elseif ($this->id > 0)
			{
				// Get all groups against which the user is mapped.
				$identities = $this->getAuthorisedGroups();
				array_unshift($identities, $this->id * -1);

				if (Access::getAssetRules(1)->allow('core.admin', $identities))
				{
					$this->isRoot = true;

					return true;
				}
			}
		}

		return $this->isRoot ? true : (bool) Access::check($this->id, $action, $assetname);
	}

	/**
	 * Method to return a list of all categories that a user has permission for a given action
	 *
	 * @param   string  $component  The component from which to retrieve the categories
	 * @param   string  $action     The name of the section within the component from which to retrieve the actions.
	 *
	 * @return  array  List of categories that this group can do this action to (empty array if none). Categories must be published.
	 *
	 * @since   1.7.0
	 */
	public function getAuthorisedCategories($component, $action)
	{
		// Brute force method: get all published category rows for the component and check each one
		// TODO: Modify the way permissions are stored in the db to allow for faster implementation and better scaling
		$db = \JFactory::getDbo();

		$subQuery = $db->getQuery(true)
			->select('id,asset_id')
			->from('#__categories')
			->where('extension = ' . $db->quote($component))
			->where('published = 1');

		$query = $db->getQuery(true)
			->select('c.id AS id, a.name AS asset_name')
			->from('(' . (string) $subQuery . ') AS c')
			->join('INNER', '#__assets AS a ON c.asset_id = a.id');
		$db->setQuery($query);
		$allCategories = $db->loadObjectList('id');
		$allowedCategories = array();

		foreach ($allCategories as $category)
		{
			if ($this->authorise($action, $category->asset_name))
			{
				$allowedCategories[] = (int) $category->id;
			}
		}

		return $allowedCategories;
	}

	/**
	 * Gets an array of the authorised access levels for the user
	 *
	 * @return  array
	 *
	 * @since   1.7.0
	 */
	public function getAuthorisedViewLevels()
	{
		if ($this->_authLevels === null)
		{
			$this->_authLevels = array();
		}

		if (empty($this->_authLevels))
		{
			$this->_authLevels = Access::getAuthorisedViewLevels($this->id);
		}

		return $this->_authLevels;
	}

	/**
	 * Gets an array of the authorised user groups
	 *
	 * @return  array
	 *
	 * @since   1.7.0
	 */
	public function getAuthorisedGroups()
	{
		if ($this->_authGroups === null)
		{
			$this->_authGroups = array();
		}

		if (empty($this->_authGroups))
		{
			$this->_authGroups = Access::getGroupsByUser($this->id);
		}

		return $this->_authGroups;
	}

	/**
	 * Clears the access rights cache of this user
	 *
	 * @return  void
	 *
	 * @since   3.4.0
	 */
	public function clearAccessRights()
	{
		$this->_authLevels = null;
		$this->_authGroups = null;
		$this->isRoot = null;
		Access::clearStatics();
	}

	/**
	 * Pass through method to the table for setting the last visit date
	 *
	 * @param   integer  $timestamp  The timestamp, defaults to 'now'.
	 *
	 * @return  boolean  True on success.
	 *
	 * @since   1.7.0
	 */
	public function setLastVisit($timestamp = null)
	{
		// Create the user table object
		$table = $this->getTable();
		$table->load($this->id);

		return $table->setLastVisit($timestamp);
	}

	/**
	 * Method to get the user parameters
	 *
	 * This method used to load the user parameters from a file.
	 *
	 * @return  object   The user parameters object.
	 *
	 * @since   1.7.0
	 * @deprecated  4.0 - Instead use User::getParam()
	 */
	public function getParameters()
	{
		// @codeCoverageIgnoreStart
		\JLog::add('User::getParameters() is deprecated. User::getParam().', \JLog::WARNING, 'deprecated');

		return $this->_params;

		// @codeCoverageIgnoreEnd
	}

	/**
	 * Method to get the user parameters
	 *
	 * @param   object  $params  The user parameters object
	 *
	 * @return  void
	 *
	 * @since   1.7.0
	 */
	public function setParameters($params)
	{
		$this->_params = $params;
	}

	/**
	 * Method to bind an associative array of data to a user object
	 *
	 * @param   array  &$array  The associative array to bind to the object
	 *
	 * @return  boolean  True on success
	 *
	 * @since   1.7.0
	 */
	public function bind(&$array)
	{
		// We don't store users in the database
		return false;
	}

	/**
	 * Method to save the User object to the database
	 *
	 * @param   boolean  $updateOnly  Save the object only if not a new user
	 *                                Currently only used in the user reset password method.
	 *
	 * @return  boolean  True on success
	 *
	 * @since   1.7.0
	 * @throws  \RuntimeException
	 */
	public function save($updateOnly = false)
	{
		// We don't store users in the database
		return false;
	}

	/**
	 * Method to delete the User object from the database
	 *
	 * @return  boolean  True on success
	 *
	 * @since   1.7.0
	 */
	public function delete()
	{
		// We don't store users in the database
		return false;
	}

	/**
	 * Method to load a User object by user id number
	 *
	 * @param   mixed  $id  The user id of the user to load
	 *
	 * @return  boolean  True on success
	 *
	 * @since   1.7.0
	 */
	public function load($id)
	{
		// We don't use id's so just return true.
		return true;
	}

	/**
	 * Method to populate the user from an jwt access token.
	 * 
	 * @return bool True on success
	 */
	public function load_from_token($access_token, $refresh_token)
	{
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


		$this->access_token = $access_token;
		$this->refresh_token = $refresh_token;
		
		$user = null;
		try {
			$user = Firebase\JWT\JWT::decode($access_token, [$kid => $cert], array('RS256'));
		} catch (Exception $e) {
			JLog::add('JWT Decode exception: ' . $e->getMessage() . "\nToken was: " . $jresult->access_token, JLog::ERROR, 'openid-connect');
			return false;
		}

		$this->name = $user->name;
		$this->username = $user->preferred_username;
		$this->email = $user->email;
		$this->guest = 0;

		// TODO: Set groups
		return true;
	}

	/**
	 * Method to allow serialize the object with minimal properties.
	 *
	 * @return  array  The names of the properties to include in serialization.
	 *
	 * @since   3.6.0
	 */
	public function __sleep()
	{
		return array('access_token', 'refresh_token');
	}

	/**
	 * Method to recover the full object on unserialize.
	 *
	 * @return  void
	 *
	 * @since   3.6.0
	 */
	public function __wakeup()
	{
		// Initialise some variables
		$this->userHelper = new UserWrapper;
		$this->_params    = new Registry;

		// Load the user if it exists
		if (!empty($this->access_token) && 
			!empty($this->refresh_token) && 
			$this->load_from_token($this->access_token, $this->refresh_token))
		{
			// Push user into cached instances.
			// self::$instances[$this->id] = $this;
		}
		else
		{
			// Initialise
			$this->id = 0;
			$this->sendEmail = 0;
			$this->aid = 0;
			$this->guest = 1;
		}
	}
}
