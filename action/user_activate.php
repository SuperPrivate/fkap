<?php

	include_once('../lib/user_validate.php');
	$user_validate = new User_Validate();

	/*
		This script gets included into the email that is sent to the user so they can validate their newly created account.
		The URL will look something like this:
		http://domzzz.com/action/user_activate.php?validation_key=520619ae6b6bc5944aac9c601a16df7bd75eebcea56403ebe7fe64c9179c587c
	 */

	/*
		The validation key comes via $_GET.  If $_GET['validation_key'] is not initialized
		or if it is initialized but empty, return from this script.
	 */
	if( ! isset($_GET['validation_key']))      {
		echo "I am the Gatekeeper.  Are you the Keymaster?";
		return;
	}	else if (empty($_GET['validation_key']))     {
			echo "I am the Gatekeeper.  Are you the Keymaster?";
			return;
	}
	
	/*
		If user_validate::account_activation() returns a true your account is now activated.
		NOTE:  When users attempt to login, be sure to always test in addition to username and
		password whether acl_login.activated = TRUE.
	 */
	if($user_validate::account_activation($_GET['validation_key']))	{
		echo "Your account has been activated. <br/>";
	}	else 	{
		echo "No account was activated. <br/>";
	}


?>
