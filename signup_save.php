<?php

include_once('lib/user_create.php');
$user_login = new User_Create();

$login_array = array();

	foreach ($_POST as $key => $value) {
		switch ($key)	{
			case 'email':
				$login_array['email'] = $_POST['email'];
				break;
			case 'password':
				$login_array['password'] = $_POST['password'];
				break;
			default:
			break;
		}
	}


/*
	If the email the user wants to use is not already used as a login then continue on.
 */
if( ! $user_create::test_exist_email($pw_array['email']))	{
	/*
		1.) Encrypt the users clear text password and generate the salt.
		After running $encrypt_password::gen_pass($password) through the foreach, $pw_array looks like this:
		Array ( [email] => davet6020@gmail.com 
				[pwcleartext] => thepasswd 
				[salt] => $2a$10$SgsJC9ThGIWiEtJoD8lyoh 
				[pwencrypted] => $2a$10$SgsJC9ThGIWiEtJoD8lyoekkzjROpY9caYYLzNtvRSsSh77O7CwjW )
	 */
	foreach($encrypt_password::gen_pass($password) as $key => $value)	{
		$pw_array[$key] = $value;
	}

	/*
		2.) Generate the validation_key
		After running $pw_array['validation_key'] = $user_validate::gen_validation_key($pw_array['pwencrypted'])
		$pw_array looks like this:
		Array ( [email] => davet6020@gmail.com 
				[pwcleartext] => thepasswd 
				[salt] => $2a$10$SgsJC9ThGIWiEtJoD8lyoh 
				[pwencrypted] => $2a$10$SgsJC9ThGIWiEtJoD8lyoekkzjROpY9caYYLzNtvRSsSh77O7CwjW 
				[validation_key] => d64e0fd5d714006e33b5f8c523b9d66a8f36aa47ea3238c119350c35bc6bb867 )
	 */
	
	$pw_array['validation_key'] = $user_validate::gen_validation_key($pw_array['pwencrypted']);

	/*
		3.) Create the records in the tables.
			a.) Insert email and password into acl_login
			b.) Insert salt into acl_salt.
			c.) Insert validation_key into acl_validate
	 */
	$pw_array['userid'] = $user_create::insert_new_user($pw_array['email'], $pw_array['pwencrypted']);

	if($pw_array['userid'])	{
		if($user_create::insert_new_user_salt($pw_array['userid'], $pw_array['salt']))	{
			if($user_validate::insert_new_user_validation_key($pw_array['userid'], $pw_array['validation_key']))	{
				$pw_array['account_created'] = TRUE;
			}	else 	{
				$pw_array['account_created'] = FALSE;
			}
		}	else 	{
			$pw_array['account_created'] = FALSE;
		}
	}	else 	{
		$pw_array['account_created'] = FALSE;
	}

	/*
		4.) Send the validation email to the new user.
	 */
	if($user_validate::email_activation_key($pw_array['email'], $pw_array['validation_key']))	{
		echo 'An activation email was sent to ' . $pw_array['email'] . "<br/>";
	}	else 	{
		echo "This host is not SMTP capable so no activation email will be sent. <br/>";
	}

}
/*  ===================================================
	Sample code for how to create a new account - End
*/


	if(isset($pw_array['account_created']))	{
		echo 'New user: ' . $pw_array['email'] .' has been created. ' . "<br/>";
	}	else 	{
		echo 'Could not create user: ' . $pw_array['email'] . ". <br/>";
	}


?>