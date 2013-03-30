<?php

include_once('lib/user_login.php');
$user_login = new User_Login();

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

if($user_login::login($login_array['email'], $login_array['password']))	{
	echo "passwords match <br/>";
}	else 	{
	echo "bad passwords <br/>";
}


?>