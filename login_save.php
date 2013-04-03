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
	
	$login_status = $user_login::login($login_array['email'], $login_array['password']);
	
	if($login_status['activated']&&$login_status['passwordMatch']){
		echo "Login Succesful! <br/>";
	}
	elseif(!$login_status['passwordMatch']){
		//echo $login_status['passwordMatch'];
		echo "Passwords do not match. <br/>";
	}
	elseif(!$login_status['activated']){
		echo "Please activate your account. <br/>";
	}


//if($user_login::login($login_array['email'], $login_array['password']))	{
//	echo "passwords match <br/>";
//}	else 	{
//	echo "bad passwords <br/>";
//}


?>