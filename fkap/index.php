<?php

/*
include_once('lib/PDOFunctions.php');

$dbcred = new Dbcred();
$functions = new PDOFunctions;

$db = $functions->createNewPDOConnection($dbcred->dbhost, $dbcred->dsn, $dbcred->dbuser, $dbcred->dbpwd);
*/

/*
	Create new account
*/
include_once('lib/user_create.php');
include_once('lib/encrypt_password.php');
$user_create = new User_Create();
$encrypt_password = new Encrypt_Password();

$email = 'davet6020@gmail.com';
$password = 'password';

if( ! $user_create::test_exist_email($email))	{
	//create the acct.
	//
	echo $encrypt_password::gen_pass($password);
} 	else 	{
	echo "FALSE";
}


?>
