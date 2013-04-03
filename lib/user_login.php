<?php

include_once('PDOFunctions.php');
include_once('encrypt_password.php');

class User_Login {
	public $var = '';


	function login($email, $ctpassword)  {
		$dbcred = new Dbcred();
		$encrypt_password = new Encrypt_Password();
		$functions = new PDOFunctions;
		$db = $functions->createNewPDOConnection($dbcred->dbhost, $dbcred->dbname, $dbcred->dbuser, $dbcred->dbpwd);
    	$retval = array();
	$retval['activated'] = FALSE;
	$retval['passwordMatch'] = FALSE;
    	$login_array = array();

	    try {
			$stmt = $db->prepare("select userid, password, activated from acl_login where email=:email limit 1");
			$stmt->bindValue(':email', $email, PDO::PARAM_STR);
			$stmt->execute();

			while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
				foreach($row as $key => $value)  {
					$login_array[$key] = $value;
				}
			}
			
			if(isset($login_array['activated']) && $login_array['activated']==1){
				$retval['activated'] = TRUE;
			}
			//else if( ! isset($login_array['activated']))	{
			//	return;
			//}	else 	{
			//	if(empty($login_array['activated']))	{
			//		return;
			//	}
			//}

			$stmt = $db->prepare("select salt from acl_salt where userid=:userid limit 1");
			$stmt->bindValue(':userid', $login_array['userid'], PDO::PARAM_STR);
			$stmt->execute();
			while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
				foreach($row as $key => $value)  {
					$login_array[$key] = $value;
				}
			}

			$enc_password = array();
			foreach($encrypt_password::unEnc($ctpassword, $login_array['salt']) as $key => $value)	{
				$enc_password[$key] = $value;
			}

			if($enc_password['pwencrypted'] == $login_array['password'])	{
				$retval['passwordMatch'] = TRUE;
			}	else 	{
				$retval['passwordMatch'] = FALSE;
			}

			/*
			echo "enc_password['pwencrypted']: " . $enc_password['pwencrypted'] . "<br/>";
			echo "login_array['password']: " . $login_array['password'] . "<br/>";
			*/
	    	return $retval;
		}  catch(PDOException $e)  {

		}
	}
}

/*
	public function last_login($userid)	{

	}


	public function change_eamil($old_email, $new_email)	{

	}

*/



?>
