<?php

include_once('PDOFunctions.php');

class User_Create {
	public $var = '';


	/**
	 * Checks to see if the email addr the user is attempting to use to create a 
	 * new account has already been used.
	 * @param  string $email email address
	 * @return boolean        TRUE or FALSE if that email has already been used.
	 */
	public static function test_exist_email($email)	{
		$dbcred = new Dbcred();
		$functions = new PDOFunctions;
		$db = $functions->createNewPDOConnection($dbcred->dbhost, $dbcred->dbname, $dbcred->dbuser, $dbcred->dbpwd);

		$retval = FALSE;
    	try {
	        $stmt = $db->prepare("select email from acl_login where email=:email limit 1");
			$stmt->bindValue(':email', $email, PDO::PARAM_STR);
	        $stmt->execute();
	        $affected_rows = $stmt->rowCount();	

	        if(isset($affected_rows))	{
	        	if($affected_rows > 0)	{
	        		$retval = TRUE;
	        	}	else 	{
	        		$retval = FALSE;
	        	}
	        }	else 	{
	        	$retval = FALSE;
	        }
	      }  catch(PDOException $e)  {
	            //Error
	      }
      return $retval;
	}


	/**
	 * Inserts the new users record into table acl_login.
	 * @param  string $email        the email address = the username of the new account being created.
	 * @param  string $enc_password This is the password that is already encrypted
	 * @return boolean               TRUE or FALSE if the record was successfully inserted.
	 */
	public function insert_new_user($email, $enc_password)	{
		$retval = FALSE;
		$dbcred = new Dbcred();
		$functions = new PDOFunctions;
		$db = $functions->createNewPDOConnection($dbcred->dbhost, $dbcred->dbname, $dbcred->dbuser, $dbcred->dbpwd);
		$sql = "insert into acl_login ( email, password, date_created ) values( :email, :password, :date_created )";
		$stmt = $db->prepare($sql);
		$stmt->bindValue(':email', $email, PDO::PARAM_STR);
		$stmt->bindValue(':password', $enc_password, PDO::PARAM_STR);
		$stmt->bindValue(':date_created', date('Y-m-d H:i:s'), PDO::PARAM_STR);
		$stmt->execute();
		$affected_rows = $stmt->rowCount();
		$userid = $db->lastInsertId();

		if($affected_rows !== FALSE) {
	    	$retval = $userid;
	    }	else 	{
	    	$retval = FALSE;
	    }
	    return $retval;
	}


	/**
	 * Inserts the new users salt key into table acl_salt
	 * @param  Integer $userid This is the new users userid and is the key for this table.
	 * @param  string $salt   This is the salt of the encrypted password and is needed to compare a decryption of the password.
	 * @return Boolean         TRUE or FALSE if the salt record was written into table acl_salt
	 */
	public function insert_new_user_salt($userid, $salt)	{
		$retval = FALSE;
		$dbcred = new Dbcred();
		$functions = new PDOFunctions;
		$db = $functions->createNewPDOConnection($dbcred->dbhost, $dbcred->dbname, $dbcred->dbuser, $dbcred->dbpwd);
		$sql = "insert into acl_salt ( userid, salt ) values( :userid, :salt )";
		$stmt = $db->prepare($sql);
		$stmt->bindValue(':userid', $userid, PDO::PARAM_STR);
		$stmt->bindValue(':salt', $salt, PDO::PARAM_STR);
		$stmt->execute();
		$affected_rows = $stmt->rowCount();
		$userid = $db->lastInsertId();

		if($affected_rows !== FALSE) {
	    	$retval = TRUE;
	    }	else 	{
	    	$retval = FALSE;
	    }
	    return $retval;
	}
	
}

?>
