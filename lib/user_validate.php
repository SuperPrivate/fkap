<?php

include_once('PDOFunctions.php');

class User_Validate {
	public $var = '';


	/**
	 * Generates a sha256 key to be used as the users unique validation key.
	 * @param  string $email The users email address is used as the seed for the sha256 key.
	 * @return string        The validation_key is returned to it can be populated into $pw_array
	 */
	public static function gen_validation_key($email)	{
		$validation_key = hash('sha256', $email);
		return $validation_key;
	}


	/**
	 * Inserts the new users validation key into table acl_validate
	 * @param  Integer $userid This is the new users userid and is the key for this table.
	 * @param  string $validation_key This is the validation key the user will need in order to activate this new account.
	 * @return boolean          TRUE or FALSE is the validation key was written to the table.
	 */
	public function insert_new_user_validation_key($userid, $validation_key)	{
		$retval = FALSE;
		$dbcred = new Dbcred();
		$functions = new PDOFunctions;
		$db = $functions->createNewPDOConnection($dbcred->dbhost, $dbcred->dbname, $dbcred->dbuser, $dbcred->dbpwd);
		$sql = "insert into acl_validate ( userid, validation_key ) values( :userid, :validation_key )";
		$stmt = $db->prepare($sql);
		$stmt->bindValue(':userid', $userid, PDO::PARAM_STR);
		$stmt->bindValue(':validation_key', $validation_key, PDO::PARAM_STR);
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

	/**
	 * This sends an activation email to the user that signed up for an account.  If the web server
	 * running these programs is SMTP enabled, set $_SESSION['smtp'] = TRUE in your index.php
	 * @param  $string $email          this is the email address of the newly created user account.
	 * @param  string $validation_url this is created in user_validate.php.gen_validation_key and is stored in $pw_array['validation_key']
	 * @return boolean          returns TRUE or FALSE if the activation email was sent.  If $_SESSION['smpt'] = FALSE it returns a true but 
	 * doesn't lock up the machine by trying to send an email when it cannot.
	 */
	public static function email_activation_key($email, $validation_url)	{
		/*
		THIS is a sample email.
		header: From: activate@codeoften.com Reply-To: activate@codeoften.com X-Mailer: PHP/5.3.13 
		subject: account activation infoz 
		body: Hi there davet6020@gmail.com. You have received this email because you or someone using your email signed up
				for an account on the somethingorother web site. To activate this account, click on the URL below. 
				http://codeoften.com/action/user_activate.php?validation_key=7fd4d0ca2613e8395ee2d9fca452074da22f78609ef85c2ec842c107dfffaf49 
				If you do not want this account don't do anything and the activation key will expire in 2 weeks. 
				Thanks! activate@codeoften.com 
		 */

		/*
			If you did not set the smtp session to TRUE then you don't have an SMTP
			server so return from this function because it will not do anything but error.
		 */
		if($_SESSION['smtp'])	{
			return TRUE;
		}	else 	{
			return FALSE;
		}

		$retval = FALSE;
		$dbcred = new Dbcred();
		$functions = new PDOFunctions;
		$db = $functions->createNewPDOConnection($dbcred->dbhost, $dbcred->dbname, $dbcred->dbuser, $dbcred->dbpwd);
		$acl_email = array();

    	try {
	        $stmt = $db->prepare("select * from acl_email where emailid=:emailid limit 1");
			$stmt->bindValue(':emailid', 1, PDO::PARAM_STR);
	        $stmt->execute();
			foreach($stmt->fetch(PDO::FETCH_ASSOC) as $key => $value)	{
				$acl_email[$key] = $value;
			}
		}  catch(PDOException $e)  {
	            //echo $e->getMessage();
		}

		$headers = 'From: ' . $acl_email['email_from'] . "\r\n" . 'Reply-To: ' . $acl_email['email_from'] . "\r\n" . 'X-Mailer: PHP/' . phpversion();
		$to = $email;
		$subject = $acl_email['email_subject'];

		$body = 'Hi there ' . $email . ". \n";
		$body .= "You have received this email because you or someone using your email signed up for an account\n";
		$body .= "on the somethingorother web site.  To activate this account, click on the URL below.\n";
		$body .= $acl_email['activation_url'] . "$validation_url\n\n";
		$body .= "If you do not want this account don't do anything and the activation key will expire in 2 weeks.\n\n";
		$body .= "Thanks!\n";
		$body .= $acl_email['email_from'] . "\n";

		if(mail($to, $subject, $body, $headers)) {
			$retval = TRUE;
		} else {
			$retval = FALSE;
		}
		return $retval;
	}
	

	/**
	 * Looks up the validation key in acl_validate, gets the associated userid, sets acl_login.activated=TRUE
	 * and then deletes the validation key from acl_validate.
	 * @param  string $validation_key this is the sha256 validation key.
	 * @return Boolean                 returns TRUE or FALSE if the entire process was true.
	 */
	public function account_activation($validation_key)	{
		$dbcred = new Dbcred();
		$functions = new PDOFunctions;
		$db = $functions->createNewPDOConnection($dbcred->dbhost, $dbcred->dbname, $dbcred->dbuser, $dbcred->dbpwd);
		$retval = FALSE;
		$val_array = array();

	    try {
	        /*
	        	Get the userid associated with the supplied validation key.
	         */
			$stmt = $db->prepare("select userid from acl_validate where validation_key=:validation_key limit 1");
			$stmt->bindValue(':validation_key', $validation_key, PDO::PARAM_STR);
			$stmt->execute();

			while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
				foreach($row as $key => $value)  {
					$val_array[$key] = $value;
				}
				$retval = TRUE;
			}

			/*
				Activate the users account by setting acl_login.activated = 1.
			 */
			if($retval)	{
				$stmt = $db->prepare("update acl_login set activated=:activated where userid=:userid");
				$stmt->bindValue(':activated', TRUE, PDO::PARAM_STR);
				$stmt->bindValue(':userid', $val_array['userid'], PDO::PARAM_STR);
				$stmt->execute();
				
				if(isset($affected_rows))	{
			    	if($affected_rows !== FALSE) {
			    		$retval = TRUE;
			    	}	else 	{
			    		$retval = FALSE;
			    	}
			    }
			}


			/*
				Delete the record from acl_validate because we no longer need it.
			 */
			if($retval)	{
				$stmt = $db->prepare("delete from acl_validate where userid=:userid");
				$stmt->bindValue(':userid', $val_array['userid'], PDO::PARAM_STR);
				$stmt->execute();

				if(isset($affected_rows))	{
			    	if($affected_rows !== FALSE) {
			    		$retval = TRUE;
			    	}	else 	{
			    		$retval = FALSE;
			    	}
			    }
			}


		}  catch(PDOException $e)  {
			//Error
		}
	    return $retval;
	}

}

?>
