<?php

include_once('PDOFunctions.php');

class User_Create {
	public $var = '';


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
	            //echo $e->getMessage();
	      }
      return $retval;
	}



	/* ==================================================
		For all registered guests
	================================================== */
	/*
		This happens if test_exist_email($email) returns false.  It means the email they want to use
		for their login id has not been used by someone else so go ahead and set up their account.
		NOTE:	We have to assume that we know what kind of user they are ie; rg, cc, or patient.  This will
				be based on where they come from eg: they clicked on 'Set Up Your Site'=patient or they created
				a site for 'Someone Else'=cc or otherwise they are a registered guest.
		1.) Create the username and password stuff in acl_login.
		2.) Insert the corresponding userid, email and salt into acl_salt by calling insert_salt($userid, $email, $salt)
	*/
	public function create_login($email, $password, $groupid)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$acl = new Acl();
	   	$dbopen = new Dbopen();
	   	$util = new Utilities();
		//$util::msg(__FUNCTION__);
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
			$db->beginTransaction();
		        $sql = "insert into acl_login ( email, password, groupid ) values( :email, :password, :groupid )";
				$stmt = $db->prepare($sql);

				$salt = $acl::bfSalt(10);
				$pwsalted = $acl::bfEnc($password, $salt);

		        $stmt->bindValue(':email', $email, PDO::PARAM_STR);
				$stmt->bindValue(':password', $pwsalted, PDO::PARAM_STR);
				$stmt->bindValue(':groupid', $groupid, PDO::PARAM_STR);
	    	    $stmt->execute();
				$affected_rows = $stmt->rowCount();
				$userid = $db->lastInsertId();
			$db->commit();
	      }  catch(PDOException $e)  {
	            echo "this is an error message<br/>";
	            echo $e->getMessage();
	      }
	    if($affected_rows !== false) {
	    	$retval = TRUE;
	    	$acl::insert_salt($userid, $email, $salt);
	    	$acl::insert_validation_key($userid, $email, $groupid);
	    }	else 	{
	    	$retval = FALSE;
	    }
	    return $retval;
	}



	public static function create_login_part2($userid, $lastname, $firstname)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		//Called from create_login_patient().
		$acl = new Acl();
	   	$dbopen = new Dbopen();
		$util = new Utilities();

		$retval = FALSE;
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
			//$db->beginTransaction();
		        $sql = "insert into acl_users ( userid, lastname, firstname ) values( :userid, :lastname, :firstname )";
				$stmt = $db->prepare($sql);
				$stmt->bindValue(':userid', $userid, PDO::PARAM_STR);
				$stmt->bindValue(':lastname', $lastname, PDO::PARAM_STR);
				$stmt->bindValue(':firstname', $firstname, PDO::PARAM_STR);
	    	    $stmt->execute();
				$affected_rows = $stmt->rowCount();
			//$db->commit();
	      }  catch(PDOException $e)  {
	            echo $e->getMessage();
	      }
	    if(isset($affected_rows))	{
		    if($affected_rows !== false) {
		    	$retval = TRUE;
		    }	else 	{
		    	$retval = FALSE;
		    }
		}
	    return $retval;
	}



	public static function insert_salt($userid, $email, $salt)	{
		//$_SESSION[__METHOD__] = __METHOD__;
	//This is called from create_login_patient().
		$retval = FALSE;
		$acl = new Acl();
	   	$dbopen = new Dbopen();
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
			$db->beginTransaction();
		        $sql = "insert into acl_salt (userid, email, salt) values(:userid, :email, :salt)";
				$stmt = $db->prepare($sql);
		        $stmt->bindValue(':userid', $userid, PDO::PARAM_STR);
		        $stmt->bindValue(':email', $email, PDO::PARAM_STR);
				$stmt->bindValue(':salt', $salt, PDO::PARAM_STR);
	    	    $stmt->execute();
				$affected_rows = $stmt->rowCount();
			$db->commit();
	      }  catch(PDOException $e)  {
	            echo "this is an error message<br/>";
	            echo $e->getMessage();
	      }
	    $affected_rows = $stmt->rowCount();
   		if(isset($affected_rows))	{
		   	if($affected_rows > 0)	{
	    		$retval = TRUE;
	    	}
	    }	else 	{
	    	$retval = FALSE;
	    }
	    return $retval;
	}


	public static function insert_validation_key($userid, $email, $groupid)	{
		//$_SESSION[__METHOD__] = __METHOD__;
	//This is called from create_login_patient().
		$acl = new Acl();
	   	$dbopen = new Dbopen();
	   	$sys = new Sys();
	   	$util = new Utilities();
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
			$db->beginTransaction();
				$validation_key = hash('sha256', $email.$userid);
		        $sql = "insert into acl_validate (userid, email, validation_key, groupid) values(:userid, :email, :validation_key, :groupid)";
				$stmt = $db->prepare($sql);
		        $stmt->bindValue(':userid', $userid, PDO::PARAM_STR);
		        $stmt->bindValue(':email', $email, PDO::PARAM_STR);
				$stmt->bindValue(':validation_key', $validation_key, PDO::PARAM_STR);
				$stmt->bindValue(':groupid', $groupid, PDO::PARAM_STR);
	    	    $stmt->execute();
				$affected_rows = $stmt->rowCount();
			$db->commit();
	      }  catch(PDOException $e)  {
	            echo $e->getMessage();
	      }
		if(isset($affected_rows))	{
		   	if($affected_rows > 0)	{
	        	$retval = TRUE;
	        	// $_GET example: welcome.php?fname=Peter&age=37
	        	/*
	        	$validation_url = '<a href="http://' . $sys->where . 'x2_activatethelink.php?validation_key=' . $validation_key . '">';
	        	$validation_url .= "$validation_key</a>";
	        	$util::msg("this is your validation key.  $validation_url");
	        	*/
	        	//$validation_url = '<a href="http://' . $sys->where . 'x2_activatethelink.php?validation_key=' . $validation_key . '">';
	        	//$validation_url = 'http://' . $sys->where . 'x2_activatethelink.php?validation_key=' . $validation_key;
	        	$validation_url = $_SESSION['validation_url'] . 'activate.php?validation_key=' . $validation_key;
	        	if(! isset($_SESSION['smtp']))	{
	        		//$my_system = $util::get_system_by_hostname(gethostname());
	        		$_SESSION['smtp'] = FALSE;
	        	}
	        	if($acl::email_activation_key($email, $validation_url))	{
	        		$retval = TRUE;
	        	}
	        }
	    }	else 	{
	    	$retval = FALSE;
	    }
	    return $retval;
	}


	public static function email_activation_key($email, $validation_url)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		if(! $_SESSION['smtp'])	{
			return TRUE;	//because if the return val is false bad junk happens.
		}
		$util = new Utilities();
		$retval = FALSE;
		$headers = 'From: activate@mylifeline.org' . "\r\n" . 'Reply-To: activate@mylifeline.org' . "\r\n" . 'X-Mailer: PHP/' . phpversion();
		$to = $email;
		$subject = "MyLifeLine.org Account Activation";
		//$body = "Hi there $email,\n";
		$body = 'Hi there ' . $_SESSION['firstname'] . ' ' . $_SESSION['lastname'] . "\n";
		$body .= "You have received this email because you or someone using your email signed up for an account\n";
		$body .= "on the MyLifeLine.org web site.  To activate this account, click on the URL below.\n";
		$body .= "$validation_url\n";
		$body .= "If you do not want this account don't do anything and the activation key will expire in 2 weeks.\n\n";
		$body .= "Thanks!\n";
		$body .= "support@mylifeline.org\n";

		//if(mail($to, $subject, $body)) {
		if(mail($to, $subject, $body, $headers)) {
			$retval = TRUE;
		} else {
			$retval = FALSE;
		}
		return $retval;
	}
	

	public function account_activation($validation_key)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$acl = new Acl();
		$dbopen = new Dbopen();
		$util = new Utilities();

		$_SESSION['retval'] = FALSE;
	    try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
			$stmt = $db->prepare("select userid, email, groupid from acl_validate where validation_key=:validation_key limit 1");
			$stmt->bindValue(':validation_key', $validation_key, PDO::PARAM_STR);
			$stmt->execute();
			$affected_rows = $stmt->rowCount();
		        if(isset($affected_rows))	{
		        	if($affected_rows > 0)	{
						foreach($stmt as $row)	{
							$userid = $row['userid'];
		        			$email = $row['email'];
		        			$groupid = $row['groupid'];
		        		}
		        		switch ($groupid)	{
		        			case 35:	//patient
		        				//$acl::create_user_profile_stub($userid); //don't need this anymore.
								$acl::create_patient_profile_stub($userid);
								//$acl::create_patient_group($userid, $email, 6);
								//This used to be 6 but now I'm making it 5.  It may be a mistake.
								$acl::create_patient_group($userid, $email, 5);
								if($acl::activate_account($userid, 5))	{
				        			$_SESSION['retval'] = TRUE;
				        			$acl::remove_validation_key($email);
				        		}	else 	{
				        		}
		        				break;
							case 36:	//care coordinator
		        				$acl::create_user_profile_stub($userid);
		        				if($acl::activate_account($userid, 6))	{
				        			//$util::msg('Your account was activated');
				        			$_SESSION['retval'] = TRUE;
				        			$acl::remove_validation_key($email);
				        		}	else 	{
				        			//$util::msg('Sorry but I could not activate your account.');
				        		}
								break;
							case 37:	//registered guest
								$acl::create_user_profile_stub($userid);
								if($acl::activate_account($userid, 7))	{
				        			//$util::msg('Your account was activated');
				        			$_SESSION['retval'] = TRUE;
				        			$acl::remove_validation_key($email);
				        		}	else 	{
				        			//$util::msg('Sorry but I could not activate your account.');
				        		}
		        				break;
		        			default:	//registered guest
		        				//$util::msg('switch default.');
		        		}
		        	}	else 	{
		        		$_SESSION['retval'] = FALSE;
		        	}
		        }	else 	{
		        	$_SESSION['retval'] = FALSE;
		        }
			}  catch(PDOException $e)  {
		        //$util::msg($e->getMessage());
		    }
		    $retval = $_SESSION['retval'];
	    return $retval;
	}


	public function activate_account($userid, $groupid)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		/*
			If the activation process is a go, this function will activate the acl_login record
			for the user making them ok to login.
		*/
		$retval = FALSE;
		$acl = new Acl();
		$dbopen = new Dbopen();
		$util = new Utilities();
		try {
		    $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
		    $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
		    $stmt = $db->prepare("update acl_login set activated=:activated, groupid=:groupid where userid=:userid");
		    $stmt->bindValue(':activated', 1, PDO::PARAM_INT);
		    $stmt->bindValue(':groupid', $groupid, PDO::PARAM_INT);
		    $stmt->bindValue(':userid', $userid, PDO::PARAM_INT);
		    $stmt->execute();
		    $retval = TRUE;
	    }  catch(PDOException $e)  {
	    	$retval = FALSE;
	        //$util::msg($e->getMessage());
	    }
	    return $retval;
	}


	public function remove_validation_key($email)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$acl = new Acl();
		$dbopen = new Dbopen();
		$retval = FALSE;
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );

			$stmt = $db->prepare("delete from acl_validate where email=:email");
			$stmt->bindValue(':email', $email, PDO::PARAM_STR);
			$stmt->execute();
			$affected_rows = $stmt->rowCount();
	      }  catch(PDOException $e)  {
	            echo "this is an error message<br/>";
	            echo $e->getMessage();
	      }
		    if(isset($affected_rows))	{
		    	if($affected_rows !== false) {
		    		$retval = TRUE;
		    	}	else 	{
		    		$retval = FALSE;
		    	}
		    }
      return $retval;
	}




	public function create_user_profile_stub($userid)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$acl = new Acl();
	   	$dbopen = new Dbopen();
		$util = new Utilities();
		$retval = FALSE;
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
			$db->beginTransaction();
		        $sql = "insert into acl_users ( userid ) values( :userid )";
				$stmt = $db->prepare($sql);
				$stmt->execute(array( ':userid' => $userid ));
				$affected_rows = $stmt->rowCount();
			$db->commit();
	      }  catch(PDOException $e)  {
	            echo $e->getMessage();
	      }
	    if(isset($affected_rows))	{
		    if($affected_rows !== false) {
		    	$retval = TRUE;
		    }	else 	{
		    	$retval = FALSE;
		    }
		}
	    return $retval;
	}


	/* ==================================================
		For all guests
	================================================== */


	/* ==================================================
		For encryption stuff
	================================================== */
	public static function bfSalt($cost)	{
		//$_SESSION[__METHOD__] = __METHOD__;
	    $chars='./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	    $salt=sprintf('$2a$%02d$', $cost);
	    for($i=0; $i<22; $i++)	{
	    	$salt.=$chars[rand(0,63)];	
	    }
	return $salt;
	}


	public static function bfEnc($ctpw, $salt)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$enc = crypt($ctpw, $salt);
		$_SESSION['enc'] = $enc;
		return $enc;
	}


	public static function bfUnEnc($ctpw, $salt)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$tstenc = crypt($ctpw, $salt);
		/*
		if($tstenc == $_SESSION['enc'])	{
			$retval = TRUE;
		}	else 	{
			$retval = FALSE;
		}
		*/
		return $tstenc;
	}


	public static function bfUnEncORIG($ctpw, $salt)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$retval = FALSE;
		$tstenc = crypt($ctpw, $salt);
		if($tstenc == $_SESSION['enc'])	{
			$retval = TRUE;
		}	else 	{
			$retval = FALSE;
		}
		//return $retval;
		return $tstenc;
	}


	public function clear_login_session_info()  {
		//$_SESSION[__METHOD__] = __METHOD__;
		$email = NULL;
		$password = NULL;
		$_SESSION['logged_in'] = FALSE;
		$_SESSION['userid'] = NULL;
		$_SESSION['firstname'] = NULL;
		$_SESSION['lastname'] = NULL;
		$_SESSION['email'] = NULL;
		$_SESSION['screen_name'] = NULL;
		$_SESSION['logged_in'] = FALSE;
		$_SESSION['last_logged_in'] = NULL;
		$_SESSION['pw_last_changed'] = NULL;
	}
	

	public function unset_login_session_info()  {
		//$_SESSION[__METHOD__] = __METHOD__;
		$email = NULL;
		$password = NULL;
		unset($_SESSION['logged_in']);
		unset($_SESSION['userid']);
		unset($_SESSION['firstname']);
		unset($_SESSION['lastname']);
		unset($_SESSION['email']);
		unset($_SESSION['screen_name']);
		unset($_SESSION['logged_in']);
		unset($_SESSION['last_logged_in']);
		unset($_SESSION['pw_last_changed']);
	}


	public function loggedin()	{
		//$_SESSION[__METHOD__] = __METHOD__;
		if(! isset($_SESSION['logged_in']))	{
			$_SESSION['logged_in'] = "";
		}
		if($_SESSION['logged_in'])	{
			$logged = TRUE;
		}	else 	{
			$logged = FALSE;
		}
		return $logged;
	}

}

?>
