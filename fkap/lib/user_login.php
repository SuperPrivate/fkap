<?php

include_once('__config_db.php');
include_once('utilities.php');

class Acl {
	public $var = '';



	/* ==================================================
		For all users with or without accounts
	================================================== */
	public function keep_alive() {
		//$_SESSION[__METHOD__] = __METHOD__;
		session_regenerate_id(true);
		/*
			 900 seconds = 15 minutes.
			1800 seconds = 30 minutes.
			3600 seconds = 60 minutes.
		
			 60 minutes = 1 hour
			120 minutes = 2 hours
			180 minutes = 3 hours
			240 minutes = 4 hours
			300 minutes = 5 hours
			360 minutes = 6 hours
		   1440 minutes = 24 hours
		*/

		$to_in_seconds = $_SESSION['whitelabel_timeout'] * 60;
		$_SESSION['KEEP_ALIVE'] = $to_in_seconds;
		
		if (isset($_SESSION['LAST_ACTIVITY']) && (time() - $_SESSION['LAST_ACTIVITY'] > $$_SESSION['KEEP_ALIVE'])) {
			// last request was more than list_whitelabels.whitelabel_timeout minutes ago
			session_destroy();   // destroy session data in storage
			session_unset();     // unset $_SESSION variable for the runtime
			header('Location: ' . $_SESSION['site_url'] . 'login?login=FALSE');
		}
		$_SESSION['LAST_ACTIVITY'] = time(); // update last activity time stamp
		
		if (!isset($_SESSION['CREATED'])) {
			$_SESSION['CREATED'] = time();
		} else if (time() - $_SESSION['CREATED'] > 1800) {
			// session started more than 30 minutes ago
			session_regenerate_id(true);    // change session ID for the current session an invalidate old session ID
			$_SESSION['CREATED'] = time();  // update creation time
		}
	}


	/* ==================================================
		For all users with accounts
	================================================== */
	function login($email, $password)  {
		//$_SESSION[__METHOD__] = __METHOD__;
    	$retval = FALSE;
		$acl = new Acl();
		$dbopen = new Dbopen();
		$matrix = new Matrix();
		$util = new Utilities();

		//Run this first so if the login fails we still have some info about them.
		$matrix::not_logged_in($email);

	    try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
			$stmt = $db->prepare("select salt from acl_salt where email=:email limit 1");
			$stmt->bindValue(':email', $email, PDO::PARAM_STR);
			$stmt->execute();
			$affected_rows = $stmt->rowCount();	
		        if(isset($affected_rows))	{
		        	if($affected_rows > 0)	{
		        		foreach($stmt as $row)	{
		        			$salt = $row['salt'];
		        		}
		        	}	else 	{
		        		$salt = "there was a problem.";
		        	}
		        }	else 	{
		        	$salt = "there really was a problem.";
		        }

	        $stmt = $db->prepare("select userid, email, activated, groupid from acl_login
	            				  where email=:email and password=:password limit 1");
	        $stmt->bindValue(':email', $email, PDO::PARAM_STR);
			//$stmt->bindValue(':password', $acl::pw_unhasher($password, $salt), PDO::PARAM_STR);
			$stmt->bindValue(':password', $acl::bfUnEnc($password, $salt), PDO::PARAM_STR);
	        $stmt->execute();

	        $affected_rows = $stmt->rowCount();	
		        if(isset($affected_rows))	{
		        	if($affected_rows > 0)	{
		        		$retval = TRUE;
		        		foreach($stmt as $row)	{
		        			$_SESSION['userid'] = $row['userid'];
		        			$_SESSION['email'] = $row['email'];
		        			$_SESSION['activated'] = $row['activated'];
		        			$_SESSION['groupid'] = $row['groupid'];
		        		}
		        			if(! $_SESSION['activated'])	{
		        				$retval = FALSE;
		        				//$util::msg('This account has never been activated.');
		        			}	else 	{
		        				//The login works and the user has an activated account.  Build the login matrix.
		        				$acl::update_last_logged_in($_SESSION['userid']);
		        				$matrix::get_remote_ip($_SESSION['userid']);
		        				//$acl::login_get_matrix($_SESSION['userid']);
		        			}
		        	}	else 	{
		        		$retval = FALSE;
		        	}
		        }	else 	{
		        	$retval = FALSE;
		        }
			}  catch(PDOException $e)  {
		        echo $e->getMessage();
		    }



	    	return $retval;
	}


	public function login_get_matrix($userid)  {
		//$_SESSION[__METHOD__] = __METHOD__;
		/*
			What we have: $_SESSION['userid'], $_SESSION['email'], $_SESSION['groupid']
			What we need:
				1.) if groupid==5 OR 6 select * from acl_patients AND acl_users
				2.) if groupid==7 select * from acl_users
		*/
		$acl = new Acl();
		$dbopen = new Dbopen();
		$util = new Utilities();
	    try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
		        switch ($_SESSION['groupid'])	{
		        	case 5:
		        		$stmt = $db->prepare("select * from acl_patients as p, acl_users as u where u.userid=:userid and p.userid=:userid limit 1");
		        	break;
		        	case 6:
						$stmt = $db->prepare("select * from acl_patients as p, acl_users as u where u.userid=:userid and p.userid=:userid limit 1");
		        	break;
		        	case 7:
		        		$stmt = $db->prepare("select * from acl_users as u where u.userid=:userid limit 1");
		        	break;
		        }
	        $stmt->bindValue(':userid', $userid, PDO::PARAM_STR);
	        $stmt->execute();
	            while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
	            	foreach($row as $key => $value)  {
	               		//echo $key . ": $value<br/>";
	                	$$key = $value;
	               	}
	               	//echo "remote_ip_addr: " . $_SESSION['remote_ip_addr'] . "<br/>";
	           	}
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
		        echo $e->getMessage();
		    }
		}


	public function group_adduser($groupid, $userid)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		/*
			Adds a user to a group by associating with a group in lu_group_user.
		*/
		$acl = new Acl();
		$dbopen = new Dbopen();
		$util = new Utilities();
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
	        $sql = "insert ignore into lu_group_user (groupid, userid) values(:groupid, :userid)";
			$stmt = $db->prepare($sql);
			$stmt->bindValue(':groupid', $groupid, PDO::PARAM_STR);
			$stmt->bindValue(':userid', $userid, PDO::PARAM_STR);
			$stmt->execute();
			$affected_rows = $stmt->rowCount();

	      }  catch(PDOException $e)  {
	            echo $e->getMessage();
	      }
	    if($affected_rows !== false) {
	    	$retval = 'Number of rows added: '. $affected_rows;
	    }	else 	{
	    	$retval = "Could not join that user to this group.";
	    }
	    return $retval;
	}


	public function group_deluser($groupid, $userid)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		// Removes a user from a group by dis-associating it from the group in lu_group_user
		$acl = new Acl();
		$dbopen = new Dbopen();
		$util = new Utilities();
		$retval = "No user with that id was found.";
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );

			$stmt = $db->prepare("delete from lu_group_user where groupid=:groupid and userid=:userid");
			$stmt->bindValue(':groupid', $groupid, PDO::PARAM_STR);
			$stmt->bindValue(':userid', $userid, PDO::PARAM_STR);
			$stmt->execute();
			$affected_rows = $stmt->rowCount();
	      }  catch(PDOException $e)  {
	            echo "this is an error message<br/>";
	            echo $e->getMessage();
	      }
	    	if($affected_rows !== false) {
	    		$retval = 'Number of rows updated: '. $affected_rows;
	    	}	else 	{
	    		$retval = "Could not update the user.";
	    	}
      return $retval;
	}


	public function group_get_info($userid)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		/*
			select g.groupid, g.groupname from acl_groups g, lu_group_user l 
			where g.groupid = l.groupid and l.userid=3
		*/
		$acl = new Acl();
		$dbopen = new Dbopen();
		$util = new Utilities();
        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
		$stmt = $db->prepare("select g.groupid, g.groupname from acl_groups g, lu_group_user l where g.groupid = l.groupid and l.userid=? order by g.groupid");
        $stmt->execute(array($userid));
        	$_SESSION['groups_count'] = 0;
        	$i = 0;
            while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            	$_SESSION['groups_count'] += 1;
				$i += 1;
				$sgroupid = "groupid" . $i;
				$sgroupname = "groupname" . $i;
            	$_SESSION[$sgroupid] = $row['groupid'];
            	$_SESSION[$sgroupname] = $row['groupname'];
			}

		    echo "<br/>I am a member of the following " . $_SESSION['groups_count'] . " groups.<br/>";
		    echo "<u>groupid - groupname </u><br/>";
		    for($i=1; $i<=$_SESSION['groups_count']; $i++)	{
		    	$sgroupid = "groupid" . $i;
				$sgroupname = "groupname" . $i;
		    	echo "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" . $_SESSION[$sgroupid] . " - " . $_SESSION[$sgroupname] . "<br/>";
		    }

			$group_array = array();
			for($i=1; $i<=$_SESSION['groups_count']; $i++)	{
				$sgroupid = "groupid" . $i;
				$sgroupname = "groupname" . $i;
				array_push($group_array, $_SESSION[$sgroupid]); //, $_SESSION[$sgroupname]);
			}
			$_SESSION['group_array'] = $group_array;
	}


	public function get_userid_by_email($email)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$dbopen = new Dbopen();
		$retval = "Admin $email was not found.";
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
	        $rcols = "userid";
	        $stmt = $db->prepare("select $rcols from acl_users where email = ? limit 1");
	        $stmt->execute(array($email));
	            while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
	            	$retval = NULL;
	               	foreach($row as $key => $value)  {
	                	$$key = $value;
	                	//echo $key . ": $value<br/>";
	                	//$retval .= $key . "|$value<br/>";
	                	$retval .= $value;
	               }
	            }
	      }  catch(PDOException $e)  {
	            echo "this is an error message<br/>";
	            echo $e->getMessage();
	      }
      return $retval;
	}


	public function get_profile_completion($userid)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		/*
			This will also update acl_user.profile_complete_percent with the calculated value.  Why not do it!.
		*/
		$acl = new Acl();
		$dbopen = new Dbopen();
		$retval = 0;
		$numcols = 0;
		$numcols = -2;		//Subtracted 2 for addr2 and addr3 fields.  They are unusual and unlikely in the US.
		$numfull = 0;
		$numempty = 0;
    	try {
	        /*
	       	$db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
	        $stmt = $db->prepare("select groupid from acl_login where userid=:userid limit 1");
	        $stmt->bindParam(':userid', $userid);
	        $stmt->execute();
	        $affected_rows = $stmt->rowCount();	
		        if(isset($affected_rows))	{
		        	if($affected_rows > 0)	{
		        		//foreach($stmt as $row)	{
		        			//I shouldn't have to do this.  I should already have the groupid in session.
		        			$_SESSION['groupid'] = $row['groupid'];
		        		//}
		        	}
		        }
		    */

	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );

	        switch ($_SESSION['groupid'])	{
	        	case 5:
	        		$stmt = $db->prepare("select * from acl_patients as p, acl_users as u where u.userid=:userid and p.userid=:userid limit 1");
	        	break;
	        	case 6:
					$stmt = $db->prepare("select * from acl_patients as p, acl_users as u where u.userid=:userid and p.userid=:userid limit 1");
	        	break;
	        	case 7:
	        		$stmt = $db->prepare("select * from acl_users as u where u.userid=:userid limit 1");
	        	break;
	        	default:
	        		$stmt = $db->prepare("select * from acl_users as u where u.userid=:userid limit 1");
	        }

	        $stmt->bindParam(':userid', $userid);
	        $stmt->execute();
	            while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
	               	foreach($row as $key => $value)  {
	                	$$key = $value;
	                	$numcols += 1;
	                	if(trim($value == ''))	{
	                		$numempty += 1;
	                	}	else 	{
	                		$numfull += 1;
	                	}
	               }
	               $longpercent = ($numfull / $numcols);
	               $profile_complete_percent = round((float)$longpercent * 100 );
	               $acl::update_profile_completion($userid, $profile_complete_percent);
	               $_SESSION['profile_complete_percent'] = $profile_complete_percent;
	               $retval = $profile_complete_percent;
	            }
	      }  catch(PDOException $e)  {
	            echo $e->getMessage();
	      }
      return $retval;
	}


	public function update_profile_completion($userid, $profile_complete_percent)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$acl = new Acl();
		$dbopen = new Dbopen();
	    try {
		        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
		        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
		        $stmt = $db->prepare("update acl_users set profile_complete_percent=:profile_complete_percent where userid=:userid");
		        $stmt->bindParam(':profile_complete_percent', $profile_complete_percent);
		        $stmt->bindParam(':userid', $userid);
		        $stmt->execute();
	    }  catch(PDOException $e)  {
	            echo $e->getMessage();
	    }
	}


	public function update_cancer_info($userid, $update_array)	{
		$retval = FALSE;
		$sql = 'update lu_patients_cancerinfo set ';
		foreach($update_array as $key => $value)  {
			if($key != 'userid')	{	//I add the userid at the end in the where so eliminate it from the first part of the update.
				$sql .= $key . " = :$key, ";
			}
		}
		$sql = substr($sql,0,-2);	//This removes the comma and trailing space from the sql string.
		$sql .= " where userid =  '$userid'";

		$dbopen = new Dbopen();
	    try {
		        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
		        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
		        $stmt = $db->prepare($sql);
				foreach($update_array as $key => $value)  {
					$stmt->bindValue(":$key", $value, PDO::PARAM_INT);
				}
		        $stmt->execute();
	    }  catch(PDOException $e)  {
	            echo $e->getMessage();
	    }
	}


	public function update_last_logged_in($userid)  {
		//$_SESSION[__METHOD__] = __METHOD__;
		$acl = new Acl();
		$dbopen = new Dbopen();
		$util = new Utilities();
	    try {
		        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
		        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
		        $stmt = $db->prepare("update acl_users set logged_in=:logged_in, last_logged_in=:last_logged_in where userid=:userid");
		        $logged_in = TRUE;
		        $stmt->bindParam(':logged_in', $logged_in);
		        $stmt->bindParam(':last_logged_in', $util::now());
		        $stmt->bindParam(':userid', $userid);
		        //$stmt->execute(array($util::now(), $userid));
		        $stmt->execute();
	    }  catch(PDOException $e)  {
	            echo "Trying to update the last logged in field.<br/>";
	            echo $e->getMessage();
	    }
	        //return $logged_in;
	}


	/* ==================================================
		For patients
	================================================== */
	function create_patient_site($whitelabel_code, $uniqueurl)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		// From line 2081
		require_once( '../lib/common/_fake_global.php' );

	   	$acl = new Acl();
	   	$dbopen = new Dbopen();
	   	$matrix = new Matrix();
		$util = new Utilities();	

		$page_name = basename(__FILE__);
		//$full_path = $_SESSION['site_path'] . 'sites/' . $whitelabel_code . '/' . $uniqueurl . '/';
		$full_path = $_SESSION['site_path'] . 'sites/' . $_SESSION['whitelabel_code'] . '/' . $uniqueurl . '/';
		$_SESSION['full_path'] = $full_path;
		
/*
		if ( ! file_exists( $full_path )) {
			mkdir($full_path);
			$robots = fopen($full_path . 'robots.txt', 'w') or die("can't open file");

			$line = 'User-agent: *' . "\n";
			fwrite($robots, $line);
			$line = 'Disallow: /' . "\n";
			fwrite($robots, $line);
			fclose($robots);
		}

		if ( ! file_exists( $full_path . 'index.php' )) {
			$index = fopen($full_path . 'index.php', 'w') or die("can't open file");

			$line = "<h3>Web site for: $uniqueurl </h3> \n";
			fwrite($index, $line);
			fclose($index);
		}	else 	{
				$index = fopen($full_path . 'index.php', 'w') or die("can't open file");
				$line = "<h3>Web site for: $uniqueurl </h3> \n";
				fwrite($index, $line);
				fclose($index);
		}
*/
		if ( ! file_exists( $full_path )) {
			mkdir($full_path);					// looks like: /var/www/html/mylifeline/sites/mll/joeblow
			mkdir($full_path . 'galleries');	// looks like: /var/www/html/mylifeline/sites/mll/joeblow/galleries
		}

		if ( ! file_exists( $full_path . 'robots.txt' )) {
			copy($_SESSION['site_path'] . 'sites/' . $whitelabel_code . '/robots.txt', $full_path . 'robots.txt');
		}

		if ( ! file_exists( $full_path . 'index.php' )) {
			copy($_SESSION['site_path'] . 'sites/' . $whitelabel_code . '/template.php', $full_path . 'index.php');
		}

	}


	public function create_patient_group($userid, $email, $grouptypeid)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		/*
			When a new patient is successfully created, call create_user_group with the email address of the new user.
			This creates a unique group with the same name as the unique userid (the email address passed in).
			For future reference, any userid who is a member of the group that has the same name as the user name
			is a care coordinator of that patient.
		*/
		$dbopen = new Dbopen();
		$acl = new Acl();
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
	        $sql = "insert into acl_groups ( userid, grouptypeid, groupname, groupdesc ) values( :userid, :grouptypeid, :groupname, :groupdesc )";
			$stmt = $db->prepare($sql);
		        switch ($grouptypeid)	{
		        	case 5:	//care coordinator
						$groupdesc = "This is the patient/owner of group: $email";
					case 6:	//care coordinator
						$groupdesc = "This is the care coordinator group for user: $email";
					break;
					case 7:	//registered guest
						$groupdesc = "This is the registered guest group for user: $email";
					break;
        			default:	//registered guest
        				$groupdesc = "This is the registered guest group for user: $email";
		        }
			//$stmt->bindValue(':groupid', $userid, PDO::PARAM_STR);
			$stmt->bindValue(':userid', $userid, PDO::PARAM_STR);
			$stmt->bindValue(':grouptypeid', $grouptypeid, PDO::PARAM_STR);
			$stmt->bindValue(':groupname', $email, PDO::PARAM_STR);
			$stmt->bindValue(':groupdesc', $groupdesc, PDO::PARAM_STR);
			$stmt->execute();
			
			$affected_rows = $stmt->rowCount();
			
			//Join new patient to their own group in the lookup table.
			//$groupid = $userid;		//Yes, I know it's crazy.
			$groupid = $db->lastInsertId();
			$acl::group_adduser($groupid, $userid);
	      }  catch(PDOException $e)  {
	            echo "this is an error message<br/>";
	            echo $e->getMessage();
	      }
	    if($affected_rows !== false) {
	    	$retval = TRUE;
	    }	else 	{
	    	$retval = FALSE;
	    }
	    return $retval;
	}


	/* ========== READ patient profile ==========
		I see this being used when you are already logged in and want to make a
		profile change.  You will already know your userid number and it will be
		passed into this function like this:
			read_user_profile_info($_SESSION['userid']);
	*/
	public static function read_patient_profile_id($userid)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$dbopen = new Dbopen();
		$retval = "No user with that id was found.";
		$profile_array = array();
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
			$sql1 = "select * from acl_users where userid = :userid";
			$sql2 = "select * from acl_login where userid = :userid";
			$sql3 = "select * from acl_patients where userid = :userid";
			$sql4 = "select * from sites where userid = :userid";
			$sql5 = "select * from list_countries where country_code = :country_code";
			$sql6 = "select * from list_how_heard where howheardid = :howheardid";
			$sql7 = "select * from list_tz where tzid = :timezone";

	        $stmt = $db->prepare($sql1);
	        $stmt->bindValue(':userid', $userid, PDO::PARAM_STR);
	    	$stmt->execute();
			while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
	        	foreach($row as $key => $value)  {
	            	$profile_array[$key] = $value;
	            }
	        }

	        $stmt = $db->prepare($sql2);
	        $stmt->bindValue(':userid', $userid, PDO::PARAM_STR);
	    	$stmt->execute();
	            while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
	               	foreach($row as $key => $value)  {
	               		$profile_array[$key] = $value;
	               }
	            }

	        $stmt = $db->prepare($sql3);
	        $stmt->bindValue(':userid', $userid, PDO::PARAM_STR);
	    	$stmt->execute();
	            while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
	               	foreach($row as $key => $value)  {
	               		$profile_array[$key] = $value;
	               }
	            }

	        $stmt = $db->prepare($sql4);
	        $stmt->bindValue(':userid', $userid, PDO::PARAM_STR);
	    	$stmt->execute();
	            while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
	               	foreach($row as $key => $value)  {
	               		$profile_array[$key] = $value;
	               }
	            }

	        $stmt = $db->prepare($sql5);
	        $stmt->bindValue(':country_code', $profile_array['country_code'], PDO::PARAM_STR);
	    	$stmt->execute();
	            while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
	               	foreach($row as $key => $value)  {
	               		$profile_array[$key] = $value;
	               }
	            }

	        $stmt = $db->prepare($sql6);
	        $stmt->bindValue(':howheardid', $profile_array['howheardid'], PDO::PARAM_STR);
	    	$stmt->execute();
	            while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
	               	foreach($row as $key => $value)  {
	               		$profile_array[$key] = $value;
	               }
	            }

	        $stmt = $db->prepare($sql7);
	        $stmt->bindValue(':timezone', $profile_array['timezone'], PDO::PARAM_STR);
	    	$stmt->execute();
	            while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
	               	foreach($row as $key => $value)  {
	               		$profile_array[$key] = $value;
	               }
	            }

	      }  catch(PDOException $e)  {
	            echo "this is an error message<br/>";
	            echo $e->getMessage();
	      }
	      $_SESSION['firstname'] = $profile_array['firstname'];		//This is displayed as {Username}
	      //$_SESSION['profile_complete_percent'] = $profile_array['profile_complete_percent'];

	      /*
			To keep the form profile.php from erroring with empty indexes, I force values where needed.
	      */
		if( ! isset($profile_array['country_name']) || $profile_array['country_name'] == null)	{
	    	$profile_array['country_name'] = "";
	    }
	    if( ! isset($profile_array['country_code']) || $profile_array['country_code'] == null)	{
	    	$profile_array['country_code'] = "";
	    }
   	    if( ! isset($profile_array['tz_set']) || $profile_array['tz_set'] == null)	{
	    	$profile_array['tz_set'] = "";
	    }



	    return $profile_array;
	}


	public static function read_patient_profile_id_ORIG($userid)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$dbopen = new Dbopen();
		$retval = "No user with that id was found.";
		$profile_array = array();
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
	        $sql = "select u.firstname, u.lastname, u.last_logged_in, u.addr1, u.addr2, u.addr3, u.city, u.region, u.postcode, u.country_code, 
	        		u.birthdate, u.profile_complete_percent, 
	        		h.howheard_name,  
	        		c.country_name, 
	        		l.email,
	        		p.user_pref_subscribe,
	        		p.user_pref_show_msgs,
	        		p.user_pref_show_in_search,
	        		si.banner_text,
	        		si.banner_show,
	        		st.state_name,
	        		tz.timezone,
	        		tz.tz_set
					from acl_users as u, list_countries AS c, list_how_heard as h, acl_login AS l, acl_patients as p, 
						  sites as si, list_states as st, list_tz as tz
					where u.userid = l.userid
					and u.country_code = c.country_code
					and st.state_code = u.region
					and h.howheardid = u.howheardid
					and si.userid = u.userid
					and tz.tzid = u.timezone
					and u.userid = ?
					limit 1";
	        $stmt = $db->prepare($sql);
	        $stmt->execute(array($userid));
	            while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
	            	$retval = NULL;
	               	foreach($row as $key => $value)  {
	               		$profile_array[$key] = $value;
	                	//echo $key . ": $value \n";
	                	//$retval .= $key . "|$value<br/>";
	               }
	            }
	      }  catch(PDOException $e)  {
	            echo "this is an error message<br/>";
	            echo $e->getMessage();
	      }
	      $_SESSION['firstname'] = $profile_array['firstname'];		//This is displayed as {Username}
	      $_SESSION['profile_complete_percent'] = $profile_array['profile_complete_percent'];
	      $_SESSION['tz_set'] = $profile_array['tz_set'];
	      return $profile_array;
	}


	public static function get_country_codes()	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$dbopen = new Dbopen();
		$list_country_codes = array();
		$list_country_codes['US'] = 'United States';	//This puts US at the top of the list.
		$list_country_codes['CA'] = 'Canada';			//This puts Canada 2nd on the list.
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
	        $sql = "select country_code, country_name from list_countries order by country_name";
	        $stmt = $db->prepare($sql);
	        $stmt->execute();
	            while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
	               		$list_country_codes[$row['country_code']] = $row['country_name'];
	            }
	      }  catch(PDOException $e)  {
	            echo $e->getMessage();
	      }
	      return $list_country_codes;
	}


	public static function get_state_codes()	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$dbopen = new Dbopen();
		$list_state_codes = array();
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
	        $sql = "select state_code, state_name from list_states order by stateid";
	        $stmt = $db->prepare($sql);
	        $stmt->execute();
	            while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
	               		$list_state_codes[$row['state_code']] = $row['state_name'];
	            }
	      }  catch(PDOException $e)  {
	            echo $e->getMessage();
	      }
	      return $list_state_codes;
	}


	public static function get_how_heard()	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$dbopen = new Dbopen();
		$list_how_heard = array();
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
	        $sql = "select howheardid, howheard_name from list_how_heard order by howheardid";
	        $stmt = $db->prepare($sql);
	        $stmt->execute();
	            while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
	               		$list_how_heard[$row['howheardid']] = $row['howheard_name'];
	            }
	      }  catch(PDOException $e)  {
	            echo $e->getMessage();
	      }
	      return $list_how_heard;
	}


	public static function get_cancer_types()	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$dbopen = new Dbopen();
		$list_cancer_types = array();
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
	        $sql = "select cancertypeid, cancertypedesc from list_cancer_types order by cancertypeid";
	        $stmt = $db->prepare($sql);
	        $stmt->execute();
	            while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
	               		$list_cancer_types[$row['cancertypeid']] = $row['cancertypedesc'];
	            }
	      }  catch(PDOException $e)  {
	            echo $e->getMessage();
	      }
	      return $list_cancer_types;
	}


	public static function get_treatment_status()	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$dbopen = new Dbopen();
		$list_treatment_status = array();
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
	        $sql = "select treatmentcode, treatmentdesc from list_treatment_status order by treatmentcode";
	        $stmt = $db->prepare($sql);
	        $stmt->execute();
	            while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
	               		$list_treatment_status[$row['treatmentcode']] = $row['treatmentdesc'];
	            }
	      }  catch(PDOException $e)  {
	            echo $e->getMessage();
	      }
	      return $list_treatment_status;
	}


	public static function get_cancer_centers()	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$dbopen = new Dbopen();
		$list_cancer_centers = array();
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
	        $sql = "select cancercenterid, cancercenterdesc from list_cancer_centers order by cancercenterid";
	        $stmt = $db->prepare($sql);
	        $stmt->execute();
	            while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
	               		$list_cancer_centers[$row['cancercenterid']] = $row['cancercenterdesc'];
	            }
	      }  catch(PDOException $e)  {
	            echo $e->getMessage();
	      }
	      return $list_cancer_centers;
	}


	public static function get_profile_cancerinfo($userid)	{
		/*
			This generates the child table displayed in profile.cancer info tab.
		*/
		$cancer_info_array = array();

		$_SESSION['diagnosis_count'] = 0;
		$dbopen = new Dbopen();
	  	try {
	    	$db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	    	$db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
	    	$sql = "select a.diagnosisid, a.cancertypeid, a.diagnosis_date, b.cancertypedesc from lu_patients_cancerinfo as a, 
	    			list_cancer_types as b where a.userid=:userid and b.cancertypeid = a.cancertypeid";
			$stmt = $db->prepare($sql);
			$stmt->bindValue(':userid', $userid, PDO::PARAM_STR);
			$stmt->execute();

	        while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
	           		$_SESSION['diagnosis_count'] += 1;
	           		$cancer_info_array[$_SESSION['diagnosis_count']] = array('diagnosisid' => $row['diagnosisid'], 'cancertypedesc' => $row['cancertypedesc'], 'diagnosis_date' => $row['diagnosis_date']);
	        }
	    }  catch(PDOException $e)  {
	        echo $e->getMessage();
	    }
	    return $cancer_info_array;
	}


	public static function get_site_info($userid)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$dbopen = new Dbopen();
		$site_info = array();
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
	        $sql = "select * from sites where userid=:userid";
	        $stmt = $db->prepare($sql);
	        $stmt->bindValue(':userid', $userid, PDO::PARAM_STR);
	    	$stmt->execute();
	            while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
		            foreach($row as $key => $value)  {
		            	//echo $key . ": $value \n";
		            	$site_info[$key] = $value;
		            }
		        }
	      }  catch(PDOException $e)  {
	            echo $e->getMessage();
	      }
	      return $site_info;
	}


	public function read_patient_profile_id_OLD($userid)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$dbopen = new Dbopen();
		$retval = "No user with that id was found.";
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
	        $rcols = "lastname, firstname, email, screen_name, logged_in, last_logged_in, pw_last_changed";
	        $stmt = $db->prepare("select $rcols from acl_users where userid = ? limit 1");
	        $stmt->execute(array($userid));
	            while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
	            	$retval = NULL;
	               	foreach($row as $key => $value)  {
	                	$$key = $value;
	                	//echo $key . ": $value<br/>";
	                	$retval .= $key . "|$value<br/>";
	               }
	            }
	      }  catch(PDOException $e)  {
	            echo "this is an error message<br/>";
	            echo $e->getMessage();
	      }
      return $retval;
	}


	public function read_patient_profile_name($email)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$dbopen = new Dbopen();
		$retval = "No user with that id was found.";
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
	        $rcols = "lastname, firstname, email, screen_name, logged_in, last_logged_in, pw_last_changed";
	        $stmt = $db->prepare("select $rcols from acl_users where email = :email limit 1");
	        $stmt->execute(array(':email' => $email));
	            while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
	            	$retval = NULL;
	               	foreach($row as $key => $value)  {
	                	$$key = $value;
	                	$retval .= $key . "|$value<br/>";
	               }
	            }
	      }  catch(PDOException $e)  {
	            echo "this is an error message<br/>";
	            echo $e->getMessage();
	      }
      return $retval;
	}


	public function get_whitelabel_id($whitelabelid)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$dbopen = new Dbopen();
		$retval = "Bad WhiteLabel Name";
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
	        $rcols = "whitelabel_code";
	        $stmt = $db->prepare("select $rcols from list_whitelabels where whitelabelid = :whitelabelid limit 1");
	        $stmt->bindValue(':whitelabelid', $whitelabelid, PDO::PARAM_STR);
	        $stmt->execute(array(':whitelabelid' => $whitelabelid));

	            while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
	            	$retval = NULL;
	               	foreach($row as $key => $value)  {
	                	$$key = $value;
	                	//echo $key . ": $value<br/>";
	                	//$retval .= $key . "|$value<br/>";
	                	$retval .= $value;
	               }
	            }
	      }  catch(PDOException $e)  {
	            echo "this is an error message<br/>";
	            echo $e->getMessage();
	      }
      return $retval;
	}

	//public static function test_exist_email($email)	{
	public static function test_exist_email($email)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$dbopen = new Dbopen();
		$util = new Utilities();
		// $util::msg(__FUNCTION__);
		$retval = FALSE;
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
	        $stmt = $db->prepare("select email from acl_login where email=:email limit 1");

			$stmt->bindValue(':email', $email, PDO::PARAM_STR);
	        $stmt->execute(array(	':email' => $email	));
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
	            echo "this is an error message<br/>";
	            echo $e->getMessage();
	      }
      return $retval;
	}


	public static function test_exist_gallery_path($userid, $gallery_path)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$dbopen = new Dbopen();
		$util = new Utilities();
		$retval = FALSE;
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
	        $sql = "select gallery_path from sites_galleries where gallery_path=:gallery_path and userid=:userid";
	        $stmt = $db->prepare($sql);
			$stmt->bindValue(':userid', $userid, PDO::PARAM_STR);
			$stmt->bindValue(':gallery_path', $gallery_path, PDO::PARAM_STR);
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
	            echo $e->getMessage();
	      }
      return $retval;
	}


	public static function test_exist_gallery_display($userid, $gallery_display)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$dbopen = new Dbopen();
		$util = new Utilities();
		$retval = FALSE;
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
	        $sql = "select gallery_display from sites_galleries where gallery_display=:gallery_display and userid=:userid";
	        $stmt = $db->prepare($sql);
			$stmt->bindValue(':userid', $userid, PDO::PARAM_STR);
			$stmt->bindValue(':gallery_display', $gallery_display, PDO::PARAM_STR);
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
	            echo $e->getMessage();
	      }
      return $retval;
	}


	public function test_exist_patient_site($whitelabelid, $user_directory)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		//The whitelabel must be supplied by virtue of how the user is signing up (url) and 
		//the user_directory is the user_directory they are attempting use.
		$dbopen = new Dbopen();
		$retval = FALSE;
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
	        $rcols = "user_directory";
	        $stmt = $db->prepare("select $rcols from acl_users where whitelabelid=:whitelabelid and user_directory=:user_directory limit 1");

	        $stmt->bindValue(':whitelabelid', $whitelabelid, PDO::PARAM_STR);
			$stmt->bindValue(':user_directory', $user_directory, PDO::PARAM_STR);

	        $stmt->execute(array(	':whitelabelid' => $whitelabelid,
									':user_directory' => $user_directory
	        					));
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
	            echo "this is an error message<br/>";
	            echo $e->getMessage();
	      }
      return $retval;
	}


	public static function update_acl_patients($userid, $update_array)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$retval = FALSE;
		$retval = "Could not update the user.";
		$exec_array = NULL;
		$sql = 'update acl_patients set ';
		foreach($update_array as $key => $value)  {
			if($key != 'userid')	{
				$sql .= $key . " = :$key, ";
			}
		}
		$sql = substr($sql,0,-2);	//This removes the comma and trailing space from the sql string.
		$sql .= " where userid =  '$userid'";

		$dbopen = new Dbopen();
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
			$stmt = $db->prepare($sql);

			foreach($update_array as $key => $value)  {
				//echo "key: $key - val: $value <br/>";
				$stmt->bindValue(":$key", $value, PDO::PARAM_INT);
			}

			$stmt->execute();
			$affected_rows = $stmt->rowCount();
	      }  catch(PDOException $e)  {
	            //echo "this is an error message<br/>";
	            echo $e->getMessage();
	      }
	    if(isset($affected_rows))	{
		    if($affected_rows !== false) {
		    	$retval = TRUE;
		    }
		}
	    return $retval;
	}

	public static function update_acl_users($userid, $update_array)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$retval = FALSE;
		$acl = new Acl();
		$dbopen = new Dbopen();
		$util = new Utilities();
		$retval = "Could not update the user.";
		$exec_array = NULL;
		$sql = 'update acl_users set ';
		foreach($update_array as $key => $value)  {
			if($key != 'userid')	{
				$sql .= $key . " = :$key, ";
			}
		}
		$sql = substr($sql,0,-2);	//This removes the comma and trailing space from the sql string.
		$sql .= " where userid =  '$userid'";

		$dbopen = new Dbopen();
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
			$stmt = $db->prepare($sql);

			foreach($update_array as $key => $value)  {
				//echo "key: $key - val: $value <br/>";
				$stmt->bindValue(":$key", $value, PDO::PARAM_INT);
			}

			$stmt->execute();
			$affected_rows = $stmt->rowCount();
	      }  catch(PDOException $e)  {
	            //echo "this is an error message<br/>";
	            echo $e->getMessage();
	      }
	    if(isset($affected_rows))	{
		    if($affected_rows !== false) {
		    	//update profile complete
		    	$_SESSION['profile_complete_percent'] = $acl::get_profile_completion($_SESSION['userid']);
		    	$retval = TRUE;
		    }
		}
	    return $retval;
	}

	public static function update_acl_password($userid, $password, $password_new, $password_confirm)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		//update_acl_password($_SESSION['userid'], $update_acl_password['password'], $update_acl_password['password_new'], $update_acl_password['password_confirm'])
		$retval = FALSE;
		$acl = new Acl();
	   	$dbopen = new Dbopen();
	   	$util = new Utilities();

	   	$salt = $acl::bfSalt(10);
		$pwsalted = $acl::bfEnc($password_new, $salt);
		
    	try {
    		$sql = 'update acl_login set password = :password where userid = :userid';
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
			$stmt = $db->prepare($sql);
			$stmt->bindValue(':userid', $userid, PDO::PARAM_STR);
			$stmt->bindValue(':password', $pwsalted, PDO::PARAM_STR);
			$stmt->execute();
			$affected_rows = $stmt->rowCount();
	      }  catch(PDOException $e)  {
	            echo $e->getMessage();
	      }
	    if(isset($affected_rows))	{
		    if($affected_rows !== false) {
		    	$retval = $acl::update_salt($userid, $salt);
		    }
		}
	    return $retval;
	}


	public static function update_salt($userid, $salt)	{
		//$_SESSION[__METHOD__] = __METHOD__;
	//This is called from update_acl_password().
		$retval = FALSE;
		$acl = new Acl();
	   	$dbopen = new Dbopen();
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
	                  //update acl_login set activated=:activated, groupid=:groupid where userid=:userid
		        $sql = "update acl_salt set salt = :salt where userid = :userid";
				$stmt = $db->prepare($sql);
		        $stmt->bindValue(':userid', $userid, PDO::PARAM_STR);
				$stmt->bindValue(':salt', $salt, PDO::PARAM_STR);
	    	    $stmt->execute();
				$affected_rows = $stmt->rowCount();
	      }  catch(PDOException $e)  {
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


	public static function update_sites($userid, $update_array)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$retval = FALSE;
		$util = new Utilities();
		$retval = "Could not update the user.";
		$exec_array = NULL;
		$sql = 'update sites set ';
		foreach($update_array as $key => $value)  {
			if($key != 'userid')	{
				$sql .= $key . " = :$key, ";
			}
		}
		$sql = substr($sql,0,-2);	//This removes the comma and trailing space from the sql string.
		$sql .= " where userid =  '$userid'";

		$dbopen = new Dbopen();
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
			$stmt = $db->prepare($sql);

			foreach($update_array as $key => $value)  {
				//echo "key: $key - val: $value <br/>";
				$stmt->bindValue(":$key", $value, PDO::PARAM_INT);
			}

			$stmt->execute();
			$affected_rows = $stmt->rowCount();
	      }  catch(PDOException $e)  {
	            //echo "this is an error message<br/>";
	            echo $e->getMessage();
	      }
	    if(isset($affected_rows))	{
		    if($affected_rows !== false) {
		    	$retval = TRUE;
		    }
		}
	    return $retval;
	}


	public static function update_acl_privacy($userid, $update_array)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$retval = FALSE;
		$util = new Utilities();
		$retval = "Could not update the user.";
		$exec_array = NULL;
		$sql = 'update sites set ';
		foreach($update_array as $key => $value)  {
			if($key != 'userid')	{
				$sql .= $key . " = :$key, ";
			}
		}
		$sql = substr($sql,0,-2);	//This removes the comma and trailing space from the sql string.
		$sql .= " where userid =  '$userid'";

		$dbopen = new Dbopen();
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
			$stmt = $db->prepare($sql);

			foreach($update_array as $key => $value)  {
				$stmt->bindValue(":$key", $value, PDO::PARAM_INT);
			}

			$stmt->execute();
			$affected_rows = $stmt->rowCount();
	      }  catch(PDOException $e)  {
	            //echo "this is an error message<br/>";
	            echo $e->getMessage();
	      }
	    if(isset($affected_rows))	{
		    if($affected_rows !== false) {
		    	$retval = TRUE;
		    }
		}
	    return $retval;
	}


	public static function update_show_add($userid, $update_array)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$retval = FALSE;
		$util = new Utilities();
		$retval = "Could not update the user.";
		$exec_array = NULL;
		$sql = 'update sites set ';
		foreach($update_array as $key => $value)  {
			if($key != 'userid')	{
				$sql .= $key . " = :$key, ";
			}
		}
		$sql = substr($sql,0,-2);	//This removes the comma and trailing space from the sql string.
		$sql .= " where userid =  '$userid'";

		$dbopen = new Dbopen();
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
			$stmt = $db->prepare($sql);

			foreach($update_array as $key => $value)  {
				$stmt->bindValue(":$key", $value, PDO::PARAM_INT);
			}

			$stmt->execute();
			$affected_rows = $stmt->rowCount();
	      }  catch(PDOException $e)  {
	            //echo "this is an error message<br/>";
	            echo $e->getMessage();
	      }
	    if(isset($affected_rows))	{
		    if($affected_rows !== false) {
		    	$retval = TRUE;
		    }
		}
	    return $retval;
	}


	/* ========== UPDATE user info ========== DEPRECATED
		example usage to update the spelling of the firstname
		echo $acl::update_user_profile_info($userid, $firstname);
	*/
	//public function update_user_profile_info($userid, $email)	{
	public static function update_patient_profile($userid, $update_array)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$util = new Utilities();
		$retval = "Could not update the user.";
		$exec_array = NULL;
		$sql = 'update acl_users set ';
		foreach($update_array as $key => $value)  {
			if($key != 'userid')	{
				$sql .= $key . " = :$key, ";
			}
		}
		$sql = substr($sql,0,-2);	//This removes the comma and trailing space from the sql string.
		$sql .= " where userid =  '$userid'";

		$dbopen = new Dbopen();
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
			$stmt = $db->prepare($sql);

			foreach($update_array as $key => $value)  {
				echo "key: $key - val: $value <br/>";
				$stmt->bindValue(":$key", $value, PDO::PARAM_INT);
			}

			$stmt->execute();
			$affected_rows = $stmt->rowCount();
	      }  catch(PDOException $e)  {
	            echo "this is an error message<br/>";
	            echo $e->getMessage();
	      }
	    if(isset($affected_rows))	{
		    if($affected_rows !== false) {
		    	$retval = 'Number of rows updated: '. $affected_rows;
		    }
		}
	    return $retval;
	}


	public static function test_query($var)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$dbopen = new Dbopen();
		$util = new Utilities();
		$retval = FALSE;
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
	        $stmt = $db->prepare("select * from z_stored_commands where cmd = :cmd");

			$stmt->bindValue(':cmd', $var, PDO::PARAM_STR);
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
	            echo $e->getMessage();
	      }
      return $retval;
	}


	public function delete_patient_profile($userid, $email)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$dbopen = new Dbopen();
		$retval = "No user with that id was found.";
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );

			$stmt = $db->prepare("delete from acl_users where userid=:userid");
			$stmt->bindValue(':userid', $userid, PDO::PARAM_STR);
			$stmt->execute();
			$affected_rows = $stmt->rowCount();

			$stmt = $db->prepare("delete from acl_groups where groupname=:email");
			$stmt->bindValue(':email', $email, PDO::PARAM_STR);
			$stmt->execute();
			$affected_rows = $stmt->rowCount();

			$stmt = $db->prepare("delete from lu_group_user where userid=:userid");
			$stmt->bindValue(':userid', $userid, PDO::PARAM_STR);
			$stmt->execute();
			$affected_rows = $stmt->rowCount();

	      }  catch(PDOException $e)  {
	            echo "this is an error message<br/>";
	            echo $e->getMessage();
	      }
	    	if($affected_rows !== false) {
	    		$retval = 'Number of rows updated: '. $affected_rows;
	    	}	else 	{
	    		$retval = "Could not update the user.";
	    	}
      return $retval;
	}


	public function get_patient_group($email)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$dbopen = new Dbopen();
		$retval = "group $email was not found.";
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
	        $rcols = "groupid";
	        $stmt = $db->prepare("select $rcols from acl_groups where groupname = ? limit 1");
	        $stmt->execute(array($email));
	            while($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
	            	$retval = NULL;
	               	foreach($row as $key => $value)  {
	                	$$key = $value;
	                	//echo $key . ": $value<br/>";
	                	//$retval .= $key . "|$value<br/>";
	                	$retval .= $value;
	               }
	            }
	      }  catch(PDOException $e)  {
	            echo "this is an error message<br/>";
	            echo $e->getMessage();
	      }
      return $retval;
	}


	/* ==================================================
		For all care coordinators
	================================================== */
	public function create_cc_profile($create_array, $patient_email)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$acl = new Acl();
	   	$dbopen = new Dbopen();
		$util = new Utilities();
		foreach($create_array as $key => $value)  {
			//echo "key: $key --- value: $value<br/>";
			$$key = $value;
		}

		$dbopen = new Dbopen();
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
			$db->beginTransaction();
		        $sql = "insert into acl_users (
		        		  email, lastname, firstname, screen_name, password, logged_in, last_logged_in, pw_last_changed)
		        		values(
		        		  :email, :lastname, :firstname, :screen_name, :password, :logged_in, :last_logged_in, :pw_last_changed)";
				$stmt = $db->prepare($sql);
				$stmt->execute(array(':email' => $email,
									':lastname' => $lastname,
									 ':firstname' => $firstname, 
									 ':screen_name' => $screen_name, 
									 ':password' => $acl::hash_password($password), 
									 ':logged_in' => $logged_in, 
									 ':last_logged_in' => $last_logged_in, 
									 ':pw_last_changed' => $pw_last_changed));
				$affected_rows = $stmt->rowCount();
				$userid = $db->lastInsertId();
			$db->commit();
	      }  catch(PDOException $e)  {
	            echo "this is an error message<br/>";
	            echo $e->getMessage();
	      }
	    if(isset($affected_rows)) {
	    	if($affected_rows !== false) {
		    	$retval = TRUE;
		    		$patient_group = $acl::get_patient_group($patient_email);
		    		//$util::msg("patient group: $patient_group");
		    		$acl::group_adduser(6, $userid);
		    		$acl::group_adduser($patient_group, $userid);
		    }
	    }	else 	{
	    	$retval = FALSE;
	    }
	    return $retval;
	}


	/* ========== DELETE cc profile ==========
		This is to remove a user.  I imagine this will seldom be used.
		You will already know your userid number and it will be
		passed into this function like this:
			delete_user_profile_info($_SESSION['userid']);	
	*/
	public function delete_cc_profile_id($userid)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$dbopen = new Dbopen();
		$retval = "No user with that id was found.";
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );

			$stmt = $db->prepare("delete from acl_users where userid=:userid");
			$stmt->bindValue(':userid', $userid, PDO::PARAM_STR);
			$stmt->execute();
			$affected_rows = $stmt->rowCount();

			$stmt = $db->prepare("delete from lu_group_user where userid=:userid");
			$stmt->bindValue(':userid', $userid, PDO::PARAM_STR);
			$stmt->execute();
			$affected_rows = $stmt->rowCount();

	      }  catch(PDOException $e)  {
	            echo "this is an error message<br/>";
	            echo $e->getMessage();
	      }
	    	if($affected_rows !== false) {
	    		$retval = 'Number of rows updated: '. $affected_rows;
	    	}	else 	{
	    		$retval = "Could not update the user.";
	    	}
      return $retval;
	}


	public function delete_cc_profile_name($email)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$acl = new Acl();
		$dbopen = new Dbopen();
		$retval = "No user with that id was found.";
		$userid = $acl::get_userid_by_email($email);

    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );

			$stmt = $db->prepare("delete from acl_users where email=:email");
			$stmt->bindValue(':email', $email, PDO::PARAM_STR);
			$stmt->execute();
			$affected_rows = $stmt->rowCount();

			$stmt = $db->prepare("delete from lu_group_user where userid=:userid");
			$stmt->bindValue(':userid', $userid, PDO::PARAM_STR);
			$stmt->execute();
			$affected_rows = $stmt->rowCount();

	      }  catch(PDOException $e)  {
	            echo "this is an error message<br/>";
	            echo $e->getMessage();
	      }
	    	if($affected_rows !== false) {
	    		$retval = 'Number of rows updated: '. $affected_rows;
	    	}	else 	{
	    		$retval = "Could not update the user.";
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


	// RDT - 3/6/2013 - Called from page-signup-val.php
	public static function create_login_patient($email, $password, $groupid, $lastname, $firstname)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$acl = new Acl();
	   	$dbopen = new Dbopen();
	   	$util = new Utilities();

    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
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
				$_SESSION['userid'] = $userid;
	      }  catch(PDOException $e)  {
	            echo $e->getMessage();
	      }
	    if($affected_rows !== false) {
	    	$retval = TRUE;
	    	$acl::insert_salt($userid, $email, $salt);
	    	$acl::insert_validation_key($userid, $email, $groupid);
	    		if( ! isset($_SESSION['whitelabel_code']))	{
					$_SESSION['whitelabel_code'] = 'mll';
					$_SESSION['whitelabelid'] = 10;
					if(empty($_SESSION['whitelabel_code']))	{
						$_SESSION['whitelabel_code'] = 'mll';
						$_SESSION['whitelabelid'] = 10;
					}
				}
	    	$acl::create_login_part2($userid, $lastname, $firstname );
	    	$acl::create_patient_site_stub($_SESSION['userid'], $_SESSION['user_directory']);
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


	public function create_login_cc($email, $password, $groupid, $lastname, $firstname, $patient_email, $patient_lastname, $patient_firstname)	{
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
				$_SESSION['userid'] = $userid;
			$db->commit();
	      }  catch(PDOException $e)  {
	            echo $e->getMessage();
	      }
	    if($affected_rows !== false) {
	    	$retval = TRUE;
	    	$acl::insert_salt($userid, $email, $salt);
	    	$acl::insert_validation_key($userid, $email, $groupid);
	    	$acl::create_login_part2($userid, $lastname, $firstname );
	    	$acl::create_patient_site_stub($_SESSION['userid'], $_SESSION['user_directory']);
	    }	else 	{
	    	$retval = FALSE;
	    }

    	try {	//For the patient record.
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
			//$db->beginTransaction();
		        $sql = "insert into acl_login ( email, password, groupid ) values( :email, :password, :groupid )";
				$stmt = $db->prepare($sql);

				$salt = $acl::bfSalt(10);
				$pwsalted = $acl::bfEnc($password, $salt);

				$groupid = 35;	//patient.
		        $stmt->bindValue(':email', $patient_email, PDO::PARAM_STR);
				$stmt->bindValue(':password', $pwsalted, PDO::PARAM_STR);
				$stmt->bindValue(':groupid', $groupid, PDO::PARAM_STR);
	    	    $stmt->execute();
				$affected_rows = $stmt->rowCount();
				$userid = $db->lastInsertId();
			//$db->commit();
	      }  catch(PDOException $e)  {
	            echo $e->getMessage();
	      }
	    if($affected_rows !== false) {
	    	$retval = TRUE;
	    	$acl::insert_salt($userid, $patient_email, $salt);
	    	$acl::insert_validation_key($userid, $patient_email, $groupid);
	    	$acl::create_login_part2($userid, $patient_lastname, $patient_firstname );
	    }	else 	{
	    	$retval = FALSE;
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


	public function create_patient_profile_stub($userid)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$acl = new Acl();
	   	$dbopen = new Dbopen();
		$util = new Utilities();
		$retval = FALSE;
    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
			$db->beginTransaction();
		        $sql = "insert into acl_patients ( userid ) values( :userid )";
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


	public function create_patient_site_stub($userid, $userdirectory)	{
		//$_SESSION[__METHOD__] = __METHOD__;
		$acl = new Acl();
	   	$dbopen = new Dbopen();
		$util = new Utilities();
		$retval = FALSE;

    	try {
	        $db = new PDO($dbopen->dsn, $dbopen->dbuser, $dbopen->dbpwd);
	        $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
	        $sql = "insert into sites (userid, userdirectory) values(:userid, :userdirectory)";
			$stmt = $db->prepare($sql);
			$stmt->bindValue(':userid', $userid, PDO::PARAM_STR);
			$stmt->bindValue(':userdirectory', $userdirectory, PDO::PARAM_STR);
	    	$stmt->execute();
			$affected_rows = $stmt->rowCount();

		    if(isset($affected_rows))	{
		    	if($affected_rows > 0)	{
					if( ! isset($_SESSION['whitelabel_code']))	{
						$_SESSION['whitelabel_code'] = 'mll';
						if(empty($_SESSION['whitelabel_code']))	{
							$_SESSION['whitelabel_code'] = 'mll';
						}
					}
		    		$acl::create_patient_site($_SESSION['whitelabel_code'], $userdirectory);
		    	}
		    }

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
