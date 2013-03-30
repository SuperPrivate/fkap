<?php

class Encrypt_Password {
	public $var = '';

	public static function gen_pass($password)	{
		$salt = Encrypt_Password::bfSalt(10);
		$pwencrypted = Encrypt_Password::bfEnc($password, $salt);
		return $pwsalted;
	}


	public static function bfSalt($cost)	{
	    $chars='./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	    $salt=sprintf('$2a$%02d$', $cost);
	    for($i=0; $i<22; $i++)	{
	    	$salt.=$chars[rand(0,63)];	
	    }
	return $salt;
	}


	public static function bfEnc($ctpw, $salt)	{

	return crypt($ctpw, $salt);
	}


	public static function bfUnEnc($ctpw, $salt)	{

	return crypt($ctpw, $salt);
	}

}

?>
