-- phpMyAdmin SQL Dump
-- version 3.5.7
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Mar 30, 2013 at 09:24 PM
-- Server version: 5.5.24-log
-- PHP Version: 5.3.13

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `fkap`
--

-- --------------------------------------------------------

--
-- Table structure for table `acl_email`
--

DROP TABLE IF EXISTS `acl_email`;
CREATE TABLE IF NOT EXISTS `acl_email` (
  `emailid` int(11) NOT NULL,
  `email_type` varchar(64) NOT NULL,
  `email_from` varchar(128) NOT NULL,
  `email_subject` varchar(512) NOT NULL,
  `activation_url` varchar(1024) NOT NULL,
  PRIMARY KEY (`emailid`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `acl_email`
--

INSERT INTO `acl_email` (`emailid`, `email_type`, `email_from`, `email_subject`, `activation_url`) VALUES
(1, 'Account Activation', 'activate@codeoften.com', 'account activation infoz', 'http://codeoften.com/action/user_activate.php?validation_key=');

-- --------------------------------------------------------

--
-- Table structure for table `acl_login`
--

DROP TABLE IF EXISTS `acl_login`;
CREATE TABLE IF NOT EXISTS `acl_login` (
  `userid` int(11) NOT NULL AUTO_INCREMENT,
  `email` varchar(128) NOT NULL,
  `password` varchar(512) NOT NULL,
  `activated` tinyint(1) NOT NULL DEFAULT '0' COMMENT 'When they create a new account you have to activate it via an email.  Default is 0=not activated.  When they do activate it via email set it to 1.',
  `date_created` datetime NOT NULL,
  PRIMARY KEY (`userid`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `acl_salt`
--

DROP TABLE IF EXISTS `acl_salt`;
CREATE TABLE IF NOT EXISTS `acl_salt` (
  `userid` int(11) NOT NULL AUTO_INCREMENT,
  `salt` varchar(512) NOT NULL,
  PRIMARY KEY (`userid`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `acl_validate`
--

DROP TABLE IF EXISTS `acl_validate`;
CREATE TABLE IF NOT EXISTS `acl_validate` (
  `userid` int(11) NOT NULL,
  `validation_key` varchar(512) NOT NULL,
  PRIMARY KEY (`userid`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
