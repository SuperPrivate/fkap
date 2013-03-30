-- phpMyAdmin SQL Dump
-- version 3.5.7
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Mar 29, 2013 at 03:59 PM
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
-- Table structure for table `acl_groups`
--

DROP TABLE IF EXISTS `acl_groups`;
CREATE TABLE IF NOT EXISTS `acl_groups` (
  `groupid` int(11) NOT NULL AUTO_INCREMENT,
  `userid` int(11) NOT NULL,
  `grouptypeid` int(11) NOT NULL,
  `groupname` varchar(245) NOT NULL,
  `groupdesc` varchar(1024) NOT NULL,
  PRIMARY KEY (`groupid`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=4 ;

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
  `groupid` int(11) NOT NULL DEFAULT '37' COMMENT 'comes from acl_groups.groupid',
  PRIMARY KEY (`userid`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=7 ;

-- --------------------------------------------------------

--
-- Table structure for table `acl_salt`
--

DROP TABLE IF EXISTS `acl_salt`;
CREATE TABLE IF NOT EXISTS `acl_salt` (
  `userid` int(11) NOT NULL AUTO_INCREMENT,
  `email` varchar(128) NOT NULL,
  `salt` varchar(512) NOT NULL,
  PRIMARY KEY (`userid`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=7 ;

-- --------------------------------------------------------

--
-- Table structure for table `acl_users`
--

DROP TABLE IF EXISTS `acl_users`;
CREATE TABLE IF NOT EXISTS `acl_users` (
  `userid` int(11) NOT NULL,
  `lastname` varchar(32) DEFAULT NULL,
  `firstname` varchar(32) DEFAULT NULL,
  `logged_in` tinyint(1) DEFAULT NULL,
  `last_logged_in` datetime DEFAULT NULL,
  `pw_last_changed` datetime DEFAULT NULL,
  `addr1` varchar(256) DEFAULT NULL,
  `addr2` varchar(256) DEFAULT NULL,
  `addr3` varchar(256) DEFAULT NULL,
  `city` varchar(256) DEFAULT NULL,
  `region` varchar(2) DEFAULT NULL,
  `postcode` varchar(11) DEFAULT NULL,
  `country_code` varchar(4) DEFAULT NULL,
  `primaryphone` varchar(16) DEFAULT NULL,
  `secondaryphone` varchar(16) DEFAULT NULL,
  `gender` int(4) DEFAULT NULL,
  `birthdate` date DEFAULT NULL,
  `profile_complete_percent` int(3) DEFAULT '1' COMMENT 'this is a percent from 1-100 of how much of their profile is filled out.',
  `languageid` int(4) DEFAULT '1' COMMENT '1=English.  Others to follow.  see list_languages table.',
  `timezone` int(11) DEFAULT '9' COMMENT 'This is the same value as list_tz.timezone',
  `recovery_email` varchar(128) DEFAULT NULL,
  PRIMARY KEY (`userid`),
  UNIQUE KEY `userid_2` (`userid`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `acl_users_ext`
--

DROP TABLE IF EXISTS `acl_users_ext`;
CREATE TABLE IF NOT EXISTS `acl_users_ext` (
  `userid` int(11) NOT NULL,
  `browser_short` varchar(64) DEFAULT NULL,
  `browser_full` varchar(1024) DEFAULT NULL,
  `os_info` varchar(512) DEFAULT NULL,
  `remote_ip` varchar(32) DEFAULT NULL,
  `timestamp` datetime DEFAULT NULL,
  PRIMARY KEY (`userid`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `acl_validate`
--

DROP TABLE IF EXISTS `acl_validate`;
CREATE TABLE IF NOT EXISTS `acl_validate` (
  `userid` int(11) NOT NULL,
  `email` varchar(128) NOT NULL,
  `validation_key` varchar(512) NOT NULL,
  `groupid` int(11) NOT NULL DEFAULT '37',
  PRIMARY KEY (`userid`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `z_stored_commands`
--

DROP TABLE IF EXISTS `z_stored_commands`;
CREATE TABLE IF NOT EXISTS `z_stored_commands` (
  `cmd` int(4) NOT NULL,
  `desc` varchar(2048) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Dumping data for table `z_stored_commands`
--

INSERT INTO `z_stored_commands` (`cmd`, `desc`) VALUES
(1, 'ALTER TABLE acl_access AUTO_INCREMENT = 50; ALTER TABLE acl_groups AUTO_INCREMENT = 50;  ALTER TABLE acl_login AUTO_INCREMENT = 50; ALTER TABLE acl_patients AUTO_INCREMENT = 50; ALTER TABLE acl_salt AUTO_INCREMENT = 50; ALTER TABLE acl_users AUTO_INCREMENT = 50;  ALTER TABLE acl_validate AUTO_INCREMENT = 50;  ALTER TABLE lu_group_user AUTO_INCREMENT = 50;'),
(2, 'UPDATE `acl_modules` SET `moduledesc`=concat(''If this is turned off, '', module_name, '' is not available to any user.'')'),
(3, 'delete from acl_login where userid>2; delete from acl_patients where userid>2; delete from acl_salt where userid>2; delete from acl_users where userid>2; delete from acl_users_ext where userid>2; delete from acl_validate where userid>2; delete from sites where userid>2; delete from acl_groups; alter table acl_login auto_increment=3; alter table acl_patients auto_increment=3; alter table acl_salt auto_increment=3; alter table acl_users auto_increment=3; alter table acl_validate auto_increment=3; alter table acl_login auto_increment=3;'),
(4, 'mklink /J mylifeline c:\\wamp\\www\\mylifeline');

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
