<?php
/**
 * PDOFunctions - this file provides basic functions to create a PDO connection,
 *                  insert data to a mysql database via that connection,
 *                  and close the connection
 * @author Philip Raath
 * @version 01.15.13
 */

class Dbcred {
    public $dbhost = 'localhost';                           // $dbopen->dbhost
    public $dbuser = 'misterv';                             // $dbopen->dbuser
    public $dbpwd  = 'ip1tyth3f00l';                        // $dbopen->dbpwd
    public $dbname = 'fkap';                                // $dbopen->dbname
    //public $dsn    = 'mysql:host=localhost;dbname=fkap';   // $dbopen->dsn
}


class PDOFunctions{
    
    /**
     *Empty Constructor
     **/
    function __construct(){}

    /**
     *  createNewPDOConnection creates a PDO connection,
     *      sets error mode status,
     *      and sets up exception handing
     *  @param string $host - current host
     *  @param string $dbName - name of database that will be connected to
     *  @param string $user - login title for authorized user
     *  @param string $password - password assigned to $user
     **/
    function createNewPDOConnection($host, $dbName, $user, $password){
        try{
            $db = new PDO('mysql:host='.$host.';
                          dbname='.$dbName.';
                          charset=utf8',
                          $user,
                          $password);
            $db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
        }catch(PDOException $e){
            //echo $e->getMessage();
            echo "I'm sorry, Dave. I'm afraid I can't do that.";  
            file_put_contents('PDOErrors.txt', $e->getMessage(), FILE_APPEND);
        }
        return $db;
    }
    
    /**
     *  close allows user to close a current PDO connection
     *  @param string $db - the database to be closed
     */
    function close($db){
        $db = null;
    }
    
    /**
     *  allows user to insert an array of data into a SQL database
     *  @param array $data - data to be inserted
     *  @param string $db - database into which data will be inserted
     */
    function PDOInsert($data, $db){
        $statement = $db->prepare("INSERT INTO folks (first_name, addr, city)
                                  value(:name, :addr, :city)");
        $statement->execute($data);
    }

    function PDOSelect($data, $db)  {


        $stmt = $db->prepare($sql);

        //$stmt = $db->prepare("select email from acl_login where email=:email limit 1");

            $stmt->bindValue(':email', $email, PDO::PARAM_STR);
            $stmt->execute(array(   ':email' => $email  ));
            $affected_rows = $stmt->rowCount(); 
    }
    
}
    
?>

