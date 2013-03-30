<?php

    include_once("PDOFunctions.php");
    
    $functions = new PDOFunctions;

    $db = $functions->createNewPDOConnection('localhost', 'test', 'me', 'secret');
    
    $data = array( 'name' => 'Tom', 'addr' => '9 west circle dr', 'city'=>'lakewood' );
    
    $functions->PDOInsert($data, $db);
    
    $functions->close($db);
?>