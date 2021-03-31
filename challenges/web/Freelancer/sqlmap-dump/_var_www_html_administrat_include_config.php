<?php
$link = new mysqli("localhost", "db_user", "Str0ngP4ss", "freelancer");
 
// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>
