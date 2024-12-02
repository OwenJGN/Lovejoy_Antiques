<?php
require_once '..\config\config.php';
$host = HOST;
$db   = DB;
$user = USER; 
$pass = PASS; 
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION, 
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,       
    PDO::ATTR_EMULATE_PREPARES   => false,                  
];
try {
     $pdo = new PDO($dsn, $user, $pass, $options);
} catch (PDOException $e) {
     error_log("Database Connection Error: " . $e->getMessage());
     exit('Database connection failed.');
}
?>
