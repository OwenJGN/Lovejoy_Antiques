<?php
// Start a secure session
session_start();

// Include necessary files
require_once '../includes/db_connect.php';
require_once '../includes/functions.php';


// Set Content Security Policy headers
header("Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline';");

// Regenerate session ID to prevent session fixation
if (!isset($_SESSION['initiated'])) {
    session_regenerate_id(true);
    $_SESSION['initiated'] = true;
}
?>
