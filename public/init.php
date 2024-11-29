<?php


// Include necessary files
require_once '../includes/db_connect.php';
require_once '../includes/session.php';

startSecureSession();

//Set Content Security Policy headers
//CSP
$CSP = "default-src 'self'; ";
$CSP .= "script-src 'self' https://cdn.jsdelivr.net https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/; ";
$CSP .= "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; ";
$CSP .= "img-src 'self' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/ data:; ";
$CSP .= "frame-src https://www.google.com/recaptcha/; ";
$CSP .= "font-src 'self'; ";
$CSP .= "connect-src 'self'; ";
$CSP .= "object-src 'none'; ";
$CSP .= "base-uri 'self'; ";
$CSP .= "form-action 'self'; ";
$CSP .= "frame-ancestors 'self'; ";

// Set the CSP header
header("Content-Security-Policy: $CSP");

// Regenerate session ID to prevent session fixation
if (!isset($_SESSION['initiated'])) {
    session_regenerate_id(true);
    $_SESSION['initiated'] = true;
}
?>
