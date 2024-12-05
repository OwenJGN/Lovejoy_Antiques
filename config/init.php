<?php
/*
* Initial php file run on each page
*/

// Include necessary files
require_once '../scripts/db_connect.php';
require_once '../scripts/session.php';

startSecureSession();

// Set Content Security Policy (CSP) headers
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
$CSP .= "X-Frame-Options: SAMEORIGIN ";
$CSP .= "Referrer-Policy: same-origin ";
$CSP .= "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload ";
$CSP .= "Access-Control-Allow-Origin: localhost/lovejoy-antiques ";
$CSP .= "Access-Control-Allow-Methods: GET, POST ";
$CSP .= "Access-Control-Allow-Headers: Content-Type, Authorization ";

// Set the CSP header
header("Content-Security-Policy: $CSP");

// Regenerate session ID to prevent session fixation
if (!isset($_SESSION['initiated'])) {
    session_regenerate_id(true);
    $_SESSION['initiated'] = true;
}
?>
