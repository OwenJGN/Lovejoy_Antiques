<?php
require_once 'functions.php';

// Start a secure session
function startSecureSession() {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
}
?>
