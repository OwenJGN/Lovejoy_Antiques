<?php
// Include configuration and database connection
require_once '..\config\config.php';
require_once 'db_connect.php';

// Include all function files
require_once '2fa.php';
require_once 'auth.php';
require_once 'session.php';
require_once 'csrf.php';
require_once 'user.php';
require_once 'email.php';
require_once 'security.php';
require_once 'evaluation_requests.php';
require_once 'process_forms.php';
require_once 'file_upload.php';
require_once 'login.php';
require_once 'register.php';
require_once 'password.php';
require_once 'token.php';
?>
