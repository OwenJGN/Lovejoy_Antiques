<?php
require_once 'functions.php';

/**
 * Check if user is logged in
 */
function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

/**
 * Check if user is an admin
 */
function isAdmin() {
    return isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === 1;
}

/**
 * Access control based on user role
 */
function checkAccess($requiredRole = 'user') {
    if (!isLoggedIn()) {
        header('Location: index.php');
        exit();
    }
    if ($requiredRole === 'admin' && !isAdmin()) {
        header('Location: index.php');
        exit();
    }
}
?>
