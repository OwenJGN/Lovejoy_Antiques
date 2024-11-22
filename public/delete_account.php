<?php
// delete_account.php

// Start a secure session
session_start();

// Include necessary files
require_once '../includes/db_connect.php';
require_once '../includes/functions.php';

// Check if the user is logged in
checkAccess('user');

// Initialize variables
$errors = [];
$success = '';

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verify CSRF token
    if (!isset($_POST['csrf_token']) || !verifyCsrfToken($_POST['csrf_token'])) {
        $errors[] = "Invalid CSRF token.";
    }

    // Proceed only if no CSRF errors
    if (empty($errors)) {
        $user_id = $_SESSION['user_id'];

        try {
            // Begin a transaction to ensure atomicity
            $pdo->beginTransaction();

            // Delete related records from other tables
            // Example: Delete evaluation requests
            $stmt = $pdo->prepare("DELETE FROM evaluation_requests WHERE user_id = :user_id");
            $stmt->execute([':user_id' => $user_id]);

            // Example: Delete security questions
            $stmt = $pdo->prepare("DELETE FROM user_security_questions WHERE user_id = :user_id");
            $stmt->execute([':user_id' => $user_id]);

            // Example: Delete tokens
            $stmt = $pdo->prepare("DELETE FROM tokens WHERE user_id = :user_id");
            $stmt->execute([':user_id' => $user_id]);

            // Example: Delete user attempts
            $stmt = $pdo->prepare("DELETE FROM user_attempts WHERE user_id = :user_id");
            $stmt->execute([':user_id' => $user_id]);

            // Finally, delete the user account
            $stmt = $pdo->prepare("DELETE FROM users WHERE id = :user_id");
            $stmt->execute([':user_id' => $user_id]);

            // Commit the transaction
            $pdo->commit();

            // Clear all session variables
            $_SESSION = [];

            // Destroy the session
            session_destroy();

            // Redirect to a confirmation page or homepage with a success message
            session_start(); // Restart session to set the success message
            $_SESSION['success_message'] = "Your account has been successfully deleted.";
            header('Location: index.php');
            exit();
        } catch (PDOException $e) {
            // Rollback the transaction on error
            $pdo->rollBack();
            error_log("Database Error in delete_account.php: " . $e->getMessage());
            $errors[] = "An error occurred while deleting your account. Please try again later.";
        }
    }

    // Store error messages in session and redirect back to the account page
    if (!empty($errors)) {
        $_SESSION['error_message'] = implode("<br>", $errors);
        header('Location: view_account.php');
        exit();
    }
} else {
    // If accessed without POST, redirect to account page
    header('Location: view_account.php');
    exit();
}
?>
