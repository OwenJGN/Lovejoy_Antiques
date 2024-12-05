<?php

require_once 'functions.php';

/**
 * Handles the password reset form submission.
 */
function handlePasswordReset(PDO $pdo, bool $is_security_questions, ?int $user_id, ?string $token): array {
    // Process new password based on the access method
    if ($is_security_questions) {
        return processNewPassword($pdo, $is_security_questions, $user_id);
    } elseif (!empty($token)) {
        return processNewPassword($pdo, $is_security_questions, null);
    } else {
        return [
            'success' => '',
            'errors' => ['Invalid password reset access method.']
        ];
    }
}

/**
 * Check the password is not in the common password list
 */
function isCommonPassword(string $password, string $file_path): bool {
    $handle = fopen($file_path, 'r');
    if (!$handle) {
        die("Failed to open weak password file.");
    }

    while (($line = fgets($handle)) !== false) {
        if (trim($line) === $password) {
            fclose($handle); // Close the file before returning
            return true; 
        }
    }

    fclose($handle); // Ensure the file is closed
    return false; 
}

/**
 * Validate password strength
 */
function validatePassword($password) {
    $errors = [];

    // Load the weak password list
    $weak_passwords_file = __DIR__ . '\common_passwords\10-million-passwords.txt';
    if (!file_exists($weak_passwords_file)) {
        $errors[] = "File not found at for common passwords.";
        return $errors;
    }

    $isWeakPassword = isCommonPassword($password, $weak_passwords_file);

    // Check if the password is provided
    if (empty($password)) {
        $errors[] = "New password is required.";
    } elseif (strlen($password) < 8) {
        $errors[] = "Password must be at least 8 characters long.";
    }

    // Check complexity rules
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = "Password must contain at least one uppercase letter.";
    }
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = "Password must contain at least one lowercase letter.";
    }
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = "Password must contain at least one number.";
    }
    if (!preg_match('/[\W]/', $password)) { // \W matches any non-word character (special characters)
        $errors[] = "Password must contain at least one special character.";
    }

    // Check if the password is too common
    if ($isWeakPassword) {
        $errors[] = "Password is too common, try another one.";
    }

    return $errors; 
}
/**
 * Process the new password reset
 */
function processNewPassword($pdo, $is_security_questions = false, $user_id = null){
    $errors = [];
    $success = '';

    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !verifyCsrfToken($_POST['csrf_token'])) {
        $errors[] = "Invalid CSRF token.";
        return ['success' => $success, 'errors' => $errors];
    }

    // Retrieve and sanitize inputs
    $token = $_POST['token'] ?? '';
    $new_password = $_POST['new_password'] ?? '';
    $confirm_new_password = $_POST['confirm_new_password'] ?? '';

    // Determine reset method
    if ($is_security_questions) {
        if (!isset($user_id)) {
            $errors[] = "User identification error.";
            return ['success' => $success, 'errors' => $errors];
        }
    } elseif (!empty($token)) {
    } else {
        $errors[] = "Invalid password reset access method.";
        return ['success' => $success, 'errors' => $errors];
    }

    // Validate the new password
    $password_errors = validatePassword($new_password);
    $errors = array_merge($errors, $password_errors);

    // Confirm new password
    if (empty($confirm_new_password)) {
        $errors[] = "Please confirm your new password.";
    } elseif ($new_password !== $confirm_new_password) {
        $errors[] = "New passwords do not match.";
    }

    // Proceed only if there are no validation errors
    if (empty($errors)) {
        try {
            // Begin a transaction
            $pdo->beginTransaction();

            if ($is_security_questions) {
                // Update password for authenticated user
                updateUserPassword($pdo, $user_id, $new_password);
            } else {
                // Token-based password reset
                $token_data = getTokenData($pdo, $token, 'password_reset');

                if ($token_data) {
                    if (isTokenExpired($token_data['expires_at'])) {
                        $errors[] = "This password reset link has expired.";
                        $pdo->rollBack();
                        return ['success' => $success, 'errors' => $errors];
                    }

                    $user_id = $token_data['user_id'];
                    updateUserPassword($pdo, $user_id, $new_password);

                    // Delete the used token to prevent reuse
                    deleteToken($pdo, $token, 'password_reset');
                } else {
                    $errors[] = "Invalid password reset token.";
                    $pdo->rollBack();
                    return ['success' => $success, 'errors' => $errors];
                }
            }

            // Commit the transaction
            $pdo->commit();

            $success = "Your password has been successfully reset. You can now <a href='login.php'>log in</a> with your new password.";
        } catch (Exception $e) {
            // Rollback the transaction on error
            $pdo->rollBack();
            error_log("Password Reset Error: " . $e->getMessage());
            $errors[] = "An error occurred while resetting your password. Please try again later.";
        }
    }

    return [
        'success' => $success,
        'errors'  => $errors
    ];
}

/**
 * Update user's password in the database
 */
function updateUserPassword($pdo, $user_id, $new_password) {
    $hashed_password = hashData($new_password);
    $update_stmt = $pdo->prepare("
        UPDATE users 
        SET password = :password 
        WHERE id = :user_id
    ");
    $update_stmt->execute([
        ':password' => $hashed_password,
        ':user_id' => $user_id
    ]);
}

?>