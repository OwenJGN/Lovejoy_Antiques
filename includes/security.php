<?php
require_once 'functions.php';

/**
 * Escape output to prevent XSS
 */
function escape($html) {
    return htmlspecialchars($html, ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8");
}

/**
 * Authenticate user with email and password
 */
function authenticateUser($pdo, $email, $password) {
    try {
        $stmt = $pdo->prepare("SELECT id, name, email, password, is_admin, is_verified FROM users WHERE email = :email");
        $stmt->execute([':email' => $email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            return $user;
        }
    } catch (PDOException $e) {
        error_log("Database Error: " . $e->getMessage());
    }
    return false;
}

/**
 * Validates the password reset access method.
 */
function validateResetAccess(PDO $pdo, string $source, ?string $token): array {
    $errors = [];
    $can_display_form = false;
    $is_security_questions = false;
    $user_id = null;

    if ($source === 'security_questions') {
        // Validate security questions access
        if (isset($_SESSION['can_reset_password']) && $_SESSION['can_reset_password'] === true) {
            $is_security_questions = true;
            $can_display_form = true;
        } else {
            $errors[] = "Unauthorized access to password reset.";
        }
    } elseif (!empty($token)) {
        // Validate token-based access
        try {
            $stmt = $pdo->prepare("
                SELECT user_id, expires_at 
                FROM tokens 
                WHERE token = :token AND type = 'password_reset'
            ");
            $stmt->execute([':token' => $token]);
            $token_data = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($token_data) {
                $current_time = new DateTime();
                $expires_at = new DateTime($token_data['expires_at']);

                if ($current_time > $expires_at) {
                    $errors[] = "This password reset link has expired.";
                } else {
                    $can_display_form = true;
                    $_SESSION['reset_token'] = $token; // Optional for added security
                    $user_id = $token_data['user_id'];
                }
            } else {
                $errors[] = "Invalid password reset token.";
            }
        } catch (Exception $e) {
            error_log("Token Validation Error: " . $e->getMessage());
            $errors[] = "An error occurred while validating your reset token. Please try again later.";
        }
    } else {
        $errors[] = "Invalid password reset access method.";
    }

    return [
        'can_display_form' => $can_display_form,
        'is_security_questions' => $is_security_questions,
        'user_id' => $user_id,
        'errors' => $errors
    ];
}

/**
 * Handles the password reset form submission.
 */
function handlePasswordReset(PDO $pdo, bool $is_security_questions, ?int $user_id, ?string $token): array {
    // Process new password based on the access method
    if ($is_security_questions) {
        return processNewPassword($pdo, $is_security_questions, $user_id, '');
    } elseif (!empty($token)) {
        return processNewPassword($pdo, $is_security_questions, null, $token);
    } else {
        return [
            'success' => '',
            'errors' => ['Invalid password reset access method.']
        ];
    }
}

/**
 * Hash data using BCRYPT
 */
function hashData($data) {
    return password_hash($data, PASSWORD_BCRYPT);
}

/**
 * Validate password strength
 */
function validatePassword($password) {
    $errors = [];
    if (empty($password)) {
        $errors[] = "New password is required.";
    } elseif (strlen($password) < 8) {
        $errors[] = "Password must be at least 8 characters long.";
    } 
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = "Password must contain at least one uppercase letter.";
    }
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = "Password must contain at least one lowercase letter.";
    }
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = "Password must contain at least one number.";
    }
    if (!preg_match('/[\W]/', $password)) {
        $errors[] = "Password must contain at least one special character.";
    }
    return $errors;
}
?>
