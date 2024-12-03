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
 * Hash data using BCRYPT
 */
function hashData($data) {
    return password_hash($data, PASSWORD_BCRYPT);
}

/**
 * Check security questions and validate answers
 */
function checkSecurityQuestions($pdo, $user_id) {
    $errors = [];
    $success = false;

    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !verifyCsrfToken($_POST['csrf_token'])) {
        $errors[] = "Invalid CSRF token.";
        return ['errors' => $errors, 'success' => $success];
    }

    // Fetch stored security answers
    $stored_answers = fetchUserSecurityAnswers($pdo, $user_id);
    
    // Retrieve and sanitize user-provided answers
    $provided_answers = [
        strtolower(trim($_POST['security_answer_1'] ?? '')),
        strtolower(trim($_POST['security_answer_2'] ?? '')),
        strtolower(trim($_POST['security_answer_3'] ?? ''))
    ];

    // Validate that all answers are provided
    foreach ($provided_answers as $index => $answer) {
        if (empty($answer)) {
            $errors[] = "Answer to Security Question " . ($index + 1) . " is required.";
        }
    }

    if(empty($errors)){
        // Verify each provided answer against the stored hashed answer
        foreach ($stored_answers as $index => $stored) {
            if (!password_verify($provided_answers[$index], $stored['hashed_answer'])) {
                $errors[] = "Incorrect answer to the security question/s.";
                return ['errors' => $errors, 'success' => $success];
            }
        }
    }
    
    // All answers match
    if(empty($errors)){
        $_SESSION['can_reset_password'] = true;
        $success = true;
    }
    return ['errors' => $errors, 'success' => $success];
}


?>
