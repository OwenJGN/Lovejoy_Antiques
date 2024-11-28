<?php
require_once 'functions.php';

/**
 * Register a new user
 */
function registerUser($pdo, $name, $email, $password, $phone, 
                      $security_question_1, $security_answer_1, 
                      $security_question_2, $security_answer_2, 
                      $security_question_3, $security_answer_3) {
    try {
        // Hash the password and security answers
        $hashed_password = hashData($password);
        $hashed_answers = [
            hashData($security_answer_1),
            hashData($security_answer_2),
            hashData($security_answer_3)
        ];

        // Begin a transaction
        $pdo->beginTransaction();

        // Insert the user into the users table
        $stmt = $pdo->prepare("
            INSERT INTO users (name, email, password, phone) 
            VALUES (:name, :email, :password, :phone)
        ");
        $stmt->execute([
            ':name' => $name,
            ':email' => $email,
            ':password' => $hashed_password,
            ':phone' => $phone
        ]);

        // Get the inserted user's ID
        $user_id = $pdo->lastInsertId();

        // Insert all security questions
        insertSecurityQuestions($pdo, $user_id, [
            ['id' => $security_question_1, 'answer' => $hashed_answers[0]],
            ['id' => $security_question_2, 'answer' => $hashed_answers[1]],
            ['id' => $security_question_3, 'answer' => $hashed_answers[2]]
        ]);

        // Commit the transaction
        $pdo->commit();

        // Generate and send verification token
        $token = generateAndStoreToken($pdo, $user_id, 'verification', 16, '+24 hours');
        sendVerificationEmail($email, $token);
        
        return true;
    } catch (Exception $e) {
        // Rollback the transaction on error
        $pdo->rollBack();
        // Log the error message (ensure not to expose it to users)
        error_log("Registration Error: " . $e->getMessage());
        return "An error occurred while registering. Please try again later.";
    }
}

/**
 * Fetch all security questions
 */
function fetchSecurityQuestions($pdo) {
    $stmt = $pdo->prepare("SELECT id, question FROM security_questions ORDER BY question ASC");
    $stmt->execute();
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

/**
 * Check if an email already exists
 */
function emailExists($pdo, $email) {
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
    $stmt->execute([':email' => $email]);
    return $stmt->fetch(PDO::FETCH_ASSOC) !== false;
}

/**
 * Fetch user's security questions
 */
function fetchUserSecurityQuestions($pdo, $user_id) {
    $stmt = $pdo->prepare("
        SELECT sq.id AS id, sq.question AS question
        FROM security_questions sq
        INNER JOIN user_security_questions usq 
            ON sq.id = usq.security_question_id
        WHERE usq.user_id = :user_id
        ORDER BY sq.id DESC
    ");

    $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
    $stmt->execute();
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

/**
 * Fetch user's hashed security answers
 */
function fetchUserSecurityAnswers($pdo, $user_id){
    $stmt = $pdo->prepare("
        SELECT security_answer as hashed_answer 
        FROM user_security_questions 
        WHERE user_id = :user_id 
        ORDER BY security_question_id DESC
    ");

    $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
    $stmt->execute();
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
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
    $source = $_POST['source'] ?? '';
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
        // Token-based reset
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
 * Hash data using BCRYPT
 */
function hashData($data) {
    return password_hash($data, PASSWORD_BCRYPT);
}

/**
 * Insert multiple security questions for a user
 */
function insertSecurityQuestions($pdo, $user_id, $questions) {
    $stmt = $pdo->prepare("
        INSERT INTO user_security_questions (user_id, security_question_id, security_answer) 
        VALUES (:user_id, :security_question_id, :security_answer)
    ");
    foreach ($questions as $q) {
        $stmt->execute([
            ':user_id' => $user_id,
            ':security_question_id' => $q['id'],
            ':security_answer' => $q['answer']
        ]);
    }
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

/**
 * Retrieve token data from the database
 */
function getTokenData($pdo, $token, $type) {
    $stmt = $pdo->prepare("
        SELECT user_id, expires_at 
        FROM tokens 
        WHERE token = :token AND type = :type
    ");
    $stmt->execute([':token' => $token, ':type' => $type]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

/**
 * Check if a token has expired
 */
function isTokenExpired($expires_at) {
    $current_time = new DateTime();
    $expiration_time = new DateTime($expires_at);
    return $current_time > $expiration_time;
}

/**
 * Delete a token from the database
 */
function deleteToken($pdo, $token, $type) {
    $delete_stmt = $pdo->prepare("
        DELETE FROM tokens 
        WHERE token = :token AND type = :type
    ");
    $delete_stmt->execute([':token' => $token, ':type' => $type]);
}
?>
