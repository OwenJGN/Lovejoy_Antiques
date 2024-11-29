<?php
require_once 'functions.php';

/**
 * Resend verification email with rate limiting
 */
function processResendVerificationOrResetForm($pdo, $email, $action) {
    $errors = [];
    $success = '';

    // Validate email format
    if (empty($email)) {
        $errors[] = "Email is required.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Invalid email format.";
    }

    if (empty($errors)) {
        // Determine action-specific parameters
        if ($action === 'verification') {
            $action_type = 'verification';
            $email_status_check = true; // Check if email is already verified
            $email_message_verified = "Your email is already verified. You can <a href='login.php'>log in</a>.";
            $email_message_sent = "A new verification email has been sent to your email address.";
            $email_send_function = 'sendVerificationEmail';
            $token_type = 'verification';
            $token_length = 16;
            $token_expiry = '+24 hours';
        } elseif ($action === 'password_reset') {
            $action_type = 'password_reset';
            $email_status_check = false; // No need to check verification status
            $email_message_verified = ""; // Not applicable
            $email_message_sent = "A password reset link has been sent to your email address.";
            $email_send_function = 'sendPasswordResetEmail';
            $token_type = 'password_reset';
            $token_length = 32; // Typically longer for security
            $token_expiry = '+1 hour'; // Password reset tokens often have shorter expiry
        }

        // Fetch user and relevant attempt data
        $stmt = $pdo->prepare("
            SELECT users.id, users.is_verified, user_attempts.last_attempt, user_attempts.attempts, user_attempts.lock_until 
            FROM users
            LEFT JOIN user_attempts 
                ON users.id = user_attempts.user_id 
                AND user_attempts.action_type = :action_type
            WHERE users.email = :email
        ");
        $stmt->execute([
            ':action_type' => $action_type,
            ':email' => $email
        ]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            // Handle verification action
            if ($action === 'verification' && $user['is_verified'] == 1) {
                $success = $email_message_verified;
            } else {
                // Rate limiting parameters
                $current_time = new DateTime();
                $last_attempt = $user['last_attempt'] ? new DateTime($user['last_attempt']) : null;
                $lock_until = $user['lock_until'] ? new DateTime($user['lock_until']) : null;
                $attempts = $user['attempts'] ?? 0;

                // Check if user is currently locked out
                if ($lock_until && $current_time < $lock_until) {
                    $remaining = $current_time->diff($lock_until);
                    $hours = $remaining->h + ($remaining->days * 24);
                    $minutes = $remaining->i;
                    $errors[] = "You have reached the maximum number of {$action} attempts. Please try again after {$hours} hours and {$minutes} minutes.";
                } else {
                    // Check if the last attempt was within the rate limiting window (24 hours)
                    $hours_passed = 0;
                    if ($last_attempt) {
                        $diff = $current_time->diff($last_attempt);
                        $hours_passed = ($diff->days * 24) + $diff->h + (($diff->i > 0 || $diff->s > 0) ? 1 : 0);
                    }

                    // Determine if within rate limiting window
                    if ($hours_passed < 24) {
                        if ($attempts >= 3) {
                            // Lock the user out for 24 hours
                            $errors[] = "You have reached the maximum number of {$action} attempts. Please try again after 24 hours.";
                            $stmt = $pdo->prepare("
                                UPDATE user_attempts
                                SET lock_until = :lock_until
                                WHERE user_id = :user_id AND action_type = :action_type
                            ");
                            $lock_until_time = (clone $current_time)->modify('+24 hours')->format('Y-m-d H:i:s');
                            $stmt->execute([
                                ':lock_until' => $lock_until_time,
                                ':user_id' => $user['id'],
                                ':action_type' => $action_type
                            ]);
                        }
                    }

                    if (empty($errors)) {
                        // Generate a new token (overwrites existing if any)
                        $token = generateAndStoreToken($pdo, $user['id'], $token_type, $token_length, $token_expiry);

                        if (!$token) {
                            $errors[] = "An error occurred while generating the token. Please try again later.";
                        } else {
                            // Send the appropriate email
                            if (function_exists($email_send_function)) {
                                $email_sent = call_user_func($email_send_function, $email, $token);
                                if ($email_sent) {
                                    $success = $email_message_sent;
                                } else {
                                    $errors[] = "Failed to send the email. Please try again later.";
                                }
                            } else {
                                $errors[] = "Email sending function not defined.";
                            }

                            // Update resend attempts in user_attempts table
                            $stmt = $pdo->prepare("
                                INSERT INTO user_attempts (user_id, action_type, last_attempt, attempts, lock_until)
                                VALUES (:user_id, :action_type, :current_time_insert, :attempts_insert, NULL)
                                ON DUPLICATE KEY UPDATE 
                                    last_attempt = :current_time_update,
                                    attempts = :attempts_update,
                                    lock_until = NULL
                            ");
                            $new_attempts = ($last_attempt && $hours_passed < 24) ? $attempts + 1 : 1;
                            $stmt->execute([
                                ':user_id' => $user['id'],
                                ':action_type' => $action_type,
                                ':current_time_insert' => $current_time->format('Y-m-d H:i:s'),
                                ':attempts_insert' => $new_attempts,
                                ':current_time_update' => $current_time->format('Y-m-d H:i:s'),
                                ':attempts_update' => $new_attempts
                            ]);
                        }
                    }
                }
            }
        } else {
            if ($action === 'password_reset') {
                // For password reset, inform user that email has been sent regardless of account existence
                // to prevent email enumeration
                $success = "If an account with that email exists, a password reset link has been sent.";
            } else {
                // For verification, inform user that no account exists
                $errors[] = "No account found with that email address.";
            }
        }
    }

    return [
        'success' => $success,
        'errors'  => $errors
    ];
}

/**
 * Process email verification using token
 */
function processEmailVerification($pdo, $token) {
    $errors = [];
    $success = '';

    // Sanitize the token
    $token = trim($token);

    if (empty($token)) {
        $errors[] = "Invalid verification token.";
        return ['success' => $success, 'errors' => $errors];
    }

    try {
        // Retrieve the token record
        $stmt = $pdo->prepare("
            SELECT user_id, expires_at 
            FROM tokens 
            WHERE token = :token AND type = 'verification'
            LIMIT 1
        ");
        $stmt->execute([':token' => $token]);
        $token_record = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($token_record) {
            $current_time = new DateTime();
            $token_expiry = new DateTime($token_record['expires_at']);

            if ($current_time <= $token_expiry) {
                // Update the user's verification status
                $update_stmt = $pdo->prepare("
                    UPDATE users 
                    SET is_verified = 1 
                    WHERE id = :user_id
                ");
                $update_stmt->execute([':user_id' => $token_record['user_id']]);

                // Delete the token to prevent reuse
                $delete_stmt = $pdo->prepare("
                    DELETE FROM tokens 
                    WHERE token = :token
                ");
                $delete_stmt->execute([':token' => $token]);

                $success = "Your email has been verified successfully! You can now <a href='login.php'>log in</a>.";
            } else {
                // Token has expired
                $errors[] = "Verification token has expired. Please <a href='resend_verification.php'>request a new verification email</a>.";
            }
        } else {
            // Invalid token
            $errors[] = "Invalid verification token. Please <a href='resend_verification.php'>request a new verification email</a>.";
        }
    } catch (PDOException $e) {
        error_log("Database Error in processEmailVerification: " . $e->getMessage());
        $errors[] = "An error occurred while verifying your email. Please try again later.";
    }

    return ['success' => $success, 'errors' => $errors];
}

/**
 * Process the registration form
 */
 function processRegistrationForm($pdo) {
    $errors = [];
    $success = false;

    // CSRF token validation
    if (!isset($_POST['csrf_token']) || !verifyCsrfToken($_POST['csrf_token'])) {
        $errors[] = "Invalid CSRF token.";
        return ['errors' => $errors, 'success' => $success];
    }

    // Retrieve and sanitize inputs
    $email = trim($_POST['email'] ?? '');
    $confirm_email = trim($_POST['confirm_email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';
    $name = trim($_POST['name'] ?? '');
    $phone = trim($_POST['phone'] ?? '');

    // Retrieve and sanitize security questions and answers
    $security_question_1 = intval($_POST['security_question_1'] ?? 0);
    $security_answer_1 = strtolower(trim($_POST['security_answer_1'] ?? '')); // Lowercased
    $security_question_2 = intval($_POST['security_question_2'] ?? 0);
    $security_answer_2 = strtolower(trim($_POST['security_answer_2'] ?? '')); // Lowercased
    $security_question_3 = intval($_POST['security_question_3'] ?? 0);
    $security_answer_3 = strtolower(trim($_POST['security_answer_3'] ?? '')); // Lowercased

    // Validate email
    if (empty($email)) {
        $errors[] = "Email is required.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Invalid email format.";
    } elseif ($email !== $confirm_email) {
        $errors[] = "Emails do not match.";
    }

    // Validate password
    if (empty($password)) {
        $errors[] = "Password is required.";
    } elseif (strlen($password) < 8) {
        $errors[] = "Password must be at least 8 characters long.";
    } elseif (!preg_match('/[A-Z]/', $password)) {
        $errors[] = "Password must contain at least one uppercase letter.";
    } elseif (!preg_match('/[a-z]/', $password)) {
        $errors[] = "Password must contain at least one lowercase letter.";
    } elseif (!preg_match('/[0-9]/', $password)) {
        $errors[] = "Password must contain at least one number.";
    } elseif (!preg_match('/[\W]/', $password)) {
        $errors[] = "Password must contain at least one special character.";
    }

    // Confirm password
    if (empty($confirm_password)) {
        $errors[] = "Please confirm your password.";
    } elseif ($password !== $confirm_password) {
        $errors[] = "Passwords do not match.";
    }

    // Validate name
    if (empty($name)) {
        $errors[] = "Name is required.";
    } elseif (strlen($name) > 255) {
        $errors[] = "Name must not exceed 255 characters.";
    }

    // Validate phone
    if (empty($phone)) {
        $errors[] = "Contact telephone number is required.";
    } elseif (!preg_match('/^\+?[0-9\s\-]{7,20}$/', $phone)) {
        $errors[] = "Invalid telephone number format.";
    }

    // Validate security questions
    if ($security_question_1 === 0 || $security_question_2 === 0 || $security_question_3 === 0) {
        $errors[] = "All three security questions must be selected.";
    } else {
        // Ensure all selected questions are distinct
        if ($security_question_1 === $security_question_2 || 
            $security_question_1 === $security_question_3 || 
            $security_question_2 === $security_question_3) {
            $errors[] = "Security questions must be distinct.";
        }
    }

    // Validate security answers
    if (empty($security_answer_1)) {
        $errors[] = "Answer to Security Question 1 is required.";
    } elseif (strlen($security_answer_1) > 255) {
        $errors[] = "Security Answer 1 must not exceed 255 characters.";
    }

    if (empty($security_answer_2)) {
        $errors[] = "Answer to Security Question 2 is required.";
    } elseif (strlen($security_answer_2) > 255) {
        $errors[] = "Security Answer 2 must not exceed 255 characters.";
    }

    if (empty($security_answer_3)) {
        $errors[] = "Answer to Security Question 3 is required.";
    } elseif (strlen($security_answer_3) > 255) {
        $errors[] = "Security Answer 3 must not exceed 255 characters.";
    }

    // If no errors, proceed to register the user
    if (empty($errors)) {
        // Check if email already exists
        if (emailExists($pdo, $email)) {
            $errors[] = "An account with this email already exists.";
            return ['errors' => $errors, 'success' => $success];
        }

        // Attempt to register the user
        $result = registerUser(
            $pdo, 
            $name, 
            $email, 
            $password, 
            $phone, 
            $security_question_1, 
            $security_answer_1, 
            $security_question_2, 
            $security_answer_2, 
            $security_question_3, 
            $security_answer_3
        );

        if ($result === true) {
            $success = true;
        } else {
            $errors[] = $result;
        }
    }

    return ['errors' => $errors, 'success' => $success];
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
 * Generate and store a token (e.g., for email verification)
 */
function generateAndStoreToken($pdo, $user_id, $type, $token_length = 16, $validity_period = '+24 hours') {
    try {
        // Start a transaction to ensure atomicity
        $pdo->beginTransaction();

        // Delete existing tokens of the same type for the user
        $delete_stmt = $pdo->prepare("
            DELETE FROM tokens 
            WHERE user_id = :user_id AND type = :type
        ");
        $delete_stmt->execute([
            ':user_id' => $user_id,
            ':type'    => $type
        ]);

        // Generate a secure random token
        $token = bin2hex(random_bytes($token_length));

        // Calculate expiration time
        $expires_at = date('Y-m-d H:i:s', strtotime($validity_period));

        // Insert the new token into the tokens table
        $insert_stmt = $pdo->prepare("
            INSERT INTO tokens (user_id, token, type, expires_at)
            VALUES (:user_id, :token, :type, :expires_at)
        ");
        $insert_stmt->execute([
            ':user_id'    => $user_id,
            ':token'      => $token,
            ':type'       => $type,
            ':expires_at' => $expires_at
        ]);

        // Commit the transaction
        $pdo->commit();

        return $token;
    } catch (Exception $e) {
        // Roll back the transaction in case of error
        $pdo->rollBack();
        error_log("Error in generateAndStoreToken: " . $e->getMessage());
        return false;
    }
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