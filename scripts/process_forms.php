<?php
require_once 'functions.php';

/**
 * Helper function to handle rate limiting, token generation, email sending, and attempt updates.
 */
function handleRateLimitingAndSendEmail($pdo, $user, $action_type, $action_label, $token_type, $token_length, $token_expiry, $email_send_function, &$errors, &$success, $email_message_sent) {
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
        $errors[] = "You have reached the maximum number of {$action_label} attempts. Please try again after {$hours} hours and {$minutes} minutes.";
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
                $errors[] = "You have reached the maximum number of {$action_label} attempts. Please try again after 24 hours.";
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
                    $email_sent = call_user_func($email_send_function, $user['email'], $token);
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

/**
 * Process function for resending verification email.
 */
function processResendVerificationForm($pdo, $email) {
    $errors = [];
    $success = '';

    // CSRF token validation
    if (!isset($_POST['csrf_token']) || !verifyCsrfToken($_POST['csrf_token'])) {
        $errors[] = "Invalid CSRF token.";
        return ['errors' => $errors, 'success' => $success];
    }

    // Retrieve and sanitize input
    $email = trim($_POST['email'] ?? '');

    // Validate email format
    if (empty($email)) {
        $errors[] = "Email is required.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Invalid email format.";
    }

    if (empty($errors)) {
        // Action-specific parameters
        $action_type = 'verification';
        $action_label = 'verification';
        $email_message_verified = "Your email is already verified. You can login!";
        $email_message_sent = "A new verification email has been sent to your email address.";
        $email_send_function = 'sendVerificationEmail';
        $token_type = 'verification';
        $token_length = 16;
        $token_expiry = '+24 hours';

        // Fetch user and relevant attempt data
        $stmt = $pdo->prepare("
            SELECT users.id, users.email, users.is_verified, user_attempts.last_attempt, user_attempts.attempts, user_attempts.lock_until 
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

        //Checks is user is verified and handle the user attempts
        if ($user) {
            if ($user['is_verified'] == 1) {
                $success = $email_message_verified;
            } else {
                handleRateLimitingAndSendEmail($pdo, $user, $action_type, $action_label, $token_type, $token_length, $token_expiry, $email_send_function, $errors, $success, $email_message_sent);
            }
        } else {
            $errors[] = "No account found with that email address.";
        }
    }

    return [
        'success' => $success,
        'errors'  => $errors
    ];
}

/**
 * Process function for password reset request.
 */
function processPasswordResetForm($pdo, $email) {
    $errors = [];
    $success = '';

    // CSRF token validation
    if (!isset($_POST['csrf_token']) || !verifyCsrfToken($_POST['csrf_token'])) {
        $errors[] = "Invalid CSRF token.";
        return ['errors' => $errors, 'success' => $success];
    }

    // Retrieve and sanitize input
    $email = trim($_POST['email'] ?? '');

    // Validate email format
    if (empty($email)) {
        $errors[] = "Email is required.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Invalid email format.";
    }

    if (empty($errors)) {
        // Action-specific parameters
        $action_type = 'password_reset';
        $action_label = 'password reset';
        $email_message_sent = "If an account with that email exists, a password reset link has been sent.";
        $email_send_function = 'sendPasswordResetEmail';
        $token_type = 'password_reset';
        $token_length = 32;
        $token_expiry = '+1 hour';

        // Fetch user and relevant attempt data
        $stmt = $pdo->prepare("
            SELECT users.id, users.email, users.is_verified, user_attempts.last_attempt, user_attempts.attempts, user_attempts.lock_until 
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
            handleRateLimitingAndSendEmail($pdo, $user, $action_type, $action_label, $token_type, $token_length, $token_expiry, $email_send_function, $errors, $success, $email_message_sent);
        }

        // For password reset, inform user that email has been sent regardless of account existence
        if(empty($errors)){
             $success = $email_message_sent;
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

    // Validate the pasword
    $errors = validatePassword($password);

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
 * Redirect to a specified URL
 */
function processLoginForm(PDO $pdo): array {
    $errors = [];

    // CSRF token validation
    if (!isset($_POST['csrf_token']) || !verifyCsrfToken($_POST['csrf_token'])) {
        $errors[] = "Invalid CSRF token.";
        return $errors;
    }

    // Retrieve and sanitize inputs
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    // Validate email
    if (empty($email)) {
        $errors[] = "Email is required.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Invalid email format.";
    }

    // Validate password
    if (empty($password)) {
        $errors[] = "Password is required.";
    }

    // Get client IP
    $client_ip = $_SERVER['REMOTE_ADDR'];

    // Initialize user_id and user_name
    $user_id = null;

    // Fetch user details if email is provided
    if (!empty($email)) {
        $stmt = $pdo->prepare("SELECT id, password, is_verified, is_admin, name FROM users WHERE email = :email LIMIT 1");
        $stmt->execute([':email' => $email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($user) {
            $user_id = $user['id'];
        }
    }

    // Fetch login attempt record
    if ($user_id) {
        $stmt = $pdo->prepare("SELECT * FROM user_attempts WHERE user_id = :user_id AND action_type = 'login' LIMIT 1");
        $stmt->execute([':user_id' => $user_id]);
    } else {
        $stmt = $pdo->prepare("SELECT * FROM user_attempts WHERE ip_address = :ip_address AND action_type = 'login' LIMIT 1");
        $stmt->execute([':ip_address' => $client_ip]);
    }
    $attempt_record = $stmt->fetch(PDO::FETCH_ASSOC);

    // Check if account or IP is locked
    if ($attempt_record && $attempt_record['lock_until']) {
        $current_time = new DateTime();
        $lock_until = new DateTime($attempt_record['lock_until']);

        if ($current_time < $lock_until) {
            $remaining = $lock_until->diff($current_time);
            $hours = $remaining->h;
            $minutes = $remaining->i;
            $seconds = $remaining->s;
            $errors[] = "Your account is locked due to multiple failed login attempts. Please try again after {$hours}h {$minutes}m {$seconds}s.";
            return $errors;
        }
    }

    // Determine if CAPTCHA should be shown
    $show_captcha = false;
    if ($attempt_record) {
        if ($attempt_record['attempts'] >= 3 && $attempt_record['attempts'] < 7) {
            $show_captcha = true;
        }
    }

    // If CAPTCHA is required, verify it
    if ($show_captcha) {
        if (empty($_POST['g-recaptcha-response'])) {
            $errors[] = "Please complete the CAPTCHA.";
        } else {
            // Verify CAPTCHA with Google
            $recaptcha_secret = RECAPTCHA_SECRET_KEY;
            $recaptcha_response = $_POST['g-recaptcha-response'];

            $verify_response = file_get_contents("https://www.google.com/recaptcha/api/siteverify?secret={$recaptcha_secret}&response={$recaptcha_response}");
            $response_data = json_decode($verify_response);

            if (!$response_data->success) {
                $errors[] = "CAPTCHA verification failed. Please try again.";
            }
        }
    }

    // If there are any errors up to this point, return them
    if (!empty($errors)) {
        return $errors;
    }

    // Proceed to credential verification
    if ($user_id && isset($user['password'])) {
        if (password_verify($password, $user['password'])) {
            if ($user['is_verified'] != 1) {
                $errors[] = "Your email is not verified. Please verify your email.";
                incrementLoginAttempts($pdo, $user_id, $client_ip, 'login');
                return $errors;
            } else {
                // Credentials are correct, proceed to handle 2FA
                $_SESSION['2fa_user_id'] = $user['name'];
                $_SESSION['is_admin'] = $user['is_admin'];

                $two_fa_errors = handle2FA($pdo, $user_id);
                if (!empty($two_fa_errors)) {
                    // If there are errors in handling 2FA, return them
                    return $two_fa_errors;
                }
            }
        } else {
            // Password is incorrect
            $errors[] = "Invalid email or password.";
            // Increment login attempts
            incrementLoginAttempts($pdo, $user_id, $client_ip, 'login');
            return $errors;
        }
    } else {
        // User does not exist
        $errors[] = "Invalid email or password.";
        // Increment login attempts based on IP
        incrementLoginAttempts($pdo, null, $client_ip, 'login');
        return $errors;
    }

    // Return any accumulated errors
    return $errors;
}

/**
 * Validates the password reset access method.
 */
function processValidateResetAccess(PDO $pdo, string $source, ?string $token): array {
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
                    $_SESSION['reset_token'] = $token; 
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

?>