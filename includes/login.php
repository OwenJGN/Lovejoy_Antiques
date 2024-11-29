<?php
require_once 'functions.php';

/**
 * Reset login attempts for a user or IP address
 */
function resetLoginAttempts(PDO $pdo, ?int $user_id = null, ?string $ip_address = null){
    try {
        if ($user_id !== null) {
            // Delete user-based login attempts
            $stmt = $pdo->prepare("DELETE FROM user_attempts WHERE user_id = :user_id AND action_type = 'login'");
            $stmt->execute([':user_id' => $user_id]);

            error_log("Login attempts reset for user ID {$user_id}.");
        } elseif ($ip_address !== null) {
            // Delete IP-based login attempts
            $stmt = $pdo->prepare("DELETE FROM user_attempts WHERE ip_address = :ip_address AND action_type = 'login'");
            $stmt->execute([':ip_address' => $ip_address]);

            error_log("Login attempts reset for IP address {$ip_address}.");
        } else {
            error_log("No user ID or IP address provided to resetLoginAttempts.");
        }
    } catch (PDOException $e) {
        error_log("Error resetting login attempts: " . $e->getMessage());
    }
}

/**
 * Increment login attempts for a user or IP address
 */
function incrementLoginAttempts(PDO $pdo, ?int $user_id, string $ip_address, string $action_type = 'login'): void {
    try {
        if ($user_id !== null) {
            handleLoginAttempt($pdo, 'user', $user_id, $action_type, 5, "User ID {$user_id}");
        } else {
            handleLoginAttempt($pdo, 'ip', $ip_address, $action_type, 10, "IP Address {$ip_address}");
        }
    } catch (PDOException $e) {
        error_log("Database Error in incrementLoginAttempts: " . $e->getMessage());
    }
}

/**
 * Handle login attempts for user or IP
 */
function handleLoginAttempt(PDO $pdo, string $type, $identifier, string $action_type, int $threshold, string $log_identifier): void {
    $field = ($type === 'user') ? 'user_id' : 'ip_address';

    // Fetch existing attempt record
    $stmt = $pdo->prepare("SELECT * FROM user_attempts WHERE {$field} = :identifier AND action_type = :action_type LIMIT 1");
    $stmt->execute([
        ':identifier' => $identifier,
        ':action_type' => $action_type
    ]);
    $record = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($record) {
        // Increment attempts
        $new_attempts = $record['attempts'] + 1;
        $update_stmt = $pdo->prepare("UPDATE user_attempts SET attempts = :attempts, last_attempt = NOW() WHERE id = :id");
        $update_stmt->execute([
            ':attempts' => $new_attempts,
            ':id' => $record['id']
        ]);

        // Lock account or IP if attempts exceed threshold
        if ($new_attempts >= $threshold) {
            $lock_duration = '+30 minutes'; // Lock for 30 minutes
            $lock_until = date('Y-m-d H:i:s', strtotime($lock_duration));
            $lock_stmt = $pdo->prepare("UPDATE user_attempts SET lock_until = :lock_until WHERE id = :id");
            $lock_stmt->execute([
                ':lock_until' => $lock_until,
                ':id' => $record['id']
            ]);

            error_log("{$log_identifier} has been locked out until {$lock_until} due to multiple failed login attempts.");
        }
    } else {
        // Create new attempt record
        if ($type === 'user') {
            $insert_stmt = $pdo->prepare("
                INSERT INTO user_attempts (user_id, action_type, attempts, last_attempt)
                VALUES (:user_id, :action_type, 1, NOW())
            ");
            $insert_stmt->execute([
                ':user_id' => $identifier,
                ':action_type' => $action_type
            ]);
        } else {
            $insert_stmt = $pdo->prepare("
                INSERT INTO user_attempts (ip_address, action_type, attempts, last_attempt)
                VALUES (:ip_address, :action_type, 1, NOW())
            ");
            $insert_stmt->execute([
                ':ip_address' => $identifier,
                ':action_type' => $action_type
            ]);
        }
    }
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
    $user_name = null;

    // Fetch user details if email is provided
    if (!empty($email)) {
        $stmt = $pdo->prepare("SELECT id, password, is_verified, is_admin, name FROM users WHERE email = :email LIMIT 1");
        $stmt->execute([':email' => $email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($user) {
            $user_id = $user['id'];
            $user_name = $user['name'];
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
                return $errors;
            } else {
                // Credentials are correct, proceed to handle 2FA
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['user_name'] = $user['name'];
                $_SESSION['is_admin'] = $user['is_admin'];

                $two_fa_errors = handle2FA($pdo, $user_id);
                if (!empty($two_fa_errors)) {
                    // If there are errors in handling 2FA, return them
                    return $two_fa_errors;
                }
                // If handle2FA redirects, the following code won't execute
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
 * Processes login attempts and handles CAPTCHA and 2FA logic.
 */
function processLogin($pdo){
    $errors = processLoginForm($pdo); // Process the login form
    $show_captcha = false;
    $user_id = null;

    // Get the email from the login form
    $email = trim($_POST['email'] ?? '');
    
    if (!empty($email)) {
        // Fetch user ID by email
        $stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
        $stmt->execute([':email' => $email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        $user_id = $user ? $user['id'] : null;
    }

    // Fetch user attempts based on user ID or IP address
    if ($user_id) {
        $stmt = $pdo->prepare("SELECT * FROM user_attempts WHERE user_id = :user_id AND action_type = 'login' LIMIT 1");
        $stmt->execute([':user_id' => $user_id]);
    } else {
        $client_ip = $_SERVER['REMOTE_ADDR'];
        $stmt = $pdo->prepare("SELECT * FROM user_attempts WHERE ip_address = :ip_address AND action_type = 'login' LIMIT 1");
        $stmt->execute([':ip_address' => $client_ip]);
    }
    $attempt_record = $stmt->fetch(PDO::FETCH_ASSOC);

    // Determine if CAPTCHA should be shown
    if ($attempt_record && $attempt_record['attempts'] >= 3 && $attempt_record['attempts'] < 7) {
        $show_captcha = true;
    }

    // Handle 2FA if there are no errors and user ID exists
    if (empty($errors) && $user_id) {
        $two_fa_errors = handle2FA($pdo, $user_id);
        $errors = array_merge($errors, $two_fa_errors);
    }

    return [
        'errors' => $errors,
        'show_captcha' => $show_captcha,
        'user_id' => $user_id
    ];
}
?>