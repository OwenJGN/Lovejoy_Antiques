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