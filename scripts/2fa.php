<?php

require_once 'functions.php';

/**
 * Generates a cryptographically secure 6-digit 2FA code and stores it in the database.
 */
function generateAndStore2FACode(PDO $pdo, int $user_id) {
    // Generate a random 6-digit code using a cryptographically secure method
    $code = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    
    $hash_code = password_hash($code, PASSWORD_BCRYPT);
    // Set expiration time (e.g., 10 minutes from now)
    $expires_at = date('Y-m-d H:i:s', strtotime('+10 minutes'));
    
    try {
        $resend_count = getResendCount($pdo, $user_id);
        
        // Delete any existing 2FA codes for the user to ensure a single active code
        deleteExisting2FACodes($pdo, $user_id);
        
        // Insert the new 2FA code into the database
        insert2FACode($pdo, $user_id, $hash_code, $expires_at, $resend_count);
        
        return $code;
    } catch (PDOException $e) {
        error_log("Error generating 2FA code for user ID {$user_id}: " . $e->getMessage());
        return false;
    }
}

/**
 * Verifies the provided 2FA code for a user, handling attempts and locking if necessary.
 */
function verify2FACode(PDO $pdo, int $user_id, string $code, int $max_attempts = 5){

    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !verifyCsrfToken($_POST['csrf_token'])) {
        $errors[] = "Invalid CSRF token.";
    }

    try {
        // Fetch the latest 2FA code for the user
        $record = fetchLatest2FACode($pdo, $user_id);
        
        $current_time = new DateTime();
        if ($record) {

            $locked_minutes = checkAndResetLock2FA($pdo, $user_id);

            if($locked_minutes != 0){
                return "Too many failed attempts. Please try again after {$locked_minutes} minutes.";
            }
            else if ($record['attempts'] >= $max_attempts) {

                lock2FA($pdo, $user_id, 30);

                return "Too many failed attempts. Please try again after 30 minutes.";
            }

            // Check if the code matches and is not expired
            if (password_verify($code, $record['code']) && new DateTime() <= new DateTime($record['expires_at'])) {
                // Successful verification, delete the 2FA code
                delete2FACodeById($pdo, $record['id']);
                
                return true;
            } else {
                // Increment the attempt count
                increment2FAAttempts($pdo, $record['id']);
                
                return "Invalid or expired 2FA code.";
            }
        }
        $errors[] = "Invalid or expired 2FA code.";
        return $errors;
    } catch (PDOException $e) {
        $errors[] = "Error verifying 2FA code for user ID {$user_id}: " . $e->getMessage();
        
    }
}

/**
 * Handles the 2FA process for a user, including generating and sending the 2FA code.
 */
function handle2FA(PDO $pdo, int $user_id): array {
    $errors = [];

    // Fetch user details
    $user = fetchUserDetails($pdo, $user_id);
    $user_name = $user['user']['name'];
    $user_email = $user['user']['email'];

    if ($user) {
        // Check resend limits before sending a new code
        $resend_limit_result = check2FAResendLimit($pdo, $user_id);

        if ($resend_limit_result['can_resend']) {
            // Generate 2FA code
            $code = generateAndStore2FACode($pdo, $user_id);

            if ($code) {

                // Send 2FA code via email
                if (send2FACodeEmail($user_email, $code)) {

                    // Update resend_count and last_resend
                    update2FAResendInfo($pdo, $user_id);
                    // Store user ID in session for 2FA verification
                    $_SESSION['2fa_user_id'] = $user_id;
                    $_SESSION['temp_user_name'] = $user_name;

                    // Redirect to 2FA verification page
                    header('Location: verify_2fa.php');
                    exit();
                } else {
                    $errors[] = "Failed to send 2FA code. Please try again.";
                    error_log("Failed to send 2FA email to {$user_email} for user ID {$user_id}.");
                }
            } else {
                $errors[] = "Failed to generate 2FA code. Please try again.";
                error_log("Failed to generate 2FA code for user ID {$user_id}.");
            }
        } else {
            $errors[] = $resend_limit_result['message'];
        }
    } else {
        $errors[] = "User not found.";
        error_log("User ID {$user_id} not found during 2FA handling.");
    }

    return $errors;
}

/**
 * Checks if the user has exceeded the 2FA resend limit and enforces cooldown periods.
 */
function check2FAResendLimit(PDO $pdo, int $user_id): array {
    // Define limits
    $max_resends = 5; // Maximum number of resends allowed
    $resend_cooldown_minutes = 2; // Cooldown period in minutes

    // Fetch the latest 2FA record for the user
    $stmt = $pdo->prepare("SELECT resend_count, last_resend FROM user_2fa WHERE user_id = :user_id ORDER BY id DESC LIMIT 1");
    $stmt->execute([':user_id' => $user_id]);
    $record = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($record) {
        $current_time = new DateTime();
        $last_resend = $record['last_resend'] ? new DateTime($record['last_resend']) : null;

        // Check if the cooldown period has passed
        if ($last_resend) {
            $diff = $current_time->getTimestamp() - $last_resend->getTimestamp();
            if ($diff < ($resend_cooldown_minutes * 60)) {
                $remaining_seconds = ($resend_cooldown_minutes * 60) - $diff;
                $remaining_time = gmdate("i:s", $remaining_seconds);
                return [
                    'can_resend' => false,
                    'message' => "Please wait {$remaining_time} minutes before requesting another 2FA code."
                ];
            }
        }

        // Check if the resend_count has reached the maximum
        if ($record['resend_count'] >= $max_resends) {
            return [
                'can_resend' => false,
                'message' => "You have reached the maximum number of 2FA resend attempts. Please try again in 30 minutes."
            ];
        }

        return [
            'can_resend' => true,
            'message' => "You can resend the 2FA code."
        ];
    }

    // If no record exists, allow resending
    return [
        'can_resend' => true,
        'message' => "You can resend the 2FA code."
    ];
}

/**
 * Updates the resend_count and last_resend timestamp for a user's 2FA record.
 */
function update2FAResendInfo(PDO $pdo, int $user_id): void {
    try {
        // Update the latest 2FA record
        $stmt = $pdo->prepare("
            UPDATE user_2fa 
            SET resend_count = resend_count + 1, last_resend = NOW()
            WHERE user_id = :user_id
            ORDER BY id DESC LIMIT 1
        ");
        $stmt->execute([':user_id' => $user_id]);

        // Log the update action for debugging
    } catch (PDOException $e) {
        error_log("Error updating 2FA resend info for user ID {$user_id}: " . $e->getMessage());
    }
}

/**
 * Checks and resets the 2FA lock status for a user if the lock period has expired.
 */
function checkAndResetLock2FA(PDO $pdo, int $user_id){
    $stmt = $pdo->prepare("SELECT lock_until, resend_count, attempts FROM user_2fa WHERE user_id = :user_id LIMIT 1");
    $stmt->execute([':user_id' => $user_id]);
    $record = $stmt->fetch(PDO::FETCH_ASSOC);
    
    // If a record exists and lock_until is set
    if ($record && !empty($record['lock_until'])) {
        $current_time = new DateTime('now', new DateTimeZone('UTC'));
        $lock_until_time = new DateTime($record['lock_until'], new DateTimeZone('UTC'));
        
        // Compare current time with lock_until
        if ($current_time > $lock_until_time) {
            // Lock period has expired, reset resend_count and lock_until
            reset2FALock($pdo, $user_id);
            return 0;

        } else {
            // Lock is still active
            $remaining_interval = $current_time->diff($lock_until_time);
            
            // Calculate total remaining minutes
            $remaining_minutes = ($remaining_interval->days * 24 * 60) +
                                ($remaining_interval->h * 60) +
                                $remaining_interval->i;
            
            if ($remaining_interval->s > 0) {
                $remaining_minutes += 1; // Round up to the next minute if there are remaining seconds
            }
            
            return $remaining_minutes;
        }
    } 
    return 0;
}

/**
 * Retrieves the current resend count for a user.
 */
function getResendCount(PDO $pdo, int $user_id): int {
    $stmt = $pdo->prepare("SELECT resend_count FROM user_2fa WHERE user_id = :user_id");
    $stmt->execute([':user_id' => $user_id]);
    $resend_count_result = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($resend_count_result) {
        return (int)$resend_count_result['resend_count'];
    } else {
        return 0;
    }
}

/**
 * Deletes all existing 2FA codes for a user.
 */
function deleteExisting2FACodes(PDO $pdo, int $user_id): void {
    $delete_stmt = $pdo->prepare("DELETE FROM user_2fa WHERE user_id = :user_id");
    $delete_stmt->execute([':user_id' => $user_id]);
}

/**
 * Inserts a new 2FA code into the database for a user.
 */
function insert2FACode(PDO $pdo, int $user_id, string $code, string $expires_at, int $resend_count): void {
    $insert_stmt = $pdo->prepare("
        INSERT INTO user_2fa (user_id, code, expires_at, resend_count)
        VALUES (:user_id, :code, :expires_at, :resend_count)
    ");
    $insert_stmt->execute([
        ':user_id'    => $user_id,
        ':code'       => $code,
        ':expires_at' => $expires_at,
        ':resend_count' => $resend_count
    ]);
}

/**
 * Fetches the latest 2FA record for a user.
 */
function fetchLatest2FACode(PDO $pdo, int $user_id): ?array {
    $stmt = $pdo->prepare("
        SELECT id, code, expires_at, attempts
        FROM user_2fa 
        WHERE user_id = :user_id 
        ORDER BY last_resend DESC 
        LIMIT 1
    ");
    $stmt->execute([':user_id' => $user_id]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

/**
 * Deletes a 2FA record by its ID.
 */
function delete2FACodeById(PDO $pdo, int $id): void {
    $delete_stmt = $pdo->prepare("DELETE FROM user_2fa WHERE id = :id");
    $delete_stmt->execute([':id' => $id]);
}

/**
 * Increments the attempt count for a specific 2FA record.
 */
function increment2FAAttempts(PDO $pdo, int $id): void {
    $update_stmt = $pdo->prepare("UPDATE user_2fa SET attempts = attempts + 1 WHERE id = :id");
    $update_stmt->execute([':id' => $id]);
}

/**
 * Locks the 2FA process for a user for a specified number of minutes.
 */
function lock2FA(PDO $pdo, int $user_id, int $minutes): void {
    $stmt = $pdo->prepare("
        UPDATE user_2fa
        SET lock_until = DATE_ADD(NOW(), INTERVAL :minutes MINUTE)
        WHERE user_id = :user_id
    ");
    $stmt->execute([
        ':minutes' => $minutes,
        ':user_id' => $user_id
    ]);
}

/**
 * Resets the lock and attempt counters for a user's 2FA.
 */
function reset2FALock(PDO $pdo, int $user_id): void {
    $reset_stmt = $pdo->prepare("
        UPDATE user_2fa
        SET resend_count = 0,
            lock_until = NULL,
            attempts = 0
        WHERE user_id = :user_id
    ");
    $reset_stmt->execute([':user_id' => $user_id]);
}

/**
 * Handles the process of resending a 2FA code.
 */
function handleResend2FA(PDO $pdo, int $user_id, string $csrf_token): array {
    $errors = [];
    $success = null;

    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !verifyCsrfToken($_POST['csrf_token'])) {
        $errors[] = "Invalid CSRF token.";
        return ['success' => $success, 'errors' => $errors];
    }

    // Reset lock status for 2FA
    checkAndResetLock2FA($pdo, $user_id);

    // If no errors, proceed with resend logic
    if (empty($errors)) {
        // Check resend limits
        $resend_limit_result = check2FAResendLimit($pdo, $user_id);

        if ($resend_limit_result['can_resend']) {
            // Generate and store a new 2FA code
            $code = generateAndStore2FACode($pdo, $user_id);

            if ($code) {
                // Fetch user email
                $stmt = $pdo->prepare("SELECT email FROM users WHERE id = :id LIMIT 1");
                $stmt->execute([':id' => $user_id]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);

                if ($user) {
                    // Send 2FA code via email
                    if (send2FACodeEmail($user['email'], $code)) {
                        // Update resend_count and last_resend
                        update2FAResendInfo($pdo, $user_id);

                        $success = "A new 2FA code has been sent to your email.";
                    } else {
                        $errors[] = "Failed to send 2FA code. Please try again.";
                        error_log("Failed to resend 2FA email to {$user['email']} for user ID {$user_id}.");
                    }
                } else {
                    $errors[] = "User not found.";
                    error_log("User ID {$user_id} not found during resend 2FA.");
                }
            } else {
                $errors[] = "Failed to generate 2FA code. Please try again.";
                error_log("Failed to generate 2FA code for user ID {$user_id} during resend.");
            }
        } else {
            $errors[] = $resend_limit_result['message'];
        }
    }

    return ['success' => $success, 'errors' => $errors];
}
/**
 * Handles 2FA validation and session setup.
 */
function handle2FALogin(PDO $pdo, int $user_id, string $entered_code): array {
    $errors = [];
    $redirect = null;

    // Check and reset lock status for 2FA
    checkAndResetLock2FA($pdo, $user_id);

    // Validate input
    if (empty($entered_code)) {
        $errors[] = "2FA code is required.";
    }

    // If no input errors, verify the 2FA code
    if (empty($errors)) {
        $verification_result = verify2FACode($pdo, $user_id, $entered_code);

        if ($verification_result === true) {
            // Successful verification

            // Fetch user details
            $stmt = $pdo->prepare("SELECT name FROM users WHERE id = :id LIMIT 1");
            $stmt->execute([':id' => $user_id]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user) {
                // Set session variables
                $_SESSION['user_id'] = $user_id;
                $_SESSION['user_name'] = escape($user['name']);

                // Reset login attempts
                resetLoginAttempts($pdo, $user_id);

                // Unset temporary session variables
                unset($_SESSION['2fa_user_id']);
                unset($_SESSION['temp_user_name']);

                // Regenerate session ID to prevent session fixation
                session_regenerate_id(true);

                // Set redirect URL
                $redirect = 'index.php';
            } else {
                $errors[] = "User details could not be retrieved.";
            }
        } else {
            $errors[] = $verification_result;
        }
    }

    return [
        'success' => empty($errors),
        'errors' => $errors,
        'redirect' => $redirect
    ];
}

?>
