<?php
require_once 'functions.php';
/**
 * Escape output to prevent XSS
 */
function escape($html) {
    return htmlspecialchars($html, ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8");
}

function resetLoginAttempts(PDO $pdo, ?int $user_id = null){
    try {
        if ($user_id) {
            // Delete user-based login attempts
            $stmt = $pdo->prepare("DELETE FROM user_attempts WHERE user_id = :user_id AND action_type = 'login'");
            $stmt->execute([':user_id' => $user_id]);

            error_log("Login attempts reset for user ID {$user_id}.");
        }

        else {
            // Delete IP-based login attempts
            $stmt = $pdo->prepare("DELETE FROM user_attempts WHERE ip_address = :ip_address AND action_type = 'login'");
            $stmt->execute([':ip_address' => $ip_address]);

            error_log("Login attempts reset for IP address {$ip_address}.");
        }
    } catch (PDOException $e) {
        error_log("Error resetting login attempts: " . $e->getMessage());
    }
}

function incrementLoginAttempts(PDO $pdo, ?int $user_id, string $ip_address, string $action_type = 'login'): void {
    try {
        if ($user_id) {
            // Fetch existing attempt record
            $stmt = $pdo->prepare("SELECT * FROM user_attempts WHERE user_id = :user_id AND action_type = :action_type LIMIT 1");
            $stmt->execute([
                ':user_id' => $user_id,
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

                // Lock account if attempts exceed threshold (e.g., 5 attempts)
                if ($new_attempts >= 5) {
                    $lock_duration = '+30 minutes'; // Lock for 30 minutes
                    $lock_until = date('Y-m-d H:i:s', strtotime($lock_duration));
                    $lock_stmt = $pdo->prepare("UPDATE user_attempts SET lock_until = :lock_until WHERE id = :id");
                    $lock_stmt->execute([
                        ':lock_until' => $lock_until,
                        ':id' => $record['id']
                    ]);

                    error_log("User ID {$user_id} has been locked out until {$lock_until} due to multiple failed login attempts.");
                }
            } else {
                // Create new attempt record
                $insert_stmt = $pdo->prepare("
                    INSERT INTO user_attempts (user_id, action_type, attempts, last_attempt)
                    VALUES (:user_id, :action_type, 1, NOW())
                ");
                $insert_stmt->execute([
                    ':user_id' => $user_id,
                    ':action_type' => $action_type
                ]);
            }
        } else {
            // Handle attempts based on IP address for non-existing users
            $stmt = $pdo->prepare("SELECT * FROM user_attempts WHERE ip_address = :ip_address AND action_type = :action_type LIMIT 1");
            $stmt->execute([
                ':ip_address' => $ip_address,
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

                // Lock IP if attempts exceed threshold (e.g., 10 attempts)
                if ($new_attempts >= 10) {
                    $lock_duration = '+30 minutes'; // Lock for 30 minutes
                    $lock_until = date('Y-m-d H:i:s', strtotime($lock_duration));
                    $lock_stmt = $pdo->prepare("UPDATE user_attempts SET lock_until = :lock_until WHERE id = :id");
                    $lock_stmt->execute([
                        ':lock_until' => $lock_until,
                        ':id' => $record['id']
                    ]);

                    error_log("IP Address {$ip_address} has been locked out until {$lock_until} due to multiple failed login attempts.");
                }
            } else {
                // Create new attempt record
                $insert_stmt = $pdo->prepare("
                    INSERT INTO user_attempts (ip_address, action_type, attempts, last_attempt)
                    VALUES (:ip_address, :action_type, 1, NOW())
                ");
                $insert_stmt->execute([
                    ':ip_address' => $ip_address,
                    ':action_type' => $action_type
                ]);
            }
        }
    } catch (PDOException $e) {
        error_log("Database Error in incrementLoginAttempts: " . $e->getMessage());
    }
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
?>