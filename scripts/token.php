<?php
require_once 'functions.php';

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