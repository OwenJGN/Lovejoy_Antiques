<?php
require_once 'functions.php';

/**
 * Fetch all security questions
 */
function fetchSecurityQuestions($pdo) {
    $stmt = $pdo->prepare("SELECT id, question FROM security_questions ORDER BY question ASC");
    $stmt->execute();
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
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
 * Fetches user details from the database by user ID.
 */
function fetchUserDetails(PDO $pdo, int $user_id): array {
    try {
        // Prepare and execute the SQL statement
        $stmt = $pdo->prepare("SELECT name, email FROM users WHERE id = :id LIMIT 1");
        $stmt->execute([':id' => $user_id]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            // Escape the user data to ensure safety
            $user['name'] = escape($user['name']);
            $user['email'] = escape($user['email']);
            return [
                'success' => true,
                'user' => $user,
                'error' => null
            ];
        } else {
            return [
                'success' => false,
                'user' => null,
                'error' => "User not found."
            ];
        }
    } catch (PDOException $e) {
        // Log the error and return a failure response
        error_log("Database Error: " . $e->getMessage());
        return [
            'success' => false,
            'user' => null,
            'error' => "An error occurred while fetching your account details. Please try again later."
        ];
    }
}

?>
