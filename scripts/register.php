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
        error_log("Registration Error: " . $e->getMessage());
        return "An error occurred while registering. Please try again later.";
    }
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
 * Check if an email already exists
 */
function emailExists($pdo, $email) {
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
    $stmt->execute([':email' => $email]);
    return $stmt->fetch(PDO::FETCH_ASSOC) !== false;
}

?>