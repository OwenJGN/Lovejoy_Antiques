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
        // Hash the password using BCRYPT
        $hashed_password = password_hash($password, PASSWORD_BCRYPT);

        // Hash the security answers using BCRYPT
        $hashed_answer_1 = password_hash($security_answer_1, PASSWORD_BCRYPT);
        $hashed_answer_2 = password_hash($security_answer_2, PASSWORD_BCRYPT);
        $hashed_answer_3 = password_hash($security_answer_3, PASSWORD_BCRYPT);

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

        // Prepare the INSERT statement for user_security_questions
        $stmt = $pdo->prepare("
            INSERT INTO user_security_questions (user_id, security_question_id, security_answer) 
            VALUES (:user_id, :security_question_id, :security_answer)
        ");

        // Insert Security Question 1
        $stmt->execute([
            ':user_id' => $user_id,
            ':security_question_id' => $security_question_1,
            ':security_answer' => $hashed_answer_1
        ]);

        // Insert Security Question 2
        $stmt->execute([
            ':user_id' => $user_id,
            ':security_question_id' => $security_question_2,
            ':security_answer' => $hashed_answer_2
        ]);

        // Insert Security Question 3
        $stmt->execute([
            ':user_id' => $user_id,
            ':security_question_id' => $security_question_3,
            ':security_answer' => $hashed_answer_3
        ]);

        // Commit the transaction
        $pdo->commit();

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
function fetchSecurityQuestions($pdo) {
    $stmt = $pdo->prepare("SELECT id, question FROM security_questions ORDER BY question ASC");
    $stmt->execute();
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function emailExists($pdo, $email) {
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
    $stmt->execute([':email' => $email]);
    return $stmt->fetch(PDO::FETCH_ASSOC) !== false;
}

function fetchUserSecurityQuestions($pdo, $user_id) {
    
    $stmt = $pdo->prepare("SELECT 
        sq.id AS id,
        sq.question AS question
    FROM 
        security_questions sq
    INNER JOIN 
        user_security_questions usq 
        ON sq.id = usq.security_question_id
    WHERE 
        usq.user_id = :user_id
    ORDER BY 
        sq.id DESC");

    $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
    $stmt->execute();
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}


function fetchUserSecurityAnswers($pdo, $user_id){
    $stmt = $pdo->prepare("SELECT security_answer as hashed_answer FROM user_security_questions WHERE user_id = :user_id ORDER BY security_question_id DESC");

    $stmt->bindParam(':user_id', $user_id, PDO::PARAM_INT);
    $stmt->execute();
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}
function checkSecurityQuestions($pdo, $user_id) {
    $errors = [];
    $success = false;
    if (!isset($_POST['csrf_token']) || !verifyCsrfToken($_POST['csrf_token'])) {
        $errors[] = "Invalid CSRF token.";
        return ['errors' => $errors, 'success' => $success];
    }
    // Fetch stored security questions and hashed answers
    $stored_questions = fetchUserSecurityAnswers($pdo, $user_id);
    
    $security_answer_1 = strtolower(trim($_POST['security_answer_1'] ?? '')); // Lowercased
    $security_answer_2 = strtolower(trim($_POST['security_answer_2'] ?? '')); // Lowercased
    $security_answer_3 = strtolower(trim($_POST['security_answer_3'] ?? '')); // Lowercased

    if (empty($security_answer_1)) {
        $errors[] = "Answer to Security Question 1 is required.";
    } 

    if (empty($security_answer_2)) {
        $errors[] = "Answer to Security Question 2 is required.";
    } 

    if (empty($security_answer_3)) {
        $errors[] = "Answer to Security Question 3 is required.";
    } 

    if(empty($errors)){
        // Iterate through each stored question and verify the corresponding answer
        foreach ($stored_questions as $index => $question) {
            $currentAnswer = '';
            if($index == 0){
                $currentAnswer = $security_answer_1;
            } 
            elseif($index == 1){
                $currentAnswer = $security_answer_2;
            }            
            elseif($index == 2){
                $currentAnswer = $security_answer_3;
            }

            
            // Verify the provided answer against the hashed answer
            if (!password_verify($currentAnswer, $question['hashed_answer'])) {
                // Answer does not match
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

function processNewPassword($pdo, $is_security_questions = false, $user_id = null){
    $errors = [];
    $success = '';

    // CSRF token validation
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

    // Validate password
    if (empty($new_password)) {
        $errors[] = "New password is required.";
    } elseif (strlen($new_password) < 8) {
        $errors[] = "Password must be at least 8 characters long.";
    } elseif (!preg_match('/[A-Z]/', $new_password)) {
        $errors[] = "Password must contain at least one uppercase letter.";
    } elseif (!preg_match('/[a-z]/', $new_password)) {
        $errors[] = "Password must contain at least one lowercase letter.";
    } elseif (!preg_match('/[0-9]/', $new_password)) {
        $errors[] = "Password must contain at least one number.";
    } elseif (!preg_match('/[\W]/', $new_password)) {
        $errors[] = "Password must contain at least one special character.";
    }

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
                $hashed_password = password_hash($new_password, PASSWORD_BCRYPT);

                $update_stmt = $pdo->prepare("
                    UPDATE users 
                    SET password = :password 
                    WHERE id = :user_id
                ");
                $update_stmt->execute([
                    ':password' => $hashed_password,
                    ':user_id' => $user_id
                ]);
            } else {
                // Token-based password reset
                // Fetch the token details
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

                    // Check if the token has expired
                    if ($current_time > $expires_at) {
                        $errors[] = "This password reset link has expired.";
                        $pdo->rollBack();
                        return ['success' => $success, 'errors' => $errors];
                    } else {
                        $user_id = $token_data['user_id'];

                        // Hash the new password using BCRYPT
                        $hashed_password = password_hash($new_password, PASSWORD_BCRYPT);

                        // Update the user's password in the database
                        $update_stmt = $pdo->prepare("
                            UPDATE users 
                            SET password = :password 
                            WHERE id = :user_id
                        ");
                        $update_stmt->execute([
                            ':password' => $hashed_password,
                            ':user_id' => $user_id
                        ]);

                        // Delete the used token to prevent reuse
                        $delete_stmt = $pdo->prepare("
                            DELETE FROM tokens 
                            WHERE token = :token AND type = 'password_reset'
                        ");
                        $delete_stmt->execute([':token' => $token]);
                    }
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
?>