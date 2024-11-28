<?php
// Start a secure session
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Include configuration for sensitive data like reCAPTCHA keys
require_once 'config.php';

// Database connection
require_once '../includes/db_connect.php'; 

// Include PHPMailer for sending emails
require 'PHPMailer/src/Exception.php';
require 'PHPMailer/src/PHPMailer.php';
require 'PHPMailer/src/SMTP.php';

// Use PHPMailer namespaces
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

/**
 * Generate CSRF token and store it in session
 */
function generateCsrfToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Verify CSRF token from form submission
 */
function verifyCsrfToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Check if user is logged in
 */
function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

/**
 * Check if user is an admin
 */
function isAdmin() {
    return isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === 1;
}

/**
 * Escape output to prevent XSS
 */
function escape($html) {
    return htmlspecialchars($html, ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8");
}

/**
 * Access control based on user role
 */
function checkAccess($requiredRole = 'user') {
    if (!isLoggedIn()) {
        header('Location: index.php');
        exit();
    }
    if ($requiredRole === 'admin' && !isAdmin()) {
        header('Location: index.php');
        exit();
    }
}

/**
 * Fetch evaluation requests for admin
 */
function fetchEvaluationRequests($pdo) {
    try {
        $stmt = $pdo->prepare("
            SELECT er.id, er.details, er.preferred_contact, er.photo, er.request_date, u.name, u.email, u.phone
            FROM evaluation_requests er
            JOIN users u ON er.user_id = u.id
            ORDER BY er.request_date DESC
        ");
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        error_log("Database Error: " . $e->getMessage());
        return false;
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



/**
 * Submit an evaluation request
 */
function submitEvaluationRequest($pdo, $userId, $details, $preferred_contact, $photo_filename) {
    try {
        $stmt = $pdo->prepare("
            INSERT INTO evaluation_requests (user_id, details, preferred_contact, photo)
            VALUES (:user_id, :details, :preferred_contact, :photo)
        ");

        $stmt->execute([
            ':user_id' => $userId,
            ':details' => $details,
            ':preferred_contact' => $preferred_contact,
            ':photo' => $photo_filename
        ]);

        return $stmt->rowCount() ? true : "Failed to submit your request. Please try again.";
    } catch (PDOException $e) {
        error_log("Database Insertion Error: " . $e->getMessage());
        return "An error occurred while submitting your request. Please try again later.";
    }
}

/**
 * Handle file upload securely
 */
function handleFileUpload($file, &$errors) {
    $photo_filename = null;
    if ($file['error'] !== UPLOAD_ERR_NO_FILE) {
        $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
        $max_size = 2 * 1024 * 1024; // 2MB

        if ($file['error'] !== UPLOAD_ERR_OK) {
            $errors[] = "Error uploading the photo.";
        } elseif (!in_array($file['type'], $allowed_types)) {
            $errors[] = "Invalid file type. Only JPG, PNG, and GIF are allowed.";
        } elseif ($file['size'] > $max_size) {
            $errors[] = "File size exceeds the 2MB limit.";
        } else {
            $ext = pathinfo($file['name'], PATHINFO_EXTENSION);
            $photo_filename = uniqid('photo_', true) . '.' . $ext;
            $destination = '../public/uploads/' . $photo_filename;

            if (!move_uploaded_file($file['tmp_name'], $destination)) {
                $errors[] = "Failed to move uploaded file.";
            }
        }
    }
    return $photo_filename;
}


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
        $stmt = $pdo->prepare("SELECT id, password, is_verified, name FROM users WHERE email = :email LIMIT 1");
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
                // Optionally, you can increment login attempts here
                return $errors;
            } else {
                // Credentials are correct, proceed to handle 2FA
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
 * Process evaluation request form
 */
function processEvaluationRequestForm($pdo, $userId) {
    $errors = [];
    $success = false;

    // CSRF token validation
    if (!isset($_POST['csrf_token']) || !verifyCsrfToken($_POST['csrf_token'])) {
        $errors[] = "Invalid CSRF token.";
    }

    // Retrieve and sanitize inputs
    $details = trim($_POST['details'] ?? '');
    $preferred_contact = $_POST['preferred_contact'] ?? '';

    // Validate 'details'
    if (empty($details)) {
        $errors[] = "Details of the antique are required.";
    } elseif (strlen($details) > 1000) {
        $errors[] = "Details must not exceed 1000 characters.";
    }

    // Validate 'preferred_contact'
    $allowed_contacts = ['phone', 'email'];
    if (empty($preferred_contact)) {
        $errors[] = "Preferred method of contact is required.";
    } elseif (!in_array($preferred_contact, $allowed_contacts)) {
        $errors[] = "Invalid preferred contact method.";
    }

    // Handle photo upload
    $photo_filename = handleFileUpload($_FILES['photo'], $errors);

    // If no errors, proceed to insert into the database
    if (empty($errors)) {
        $result = submitEvaluationRequest($pdo, $userId, $details, $preferred_contact, $photo_filename);
        if ($result === true) {
            $success = true;
            $_POST = []; // Clear the form inputs
        } else {
            $errors[] = $result;
        }
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
 * Send verification email using PHPMailer
 */
function sendVerificationEmail($email, $verification_token) {
    // Create a new PHPMailer instance
    $mail = new PHPMailer(true);
    try {
        // Server settings
        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com'; // Gmail SMTP server
        $mail->SMTPAuth   = true;
        $mail->Username   = 'lovejoyantiques262924'; // Your Gmail address
        $mail->Password   = 'ehfi dtpo fucz jmkl'; // Your Gmail App Password
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = 587; // Gmail SMTP port

        // Recipients
        $mail->setFrom('no-reply@lovejoy.antiques.com', 'Lovejoy Antiques'); // Replace with your sender info
        $mail->addAddress($email); // Add a recipient

        // Content
        $mail->isHTML(true);
        $mail->Subject = 'Verify Your Email Address';
        $verification_link = "http://localhost/lovejoy_antiques/public/verify_email.php?token=" . urlencode($verification_token);
        $mail->Body    = "
            <html>
            <head>
                <title>Verify Your Email Address</title>
            </head>
            <body>
                <p>Thank you for registering! Please click the link below to verify your email address. This link will expire in 24 hours.</p>
                <p><a href='$verification_link'>$verification_link</a></p>
                <p>If you did not register, please ignore this email.</p>
            </body>
            </html>
        ";

        $mail->send();
        // Optionally, log that the email was sent successfully
    } catch (Exception $e) {
        error_log("Verification Email could not be sent to $email. Mailer Error: {$mail->ErrorInfo}");
        return false;
    }
    return true;

}

function sendPasswordResetEmail($email, $reset_token) {
    // Create a new PHPMailer instance
    $mail = new PHPMailer(true);
    try {
        // Server settings
        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com'; // Gmail SMTP server
        $mail->SMTPAuth   = true;
        $mail->Username   = 'lovejoyantiques262924'; // Your Gmail address
        $mail->Password   = 'ehfi dtpo fucz jmkl'; // Your Gmail App Password
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = 587; // Gmail SMTP port

        // Recipients
        $mail->setFrom('no-reply@lovejoy.antiques.com', 'Lovejoy Antiques'); // Replace with your sender info
        $mail->addAddress($email);

        // Content
        $mail->isHTML(true);
        $mail->Subject = 'Password Reset Request';
        $reset_link = "http://localhost/lovejoy_antiques/public/reset_password.php?token=" . urlencode($reset_token);
        $mail->Body    = "
            <html>
            <head>
                <title>Password Reset Request</title>
            </head>
            <body>
                <p>Hello,</p>
                <p>You have requested to reset your password. Please click the link below to proceed:</p>
                <p><a href='$reset_link'>Reset Your Password</a></p>
                <p>This link will expire in 1 hour. If you did not request a password reset, please ignore this email.</p>
                <p>Best regards,<br>Lovejoy Antiques Team</p>
            </body>
            </html>
        ";

        $mail->send();

        // Optionally, log that the email was sent successfully
    } catch (Exception $e) {
        error_log("Password Reset Email could not be sent to $email. Mailer Error: {$mail->ErrorInfo}");
        return false;
    }
    return true;
}

function send2FACodeEmail(string $email, string $code){
    $mail = new PHPMailer(true);
    
    try {
        // Server settings
        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com'; // Gmail SMTP server
        $mail->SMTPAuth   = true;
        $mail->Username   = 'lovejoyantiques262924'; // Your Gmail address
        $mail->Password   = 'ehfi dtpo fucz jmkl'; // Your Gmail App Password
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = 587; // Gmail SMTP port
    
        // Recipients
        $mail->setFrom('no-reply@lovejoy.antiques.com', 'Lovejoy Antiques'); // Replace with your sender info
        $mail->addAddress($email);
    
        // Content
        $mail->isHTML(true);
        $mail->Subject = 'Your 2FA Code for Lovejoy Antiques';
        $mail->Body    = "
            <html>
            <head>
                <title>2FA Code</title>
            </head>
            <body>
                <p>Dear User,</p>
                <p>Your Two-Factor Authentication (2FA) code is: <strong>{$code}</strong></p>
                <p>This code will expire in 10 minutes.</p>
                <p>If you did not attempt to log in, please secure your account immediately.</p>
                <p>Best regards,<br>Lovejoy Antiques Team</p>
            </body>
            </html>
        ";
    
        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log("2FA Email could not be sent to {$email}. Mailer Error: {$mail->ErrorInfo}");
        return false;
    }
}

function generateAndStore2FACode(PDO $pdo, int $user_id) {
    // Generate a random 6-digit code using a cryptographically secure method
    $code = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    
    // Set expiration time (e.g., 10 minutes from now)
    $expires_at = date('Y-m-d H:i:s', strtotime('+10 minutes'));
    
    try {
        $resend_count = $pdo->prepare("SELECT resend_count FROM user_2fa WHERE user_id = :user_id");
        $resend_count->execute([':user_id' => $user_id]);
        $resend_count_result = $resend_count->fetch(PDO::FETCH_ASSOC);

        if ($resend_count_result) {
            $resend_count = (int)$resend_count_result['resend_count'];
        } else {
            $resend_count = 0;
        }
        // Optionally, delete any existing 2FA codes for the user to ensure single active code
        $delete_stmt = $pdo->prepare("DELETE FROM user_2fa WHERE user_id = :user_id");
        $delete_stmt->execute([':user_id' => $user_id]);
        
        // Insert the new 2FA code into the database
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
        
        return $code;
    } catch (PDOException $e) {
        // Log the error for debugging purposes
        error_log("Error generating 2FA code for user ID {$user_id}: " . $e->getMessage());
        return false;
    }
}

function verify2FACode(PDO $pdo, int $user_id, string $code, int $max_attempts = 5){
    try {
        // Fetch the latest 2FA code for the user
        $stmt = $pdo->prepare("
            SELECT id, code, expires_at, attempts
            FROM user_2fa 
            WHERE user_id = :user_id 
            ORDER BY last_resend DESC 
            LIMIT 1
        ");
        $stmt->execute([':user_id' => $user_id]);
        $record = $stmt->fetch(PDO::FETCH_ASSOC);
        
        $current_time = new DateTime();
        if ($record) {

            $locked_minutes = checkAndResetLock($pdo, $user_id);

            if($locked_minutes != 0){
                return "Too many failed attempts. Please try again after {$locked_minutes} minutes.";
            }
            else if ($record['attempts'] >= $max_attempts) {

                $stmt = $pdo->prepare("
                    UPDATE user_2fa
                    SET lock_until = DATE_ADD(NOW(), INTERVAL 30 MINUTE)
                    WHERE user_id = :user_id
                ");
        
                // Execute the statement with the actual user_id value
                $stmt->execute([':user_id' => $user_id]);

                return "Too many failed attempts. Please try again after 30 minutes.";
            }

            // Check if the code matches and is not expired
            if ($record['code'] === $code && new DateTime() <= new DateTime($record['expires_at'])) {
                // Successful verification, delete the 2FA code
                $delete_stmt = $pdo->prepare("DELETE FROM user_2fa WHERE id = :id");
                $delete_stmt->execute([':id' => $record['id']]);
                
                return true;
            } else {
                // Increment the attempt count
                $update_stmt = $pdo->prepare("UPDATE user_2fa SET attempts = attempts + 1 WHERE id = :id");
                $update_stmt->execute([':id' => $record['id']]);
                
                return "Invalid or expired 2FA code.";
            }
        }
        
        return "Invalid or expired 2FA code.";
    } catch (PDOException $e) {
        return "Error verifying 2FA code for user ID {$user_id}: " . $e->getMessage();
    }
}

function handle2FA(PDO $pdo, int $user_id): array {
    $errors = [];

    // Fetch user details
    $stmt = $pdo->prepare("SELECT email, name FROM users WHERE id = :id LIMIT 1");
    $stmt->execute([':id' => $user_id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user) {
        // Check resend limits before sending a new code
        $resend_limit_result = check2FAResendLimit($pdo, $user_id);

        if ($resend_limit_result['can_resend']) {
            // Generate 2FA code
            $code = generateAndStore2FACode($pdo, $user_id);

            if ($code) {

                // Send 2FA code via email
                if (send2FACodeEmail($user['email'], $code)) {

                    // Update resend_count and last_resend
                    update2FAResendInfo($pdo, $user_id);
                    // Store user ID in session for 2FA verification
                    $_SESSION['2fa_user_id'] = $user_id;
                    $_SESSION['temp_user_name'] = $user['name'];

                    // Redirect to 2FA verification page
                    header('Location: verify_2fa.php');
                    exit();
                } else {
                    $errors[] = "Failed to send 2FA code. Please try again.";
                    error_log("Failed to send 2FA email to {$user['email']} for user ID {$user_id}.");
                }
            } else {
                $errors[] = "Failed to generate 2FA code. Please try again.";
                error_log("Failed to generate 2FA code for user ID {$user_id}.");
            }
        } else {
            $errors[] = "You have reached the maximum number of 2FA resend attempts. Please try again in 30 minutes.";
        }
    } else {
        $errors[] = "User not found.";
        error_log("User ID {$user_id} not found during 2FA handling.");
    }

    return $errors;
}
function check2FAResendLimit(PDO $pdo, int $user_id): array {
    // Define limits
    $max_resends = 3; // Maximum number of resends allowed
    $resend_cooldown_minutes = 5; // Cooldown period in minutes

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

function checkAndResetLock(PDO $pdo, int $user_id){

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
            $reset_stmt = $pdo->prepare("
                UPDATE user_2fa
                SET resend_count = 0,
                    lock_until = NULL,
                    attempts = 0
                WHERE user_id = :user_id
            ");
            $reset_stmt->execute([':user_id' => $user_id]);
            
            return 0;

        } else {
            // Lock is still active
            $remaining_interval = $current_time->diff($lock_until_time);
            
            // Calculate total remaining minutes
            $remaining_minutes = ($remaining_interval->days * 24 * 60) +
                                ($remaining_interval->h * 60) +
                                $remaining_interval->i;
            
            // Optionally, include seconds for more precision
            if ($remaining_interval->s > 0) {
                $remaining_minutes += 1; // Round up to the next minute if there are remaining seconds
            }
            
            return $remaining_minutes;
        }
    } 
    return 0;
    
}


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
