<?php
require_once '../includes/db_connect.php'; 
require 'PHPMailer/src/Exception.php';
require 'PHPMailer/src/PHPMailer.php';
require 'PHPMailer/src/SMTP.php';

// Generate CSRF token
function generateCsrfToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

// Verify CSRF token
function verifyCsrfToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// Check if user is logged in
function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

// Check if user is admin
function isAdmin() {
    return isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === 1;
}

// Escape output to prevent XSS
function escape($html) {
    return htmlspecialchars($html, ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8");
}

// Access control function
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

// Fetch evaluation requests (for admin)
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

// Authenticate user
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

// Register user
function registerUser($pdo, $name, $email, $password, $phone, $security_question, $security_answer) {
    try {
        // Check if email already exists
        $stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email");
        $stmt->execute([':email' => $email]);
        if ($stmt->fetch()) {
            return "An account with this email already exists.";
        } else {
            // Hash the password
            $hashed_password = password_hash($password, PASSWORD_BCRYPT);

            // Normalize and hash the security answer
            $normalized_security_answer = mb_strtolower(trim($security_answer));
            $hashed_security_answer = password_hash($normalized_security_answer, PASSWORD_BCRYPT);

            // Insert the new user into the database
            $stmt = $pdo->prepare("
                INSERT INTO users (
                    name, email, password, phone, security_question, security_answer, is_admin, registered_at, is_verified
                ) VALUES (
                    :name, :email, :password, :phone, :security_question, :security_answer, 0, NOW(), 0
                )
            ");
            $stmt->execute([
                ':name' => $name,
                ':email' => $email,
                ':password' => $hashed_password,
                ':phone' => $phone,
                ':security_question' => $security_question,
                ':security_answer' => $hashed_security_answer
            ]);

            // Get the user ID
            $user_id = $pdo->lastInsertId();

            // Generate and store email verification token
            $verification_token = generateAndStoreToken($pdo, $user_id, 'email_verification', 16, '+24 hours');

            if ($verification_token) {
                // Send verification email
                sendVerificationEmail($email, $verification_token);
            } else {
                // Handle token generation failure
                return "An error occurred while generating the verification token.";
            }

            return true;
        }
    } catch (PDOException $e) {
        error_log("Database Error in registerUser: " . $e->getMessage());
        return "An error occurred while registering. Please try again later.";
    }
}



// Submit evaluation request
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

// Handle file upload
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

// Process Login Form
function processLoginForm($pdo) {
    $errors = [];
    // CSRF token validation
    if (!isset($_POST['csrf_token']) || !verifyCsrfToken($_POST['csrf_token'])) {
        $errors[] = "Invalid CSRF token.";
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

    // If no errors, proceed to authenticate the user
    if (empty($errors)) {
        $user = authenticateUser($pdo, $email, $password);
        if($user){
            if ($user['is_verified'] == 1) {
                // Set session variables
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['user_name'] = $user['name'];
                $_SESSION['is_admin'] = $user['is_admin'];

                // Regenerate session ID upon successful login
                session_regenerate_id(true);

                // Redirect to index.php
                header('Location: index.php');
                exit();
            }
            else{
                $errors[] = "Your email is not verified. Please verify your email.";
            }
        }
        else {
            $errors[] = "Invalid email or password.";
        }
    }

    return $errors;
}

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
    $security_question = trim($_POST['security_question'] ?? '');
    $security_answer = trim($_POST['security_answer'] ?? '');

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

    // Validate security question
    if (empty($security_question)) {
        $errors[] = "Please select a security question.";
    }

    // Validate security answer
    if (empty($security_answer)) {
        $errors[] = "Please provide an answer to your security question.";
    } elseif (strlen($security_answer) > 255) {
        $errors[] = "Security answer must not exceed 255 characters.";
    }

    // If no errors, proceed to register the user
    if (empty($errors)) {
        // Attempt to register the user
        $result = registerUser($pdo, $name, $email, $password, $phone, $security_question, $security_answer);

        if ($result === true) {
            $success = true;
        } else {
            $errors[] = $result;
        }
    }

    return ['errors' => $errors, 'success' => $success];
}


// Process Evaluation Request Form
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



use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

function sendVerificationEmail($email, $verification_token) {
    // Gmail SMTP credentials
    $mail = new PHPMailer(true);
    try {
        // Server settings
        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com'; // Gmail SMTP server
        $mail->SMTPAuth   = true;
        $mail->Username   = 'lovejoyantiques262924'; // Your Gmail address
        $mail->Password   = 'trfk wbjx etst xgtl'; // Your Gmail App Password
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = 587; // Gmail SMTP port

        // Recipients
        $mail->setFrom('no-reply@lovejoy.antiques.com', 'Lovejoy Antiques'); // Replace with your sender info
        $mail->addAddress($email); // Add a recipient

        // Content
        $mail->isHTML(true);
        $mail->Subject = 'Verify Your Email Address';
        $verification_link = "http://localhost/lovejoy-antiques/public/verify_email.php?token=" . urlencode($verification_token);
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
    }
}


function processResendVerificationForm($pdo, $email) {
    $errors = [];
    $success = '';
    // Validate email format
    if (empty($email)) {
        $errors[] = "Email is required.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Invalid email format.";
    }

    if (empty($errors)) {
        // Check if user exists and is not verified
        $stmt = $pdo->prepare("
            SELECT users.id, users.is_verified, user_attempts.last_attempt, user_attempts.attempts 
            FROM users
            LEFT JOIN user_attempts 
                ON users.id = user_attempts.user_id 
                AND user_attempts.action_type = 'verification'
            WHERE users.email = :email
        ");
        $stmt->execute([':email' => $email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            if ($user['is_verified'] == 1) {
                $errors[] = "Your email is already verified. You can <a href='login.php'>log in</a>.";
            } else {
                // Rate limiting: allow max 3 resend attempts within 24 hours
                $current_time = new DateTime();
                $last_attempt = $user['last_attempt'] ? new DateTime($user['last_attempt']) : null;
                $attempts = $user['attempts'] ?? 0; // Use null coalescing operator in case attempts is NULL

                if ($last_attempt) {
                    $diff = $current_time->diff($last_attempt);
                    $hours_passed = ($diff->days * 24) + $diff->h + (($diff->i > 0 || $diff->s > 0) ? 1 : 0);
                    if ($hours_passed < 24) {
                        if ($attempts >= 3) {
                            $errors[] = "You have reached the maximum number of resend attempts. Please try again after 24 hours.";
                            $stmt = $pdo->prepare("
                                UPDATE user_attempts
                                SET lock_until = :lock_until
                                WHERE user_id = :user_id
                            ");
                            $stmt->execute([
                                ':lock_until'     =>  $current_time->modify('+24 hours')->format('Y-m-d H:i:s'),
                                ':user_id'             => $user['id']
                            ]);
                        }
                    } else {
                        // Reset attempts after 24 hours
                        $attempts = 0;
                    }
                }

                if (empty($errors)) {
                    // Generate a new token (overwrites existing if any)
                    $verification_token = generateAndStoreToken($pdo, $user['id'], 'email_verification', 16, '+24 hours');

                    if (!$verification_token) {
                        $errors[] = "An error occurred while generating the verification token. Please try again later.";
                    } else {
                        // Send verification email
                        sendVerificationEmail($email, $verification_token);
                        $success = "A new verification email has been sent to your email address.";

                        // Update resend attempts in user_attempts table with unique placeholders
                        $stmt = $pdo->prepare("
                            INSERT INTO user_attempts (user_id, action_type, last_attempt, attempts)
                            VALUES (:user_id, 'verification', :current_time_insert, :attempts_insert)
                            ON DUPLICATE KEY UPDATE 
                                last_attempt = :current_time_update,
                                attempts = :attempts_update
                        ");
                        $stmt->execute([
                            ':current_time_insert' => $current_time->format('Y-m-d H:i:s'),
                            ':attempts_insert'     => ($last_attempt && $hours_passed < 24) ? $attempts + 1 : 1,
                            ':current_time_update' => $current_time->format('Y-m-d H:i:s'),
                            ':attempts_update'     => ($last_attempt && $hours_passed < 24) ? $attempts + 1 : 1,
                            ':user_id'             => $user['id']
                        ]);
                    }
                }
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
            WHERE token = :token AND type = 'email_verification'
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

?>
