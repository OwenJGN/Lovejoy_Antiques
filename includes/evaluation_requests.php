<?php

require_once 'functions.php';

// Define constants for allowed file types, maximum file size, and allowed contact methods
define('ALLOWED_FILE_TYPES', ['image/jpeg', 'image/png', 'image/gif']);
define('MAX_FILE_SIZE', 2 * 1024 * 1024); // 2MB
define('ALLOWED_CONTACT_METHODS', ['phone', 'email']);

/*
* Get all of the evaluations request for viewing
*/
function fetchEvaluationRequests($pdo) {
    try {
        $stmt = $pdo->prepare("
            SELECT er.id, er.details, er.preferred_contact, er.photo, er.request_date,
                   u.name, u.email, u.phone
            FROM evaluation_requests er
            JOIN users u ON er.user_id = u.id
            ORDER BY er.request_date DESC
        ");
        $stmt->execute();
        $requests = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($requests as &$request) {
            if (!empty($request['photo'])) {
                $filepath = '../public/uploads/' . basename($request['photo']);
                if (file_exists($filepath)) {
                    $encrypted_content = file_get_contents($filepath);
                    if ($encrypted_content !== false) {
                        $decrypted_content = decryptData($encrypted_content);
                        if ($decrypted_content !== false) {
                            // Encode decrypted content to base64
                            $request['decrypted_photo'] = base64_encode($decrypted_content);
                        } else {
                            $request['decrypted_photo'] = null;
                        }
                    } else {
                        $request['decrypted_photo'] = null;
                    }
                } else {
                    $request['decrypted_photo'] = null;
                }
            } else {
                $request['decrypted_photo'] = null;
            }
        }

        return $requests;
    } catch (PDOException $e) {
        error_log("Database Error: " . $e->getMessage());
        return false;
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
    if (empty($preferred_contact)) {
        $errors[] = "Preferred method of contact is required.";
    } elseif (!in_array($preferred_contact, ALLOWED_CONTACT_METHODS)) {
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


?>
