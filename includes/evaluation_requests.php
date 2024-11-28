<?php

require_once 'functions.php';
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

?>
