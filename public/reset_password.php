<?php
// reset_password.php

require_once 'header.php'; // Include your header (HTML head, navigation, etc.)
require_once '../includes/functions.php'; // Include functions.php for processing

// Initialize variables
$errors = [];
$success = '';
$can_display_form = false; // Flag to control form display

$source = $_GET['source'] ?? '';
$token = $_GET['token'] ?? '';

$is_security_questions = false;
$user_id = $_SESSION['user_id'] ?? null; // Assumes user is logged in for security questions

// Determine the source of access
if ($source === 'security_questions') {
    // Verify that the user has successfully passed security questions
    if (isset($_SESSION['can_reset_password']) && $_SESSION['can_reset_password'] === true) {
        $is_security_questions = true;
        $can_display_form = true;
        // Unset the session variable to prevent reuse
    } else {
        // Invalid access attempt
        $errors[] = "Unauthorized access to password reset.";
    }
} elseif (!empty($token)) {
    // Token-based access: Validate the token
    try {
        // Fetch the token details from the database
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
            } else {
                // Token is valid; proceed to show the form
                $can_display_form = true;
                // Optionally, store the token in session for additional security
                $_SESSION['reset_token'] = $token;
            }
        } else {
            $errors[] = "Invalid password reset token.";
        }
    } catch (Exception $e) {
        error_log("Token Validation Error: " . $e->getMessage());
        $errors[] = "An error occurred while validating your reset token. Please try again later.";
    }
} else {
    // Invalid access: Neither source nor token provided
    $errors[] = "Invalid password reset access method.";
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Determine if the reset is via security questions or token
    if ($is_security_questions) {
        $result = processNewPassword($pdo, $is_security_questions, $user_id, '');
    } elseif (!empty($token)) {
        $result = processNewPassword($pdo, $is_security_questions, null, $token);
    } else {
        $result = [
            'success' => '',
            'errors' => ['Invalid password reset access method.']
        ];
    }

    $errors = $result['errors'];
    $success = $result['success'];

    if ($success) {
        unset($_SESSION['can_reset_password']);
        // Redirect to login page with a success message
        header('Location: login.php');
        exit();
    }
}
?>
<!-- Main Content Area -->
<div class="main-content">
    <div class="form-container">
        <h2 class="mb-4">Reset Your Password</h2>

        <!-- Success Message -->
        <?php if (!empty($success)): ?>
            <div class="alert alert-success" role="alert">
                <?php echo $success; ?>
            </div>
        <?php endif; ?>

        <!-- Error Messages -->
        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger" role="alert">
                <ul class="mb-0">
                    <?php foreach ($errors as $error): ?>
                        <li><?php echo escape($error); ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <!-- Password Reset Form -->
        <?php 
        // Display form only if authorized to reset and no critical errors
        if ($can_display_form): 
        ?>
            <form action="reset_password.php<?php echo $is_security_questions ? '?source=security_questions' : (!empty($token) ? '?token=' . urlencode($token) : ''); ?>" method="POST" novalidate>
                <!-- CSRF Token -->
                <input type="hidden" name="csrf_token" value="<?php echo escape(generateCsrfToken()); ?>">

                <!-- Reset Source (for security questions) -->
                <?php if ($is_security_questions): ?>
                    <input type="hidden" name="source" value="security_questions">
                <?php endif; ?>

                <!-- Reset Token (for token-based) -->
                <?php if (!empty($token)): ?>
                    <input type="hidden" name="token" value="<?php echo escape($token); ?>">
                <?php endif; ?>

                <!-- New Password Field -->
                <div class="mb-3">
                    <label for="new_password" class="form-label">New Password<span class="text-danger">*</span></label>
                    <input type="password" class="form-control" id="new_password" name="new_password" required minlength="8">
                    <div class="form-text">
                        Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.
                    </div>
                </div>

                <!-- Confirm New Password Field -->
                <div class="mb-3">
                    <label for="confirm_new_password" class="form-label">Confirm New Password<span class="text-danger">*</span></label>
                    <input type="password" class="form-control" id="confirm_new_password" name="confirm_new_password" required minlength="8">
                </div>
                
                <!-- Submit Button -->
                <button type="submit" class="btn btn-primary">Reset Password</button>
            </form>
        <?php endif; ?>
    </div>
</div>

<?php
require_once 'footer.php'; // Include your footer (closing tags, scripts, etc.)
?>
