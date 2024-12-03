<?php
/*
* Reset password form
*/

require_once 'header.php';
require_once '..\includes\functions.php';
require_once '..\config\config.php';

// Initialize variables
$errors = [];
$success = null;
$can_display_form = false;
$is_security_questions = false;
$user_id = null;

// Validate the reset access method
$source = $_GET['source'] ?? '';
$token = $_GET['token'] ?? '';
$validation_result = validateResetAccess($pdo, $source, $token);

// Extract results from validation
$can_display_form = $validation_result['can_display_form'];
$is_security_questions = $validation_result['is_security_questions'];
$user_id = $validation_result['user_id'];
$errors = array_merge($errors, $validation_result['errors']);

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $can_display_form) {
    // Determine the reset method and process the form
    $reset_result = handlePasswordReset($pdo, $is_security_questions, $user_id, $token);

    // Extract results from form processing
    $errors = array_merge($errors, $reset_result['errors']);
    $success = $reset_result['success'];

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
require_once 'footer.php';
?>
