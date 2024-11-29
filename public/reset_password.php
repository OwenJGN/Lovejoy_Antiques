<?php
// reset_password.php

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
        <h2 class="mb-4">Reset Password</h2>

        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger" role="alert">
                <ul class="mb-0">
                    <?php foreach ($errors as $error): ?>
                        <li><?php echo escape($error); ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php elseif ($success): ?>
            <div class="alert alert-success" role="alert">
                <?php echo escape($success); ?>
            </div>
        <?php endif; ?>

        <?php if ($can_display_form): ?>
            <!-- Password Reset Form -->
            <form action="reset_password.php?source=<?php echo escape($source); ?>&token=<?php echo escape($token); ?>" method="POST" novalidate>
                <!-- CSRF Token -->
                <input type="hidden" name="csrf_token" value="<?php echo escape(generateCsrfToken()); ?>">

                <!-- New Password Field -->
                <div class="mb-3">
                    <label for="new_password" class="form-label">New Password<span class="text-danger">*</span></label>
                    <input type="password" class="form-control" id="new_password" name="new_password" required minlength="8">
                </div>

                <!-- Confirm Password Field -->
                <div class="mb-3">
                    <label for="confirm_password" class="form-label">Confirm Password<span class="text-danger">*</span></label>
                    <input type="password" class="form-control" id="confirm_password" name="confirm_password" required minlength="8">
                </div>

                <button type="submit" class="btn btn-primary">Reset Password</button>
            </form>
        <?php endif; ?>
    </div>
</div>

<?php
require_once 'footer.php';
?>
