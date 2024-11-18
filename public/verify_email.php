<?php
// verify_email.php

require_once 'header.php';
require_once '../includes/functions.php'; // Include functions.php for processing

$errors = [];
$success = '';

// Check if accessed via registration (with 'registered' parameter)
if (isset($_GET['registered']) && $_GET['registered'] == '1') {
    $success = "Your account has been created successfully! A verification email has been sent to your email address. Please verify your email to activate your account or <a href='resend_verification.php'>resend verification email</a>.";
}
// Check if accessed via verification link (with 'token' parameter)
elseif (isset($_GET['token'])) { // Changed to elseif to ensure mutual exclusivity
    $verification_token = $_GET['token'];

    // Process the email verification using the function
    $result = processEmailVerification($pdo, $verification_token);

    // Assign results to variables
    $success = $result['success'];
    $errors = $result['errors'];
}
?>
<!-- HTML Output -->
<div class="main-content">
    <div class="form-container">
        <?php if ($success): ?>
            <div class="alert alert-success" role="alert">
                <?php echo $success; ?>
            </div>
        <?php elseif (!empty($errors)): ?> <!-- Changed to elseif to prevent both messages -->
            <div class="alert alert-danger" role="alert">
                <?php foreach ($errors as $error): ?>
                    <p><?php echo $error; ?></p>
                <?php endforeach; ?>
            </div>
        <?php else: ?>
            <!-- Verification Notice After Registration -->
            <div class="alert alert-info" role="alert">
                <p>Please verify your email address by clicking the verification link sent to your email before using the website's functionalities.</p>
                <a href="resend_verification.php" class="btn btn-secondary">Resend Verification Email</a>
            </div>
        <?php endif; ?>
    </div>
</div>

<?php
require_once 'footer.php';
?>
