<?php
/*
* Verify email link page
*/

require_once 'header.php';
require_once '../scripts/functions.php';

$errors = [];
$success = '';
if (isLoggedIn()) {
    header('Location: index.php');
    exit();
}

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

<!-- Main Content Area -->
<div class="main-content">
    <div class="form-container">

        <?php if ($success): ?>
            <div class="alert alert-success" role="alert">
                <?php echo $success; ?>
            </div>

        <?php elseif (!empty($errors)): ?> 
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

