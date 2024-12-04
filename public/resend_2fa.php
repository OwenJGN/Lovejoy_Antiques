<?php
/*
*  Resend users 2fa code
*/

require_once 'header.php';
require_once '..\scripts\functions.php';
require_once '..\config\config.php';

// Initialize variables
$errors = [];
$success = null;

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Extract CSRF token
    $csrf_token = $_POST['csrf_token'] ?? '';

    // User ID should be available in session or other secure storage
    $user_id = $_SESSION['2fa_user_id'] ?? null;

    if ($user_id) {
        // Call the handleResend2FA function
        $result = handleResend2FA($pdo, $user_id, $csrf_token);

        // Extract success message and errors
        $success = $result['success'];
        $errors = $result['errors'];
    } else {
        $errors[] = "User ID not found in session.";
    }
}
?>

<!-- Main Content Area -->
<div class="main-content">
    <div class="form-container">
        <h2 class="mb-4">Resend Two-Factor Authentication Code</h2>

        <?php if (!empty($success)): ?>
            <div class="alert alert-success" role="alert">
                <?php echo escape($success); ?>
            </div>
        <?php endif; ?>

        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger" role="alert">
                <ul class="mb-0">
                    <?php foreach ($errors as $error): ?>
                        <li><?php echo escape($error); ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>


        <!-- Resend 2FA Code Form -->
        <form action="resend_2fa.php" method="POST" novalidate>
            <!-- CSRF Token -->
            <input type="hidden" name="csrf_token" value="<?php echo escape(generateCsrfToken()); ?>">

            <!-- Submit Button -->
            <button type="submit" class="btn btn-primary">Resend 2FA Code</button>
        </form>

        <!-- Link Back to 2FA Verification -->
        <p class="mt-3">
            <a href="verify_2fa.php">Back to 2FA Verification</a>
        </p>
    </div>
</div>

<?php
require_once 'footer.php';
?>
