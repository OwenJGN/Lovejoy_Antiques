<?php
// verify_2fa.php

require_once 'header.php';
require_once '..\includes\functions.php';
require_once '..\includes\config.php';

// Redirect if no 2FA is pending
if (!isset($_SESSION['2fa_user_id'])) {
    header('Location: login.php');
    exit();
}

$user_id = $_SESSION['2fa_user_id'];
$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !verifyCsrfToken($_POST['csrf_token'])) {
        $errors[] = "Invalid CSRF token.";
    }

    // Retrieve and sanitize 2FA code input
    $entered_code = trim($_POST['2fa_code'] ?? '');

    // Validate 2FA code
    if (empty($entered_code)) {
        $errors[] = "2FA code is required.";
    } elseif (!ctype_digit($entered_code) || strlen($entered_code) !== 6) {
        $errors[] = "Invalid 2FA code format.";
    }

    if (empty($errors)) {
        // Verify the 2FA code with attempt limiting
        $verification_result = verify2FACode($pdo, $user_id, $entered_code);

        if ($verification_result === true) {
            // Successful verification
            // Fetch user details if not already available
            if (isset($_SESSION['temp_user_name'])) {
                $user_name = $_SESSION['temp_user_name'];
                // Set session variables
                $_SESSION['user_id'] = $user_id;
                $_SESSION['user_name'] = $user_name;

                resetLoginAttempts($pdo, $user_id);

                // Unset temporary session variables
                unset($_SESSION['2fa_user_id']);
                unset($_SESSION['temp_user_name']);

                // Regenerate session ID to prevent session fixation
                session_regenerate_id(true);

                // Redirect to dashboard or homepage
                header('Location: index.php');
                exit();
            } else {
                $errors[] = "User name not found. Please contact support.";
                error_log("User name missing in session for user ID {$user_id} after 2FA verification.");
            }
        } elseif ($verification_result === 'locked') {
            $errors[] = "Too many failed attempts. Please try again after 30 minutes.";
            // Optionally, implement account locking or notify the user
        } else {
            $errors[] = "Invalid or expired 2FA code.";
        }
    }
}
?>

<div class="main-content">
    <div class="form-container">
        <h2 class="mb-4">Two-Factor Authentication</h2>
        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger" role="alert">
                <ul class="mb-0">
                    <?php foreach ($errors as $error): ?>
                        <li><?php echo escape($error); ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <!-- 2FA Verification Form -->
        <form action="verify_2fa.php" method="POST" novalidate>
            <!-- CSRF Token -->
            <input type="hidden" name="csrf_token" value="<?php echo escape(generateCsrfToken()); ?>">

            <!-- 2FA Code Field -->
            <div class="mb-3">
                <label for="2fa_code" class="form-label">Enter the 2FA Code sent to your email<span class="text-danger">*</span></label>
                <input type="text" class="form-control" id="2fa_code" name="2fa_code" required pattern="\d{6}" maxlength="6">
                <div class="form-text">6-digit code.</div>
            </div>

            <!-- Submit Button -->
            <button type="submit" class="btn btn-primary">Verify</button>
        </form>

        <!-- Resend 2FA Code Option -->
        <p class="mt-3">
            Didn't receive the code? 
            <a href="resend_2fa.php">Resend Code</a>
        </p>
    </div>
</div>
<?php
    require_once 'footer.php';
?>

