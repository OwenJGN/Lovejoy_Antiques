<?php
// resend_2fa.php

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
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !verifyCsrfToken($_POST['csrf_token'])) {
        $errors[] = "Invalid CSRF token.";
    }

    if (empty($errors)) {
        // Check resend limits
        $resend_limit_result = check2FAResendLimit($pdo, $user_id);

        if ($resend_limit_result['can_resend']) {
            // Generate and store a new 2FA code
            $code = generateAndStore2FACode($pdo, $user_id);

            if ($code) {
                // Fetch user email
                $stmt = $pdo->prepare("SELECT email FROM users WHERE id = :id LIMIT 1");
                $stmt->execute([':id' => $user_id]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);

                if ($user) {
                    // Send 2FA code via email
                    if (send2FACodeEmail($user['email'], $code)) {
                        // Update resend_count and last_resend
                        update2FAResendInfo($pdo, $user_id);

                        $success = "A new 2FA code has been sent to your email.";
                    } else {
                        $errors[] = "Failed to send 2FA code. Please try again.";
                        error_log("Failed to resend 2FA email to {$user['email']} for user ID {$user_id}.");
                    }
                } else {
                    $errors[] = "User not found.";
                    error_log("User ID {$user_id} not found during resend 2FA.");
                }
            } else {
                $errors[] = "Failed to generate 2FA code. Please try again.";
                error_log("Failed to generate 2FA code for user ID {$user_id} during resend.");
            }
        } else {
            $errors[] = $resend_limit_result['message'];
        }
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
