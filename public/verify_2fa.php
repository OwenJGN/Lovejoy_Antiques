<?php
// 2fa_validation.php

require_once 'header.php';
require_once '..\includes\functions.php';
require_once '..\config\config.php';

// Initialize variables
$errors = [];
$redirect = null;

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Retrieve and sanitize 2FA code input
    $entered_code = trim($_POST['2fa_code'] ?? '');

    // User ID should already be stored in session
    $user_id = $_SESSION['2fa_user_id'] ?? null;

    if ($user_id) {
        // Call the handle2FALogin function
        $result = handle2FALogin($pdo, $user_id, $entered_code);

        // Extract results
        $errors = $result['errors'];
        $redirect = $result['redirect'];

        if ($result['success'] && $redirect) {
            // Redirect on successful validation
            header("Location: $redirect");
            exit();
        }
    } else {
        $errors[] = "User session has expired. Please log in again.";
    }
}
?>

<!-- Main Content Area -->
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

        <!-- 2FA Form -->
        <form action="2fa_validation.php" method="POST" novalidate>
            <!-- CSRF Token -->
            <input type="hidden" name="csrf_token" value="<?php echo escape(generateCsrfToken()); ?>">

            <!-- 2FA Code Field -->
            <div class="mb-3">
                <label for="2fa_code" class="form-label">Enter 2FA Code<span class="text-danger">*</span></label>
                <input type="text" class="form-control" id="2fa_code" name="2fa_code" required>
            </div>

            <button type="submit" class="btn btn-primary">Verify</button>
        </form>
    </div>
</div>

<?php
require_once 'footer.php';
?>
