<?php
/*
* Verify the 2FA
*/

require_once 'header.php';
require_once '..\scripts\functions.php';
require_once '..\config\config.php';

// Initialize variables
$errors = [];
$redirect = null;

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
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

            <!-- 2FA Verification Form -->
            <form action="verify_2fa.php" method="POST" novalidate>
            <!-- CSRF Token -->
            <input type="hidden" name="csrf_token" value="<?php echo escape(generateCsrfToken()); ?>">

            <!-- 2FA Code Field -->
            <div class="mb-3">
                <label for="two_fa_code" class="form-label">Enter the 2FA Code sent to your email <span class="text-danger">*</span></label>
                <input 
                    type="text" 
                    class="form-control" 
                    id="two_fa_code" 
                    name="2fa_code" 
                    required 
                    value="<?php echo isset($_POST['2fa_code']) ? escape($_POST['2fa_code']) : ''; ?>" 
                    pattern="\d{6}" 
                    maxlength="6">
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
