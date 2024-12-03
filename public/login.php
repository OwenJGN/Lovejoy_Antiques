<?php
/*
* Login Form 
*/

require_once 'header.php';
require_once '..\includes\functions.php';
require_once '..\config\config.php';

// Redirect if already logged in
if (isLoggedIn()) {
    header('Location: index.php');
    exit();
}

// Initialize variables
$errors = [];
$show_captcha = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Process the login and get the result
    $result = processLogin($pdo);

    // Extract results
    $errors = $result['errors'];
    $show_captcha = $result['show_captcha'];
    $user_id = $result['user_id'];

    // If no errors after credential verification, proceed to 2FA
    if (empty($errors) && $user_id) {
        $two_fa_errors = handle2FA($pdo, $user_id);
        $errors = array_merge($errors, $two_fa_errors);
    }
}

?>
<!-- Main Content Area -->
<div class="main-content">
    <div class="form-container">
        <h2 class="mb-4">Login</h2>

        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger" role="alert">
                <ul class="mb-0">
                    <?php foreach ($errors as $error): ?>
                        <li><?php echo escape($error); ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>


        <!-- Login Form -->
        <form action="login.php" method="POST" novalidate>
            <!-- CSRF Token -->
            <input type="hidden" name="csrf_token" value="<?php echo escape(generateCsrfToken()); ?>">

            <!-- Email Field -->
            <div class="mb-3">
                <label for="email" class="form-label">Email Address<span class="text-danger">*</span></label>
                <input type="email" class="form-control" id="email" name="email" required
                    value="<?php echo isset($_POST['email']) ? escape($_POST['email']) : ''; ?>">
            </div>

            <!-- Password Field -->
            <div class="mb-3">
                <label for="password" class="form-label">Password<span class="text-danger">*</span></label>
                <input type="password" class="form-control" id="password" name="password" required minlength="8">
            </div>

            <!-- CAPTCHA Section -->
            <?php if ($show_captcha): ?>
                <div class="mb-3">  
                    <div class="g-recaptcha" data-sitekey="<?php echo RECAPTCHA_SITE_KEY; ?>"></div>
                </div>
                <script src="https://www.google.com/recaptcha/api.js" async defer></script>
            <?php endif; ?>

            <!-- Resend Verification Email Option -->
            <?php if (in_array("Your email is not verified. Please verify your email.", $errors)): ?>
                <p class="mt-3">
                    Didn't receive the verification email? 
                    <a href="resend_verification.php">Resend Verification Email</a>
                </p>
            <?php else: ?>
                <p class="mt-3">
                    <a href="reset_password_email.php">Forgot Password?</a>
                </p>
            <?php endif; ?>

            <!-- Submit Button -->
            <button type="submit" class="btn btn-primary">Login</button>
        </form>
    </div>
</div>

<?php
require_once 'footer.php';
?>
