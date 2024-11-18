<?php
require_once 'header.php';
require_once '..\includes\functions.php';

// Redirect if already logged in
if (isLoggedIn()) {
    header('Location: index.php');
    exit();
}

// Initialize variables
$errors = [];
$result = '';
// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Process the login form and retrieve errors
    $errors = processLoginForm($pdo);

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

            <!-- Resend Verification Email Option -->
            <?php if (in_array("Your email is not verified. Please verify your email.", $errors)): ?>
                <p class="mt-3">
                    Didn't receive the verification email? 
                    <a href="resend_verification.php">Resend Verification Email</a>
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
