<?php
/*
* Resend verification email
*/

require_once 'header.php';
require_once '..\scripts\functions.php'; 

$errors = [];
$success = '';
if (isLoggedIn()) {
    header('Location: index.php');
    exit();
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // Process the resend verification form using the function
    $result = processResendVerificationForm($pdo, $email);

    // Assign results to variables for display
    $success = $result['success'];
    $errors = $result['errors'];
}
?>

<!-- Main Content Area -->
<div class="main-content">
    <div class="form-container">
        <h2 class="mb-4">Resend Verification Email</h2>

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

        <!-- Resend Verification Form -->
        <form action="resend_verification.php" method="POST" novalidate>
            <!-- CSRF Token -->
            <input type="hidden" name="csrf_token" value="<?php echo escape(generateCsrfToken()); ?>">

            <!-- Email Field -->
            <div class="mb-3">
                <label for="email" class="form-label">Email Address<span class="text-danger">*</span></label>
                <input type="email" class="form-control" id="email" name="email" required
                    value="<?php echo isset($_POST['email']) ? escape($_POST['email']) : ''; ?>">
            </div>

            <!-- Submit Button -->
            <button type="submit" class="btn btn-primary">Resend Verification Email</button>
        </form>
    </div>
</div>

<?php
require_once 'footer.php';
?>
