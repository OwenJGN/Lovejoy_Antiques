<?php
// register.php

require_once 'header.php'; // Include your header (HTML head, navigation, etc.)
require_once '../includes/functions.php'; // Include functions.php for processing

// Redirect if already logged in
if (isLoggedIn()) {
    header('Location: index.php');
    exit();
}

$errors = [];
$success = false;

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $result = processRegistrationForm($pdo);
    $errors = $result['errors'];
    $success = $result['success'];

    if ($success) {
        // Redirect to verify_email.php with a success message
        header('Location: verify_email.php?registered=1');
        exit();
    }
}
?>

<!-- Main Content Area -->
<div class="main-content">
    <div class="form-container">
        <h2 class="mb-4">Register</h2>

        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger" role="alert">
                <ul class="mb-0">
                    <?php foreach ($errors as $error): ?>
                        <li><?php echo escape($error); ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <!-- Registration Form -->
        <form action="register.php" method="POST" novalidate>
            <!-- CSRF Token -->
            <input type="hidden" name="csrf_token" value="<?php echo escape(generateCsrfToken()); ?>">

            <!-- Name Field -->
            <div class="mb-3">
                <label for="name" class="form-label">Full Name<span class="text-danger">*</span></label>
                <input type="text" class="form-control" id="name" name="name" required maxlength="255"
                    value="<?php echo isset($_POST['name']) ? escape($_POST['name']) : ''; ?>">
            </div>

            <!-- Email Field -->
            <div class="mb-3">
                <label for="email" class="form-label">Email Address<span class="text-danger">*</span></label>
                <input type="email" class="form-control" id="email" name="email" required
                    value="<?php echo isset($_POST['email']) ? escape($_POST['email']) : ''; ?>">
            </div>

            <!-- Confirm Email Field -->
            <div class="mb-3">
                <label for="confirm_email" class="form-label">Confirm Email Address<span class="text-danger">*</span></label>
                <input type="email" class="form-control" id="confirm_email" name="confirm_email" required
                    value="<?php echo isset($_POST['confirm_email']) ? escape($_POST['confirm_email']) : ''; ?>">
            </div>

            <!-- Phone Field -->
            <div class="mb-3">
                <label for="phone" class="form-label">Contact Telephone Number<span class="text-danger">*</span></label>
                <input type="tel" class="form-control" id="phone" name="phone" required
                    pattern="^\+?[0-9\s\-]{7,20}$"
                    value="<?php echo isset($_POST['phone']) ? escape($_POST['phone']) : ''; ?>">
                <div class="form-text">Allowed characters: numbers, spaces, dashes, and an optional plus sign. Minimum 7 digits.</div>
            </div>

            <!-- Password Field -->
            <div class="mb-3">
                <label for="password" class="form-label">Password<span class="text-danger">*</span></label>
                <input type="password" class="form-control" id="password" name="password" required minlength="8">
                <div class="form-text">
                    Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.
                </div>
            </div>

            <!-- Confirm Password Field -->
            <div class="mb-3">
                <label for="confirm_password" class="form-label">Confirm Password<span class="text-danger">*</span></label>
                <input type="password" class="form-control" id="confirm_password" name="confirm_password" required minlength="8">
            </div>

            <!-- Security Question Field -->
            <div class="mb-3">
                <label for="security_question" class="form-label">Security Question<span class="text-danger">*</span></label>
                <select class="form-control" id="security_question" name="security_question" required>
                    <option value="">Select a security question</option>
                    <option value="What was the name of your first pet?">What was the name of your first pet?</option>
                    <option value="What is the name of your first school?">What is the name of your first school?</option>
                    <option value="What was the make of your first car?">What was the make of your first car?</option>
                </select>
            </div>

            <!-- Security Answer Field -->
            <div class="mb-3">
                <label for="security_answer" class="form-label">Security Answer<span class="text-danger">*</span></label>
                <input type="text" class="form-control" id="security_answer" name="security_answer" required maxlength="255"
                    value="<?php echo isset($_POST['security_answer']) ? escape($_POST['security_answer']) : ''; ?>">
            </div>

            <!-- Submit Button -->
            <button type="submit" class="btn btn-primary">Register</button>
        </form>
    </div>
</div>

<?php
require_once 'footer.php'; // Include your footer (closing tags, scripts, etc.)
?>
