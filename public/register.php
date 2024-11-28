<?php
// register.php

require_once 'header.php'; // Include your header (HTML head, navigation, etc.)
require_once '../includes/functions.php'; // Include functions.php for processing

// Redirect if already logged in
if (isLoggedIn()) {
    header('Location: index.php');
    exit();
}


$security_questions = fetchSecurityQuestions($pdo);

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

            <!-- Security Questions -->
            <h3>Security Questions</h3>

            <!-- Security Question 1 -->
            <div class="mb-3">
                <label for="security_question_1" class="form-label">Security Question 1:</label>
                <select name="security_question_1" id="security_question_1" class="form-control" required>
                    <option value="">-- Select a question --</option>
                    <?php foreach ($security_questions as $question): ?>
                        <option value="<?php echo htmlspecialchars($question['id']); ?>"
                            <?php echo (isset($_POST['security_question_1']) && $_POST['security_question_1'] == $question['id']) ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($question['question']); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
                <input type="text" name="security_answer_1" class="form-control mt-2" placeholder="Your Answer" required
                       value="<?php echo isset($_POST['security_answer_1']) ? htmlspecialchars($_POST['security_answer_1']) : ''; ?>">
            </div>

            <!-- Security Question 2 -->
            <div class="mb-3">
                <label for="security_question_2" class="form-label">Security Question 2:</label>
                <select name="security_question_2" id="security_question_2" class="form-control" required>
                    <option value="">-- Select a question --</option>
                    <?php foreach ($security_questions as $question): ?>
                        <option value="<?php echo htmlspecialchars($question['id']); ?>"
                            <?php echo (isset($_POST['security_question_2']) && $_POST['security_question_2'] == $question['id']) ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($question['question']); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
                <input type="text" name="security_answer_2" class="form-control mt-2" placeholder="Your Answer" required
                       value="<?php echo isset($_POST['security_answer_2']) ? htmlspecialchars($_POST['security_answer_2']) : ''; ?>">
            </div>

            <!-- Security Question 3 -->
            <div class="mb-3">
                <label for="security_question_3" class="form-label">Security Question 3:</label>
                <select name="security_question_3" id="security_question_3" class="form-control" required>
                    <option value="">-- Select a question --</option>
                    <?php foreach ($security_questions as $question): ?>
                        <option value="<?php echo htmlspecialchars($question['id']); ?>"
                            <?php echo (isset($_POST['security_question_3']) && $_POST['security_question_3'] == $question['id']) ? 'selected' : ''; ?>>
                            <?php echo htmlspecialchars($question['question']); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
                <input type="text" name="security_answer_3" class="form-control mt-2" placeholder="Your Answer" required
                       value="<?php echo isset($_POST['security_answer_3']) ? htmlspecialchars($_POST['security_answer_3']) : ''; ?>">
            </div>


            <!-- Submit Button -->
            <button type="submit" class="btn btn-primary">Register</button>
        </form>
    </div>
</div>

<?php
require_once 'footer.php'; // Include your footer (closing tags, scripts, etc.)
?>
