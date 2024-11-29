<?php
// reset_password_security.php

require_once 'header.php'; // Include your header (HTML head, navigation, etc.)
require_once '../includes/functions.php'; // Include functions.php for processing

checkAccess('user');

$user_id = $_SESSION['user_id'];

$security_questions = fetchUserSecurityQuestions($pdo, $user_id);

$errors = [];
$success = '';

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $result = checkSecurityQuestions($pdo, $user_id);
    $errors = $result['errors'];
    $success = $result['success'];

    if ($success) {
        // Redirect to verify_email.php with a success message
        header('Location: reset_password.php?source=security_questions');
        exit();
    }
}
?>

<!-- Main Content Area -->
<div class="main-content">
    <div class="form-container">
        <h2 class="mb-4">Security Questions</h2>

            <?php if (!empty($errors)): ?>
                <div class="alert alert-danger" role="alert">
                    <ul class="mb-0">
                        <?php foreach ($errors as $error): ?>
                            <li><?php echo escape($error); ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>
            
        	<?php if (!empty($success)): ?>
            	<div class="alert alert-success" role="alert">
                	<?php echo escape($success); ?>
            	</div>
        	<?php endif; ?>

            <!-- Registration Form -->
            <form action="reset_password_security.php" method="POST" novalidate>
                <!-- CSRF Token -->
                <input type="hidden" name="csrf_token" value="<?php echo escape(generateCsrfToken()); ?>">

                <div class="mb-3">
                    <h4>Security Question 1:</h4>                
                    <p><?php echo escape($security_questions[0]['question']); ?></p>
                    <!-- Hidden input to store the question ID -->
                    <input type="hidden" name="security_question_1" value="<?php echo escape($security_questions[0]['id']); ?>">
                    <!-- Input for the user's answer -->
                    <input type="text" name="security_answer_1" class="form-control mt-2" placeholder="Your Answer" required
                        value="<?php echo isset($_POST['security_answer_1']) ? escape($_POST['security_answer_1']) : ''; ?>">
                </div>

                <!-- Security Question 2 -->
                <div class="mb-3">
                    <h4>Security Question 2:</h4>                
                    <p><?php echo escape($security_questions[1]['question']); ?></p>
                    <!-- Hidden input to store the question ID -->
                    <input type="hidden" name="security_question_2" value="<?php echo escape($security_questions[1]['id']); ?>">
                    <!-- Input for the user's answer -->
                    <input type="text" name="security_answer_2" class="form-control mt-2" placeholder="Your Answer" required
                        value="<?php echo isset($_POST['security_answer_2']) ? escape($_POST['security_answer_2']) : ''; ?>">
                </div>

                <div class="mb-3">
                    <h4>Security Question 3:</h4>                
                    <p><?php echo escape($security_questions[2]['question']); ?></p>
                    <!-- Hidden input to store the question ID -->
                    <input type="hidden" name="security_question_3" value="<?php echo escape($security_questions[2]['id']); ?>">
                    <!-- Input for the user's answer -->
                    <input type="text" name="security_answer_3" class="form-control mt-2" placeholder="Your Answer" required
                        value="<?php echo isset($_POST['security_answer_3']) ? escape($_POST['security_answer_3']) : ''; ?>">
                </div>


                <!-- Submit Button -->
                <button type="submit" class="btn btn-primary">Submit</button>
            </form>
    </div>
</div>

<?php
require_once 'footer.php'; // Include your footer (closing tags, scripts, etc.)
?>