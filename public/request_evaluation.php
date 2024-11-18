<?php
require_once 'header.php';
require_once '..\includes\functions.php';

//Check if user is logged in
checkAccess('user');

// Initialize variables
$errors = [];
$success = false;

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $result = processEvaluationRequestForm($pdo, $_SESSION['user_id']);
    $errors = $result['errors'];
    $success = $result['success'];
}
?>
<!-- Main Content Area -->
<div class="main-content">
    <div class="form-container">
        <h2 class="mb-4">Request Evaluation</h2>

        <?php if ($success): ?>
            <div class="alert alert-success" role="alert">
                Your evaluation request has been submitted successfully!
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

        <!-- Evaluation Request Form -->
        <form action="request_evaluation.php" method="POST" enctype="multipart/form-data" novalidate>
            <!-- CSRF Token -->
            <input type="hidden" name="csrf_token" value="<?php echo escape(generateCsrfToken()); ?>">

            <!-- Details of the Antique -->
            <div class="mb-3">
                <label for="details" class="form-label">Details of the Antique<span class="text-danger">*</span></label>
                <textarea class="form-control" id="details" name="details" rows="5" required maxlength="1000"
                    placeholder="Provide a detailed description of your antique item."><?php echo isset($_POST['details']) ? escape($_POST['details']) : ''; ?></textarea>
                <div class="form-text">Please describe the antique item you wish to have evaluated.</div>
            </div>

            <!-- Preferred Method of Contact -->
            <div class="mb-3">
                <label for="preferred_contact" class="form-label">Preferred Method of Contact<span class="text-danger">*</span></label>
                <select class="form-select" id="preferred_contact" name="preferred_contact" required>
                    <option value="" disabled <?php echo (!isset($_POST['preferred_contact']) || empty($_POST['preferred_contact'])) ? 'selected' : ''; ?>>Select an option</option>
                    <option value="phone" <?php echo (isset($_POST['preferred_contact']) && $_POST['preferred_contact'] === 'phone') ? 'selected' : ''; ?>>Phone</option>
                    <option value="email" <?php echo (isset($_POST['preferred_contact']) && $_POST['preferred_contact'] === 'email') ? 'selected' : ''; ?>>Email</option>
                </select>
                <div class="form-text">Choose how you would like to be contacted regarding your evaluation request.</div>
            </div>

            <!-- Photo Upload -->
            <div class="mb-3">
                <label for="photo" class="form-label">Photo of the Antique (Optional)</label>
                <input class="form-control" type="file" id="photo" name="photo" accept=".jpg, .jpeg, .png, .gif">
                <div class="form-text">Allowed file types: JPEG, PNG, GIF. Max size: 2MB.</div>
            </div>

            <!-- Submit Button -->
            <button type="submit" class="btn btn-primary">Submit Request</button>
        </form>
    </div>
</div>

<?php
require_once 'footer.php';
?>
