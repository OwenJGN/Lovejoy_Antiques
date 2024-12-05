<?php
/*
* Account Management Page
*/

require_once 'header.php';
require_once '../scripts/functions.php';
require_once '../scripts/db_connect.php';

// Check if the user is logged in
checkAccess('user');

// Fetch user ID from the session
$user_id = $_SESSION['user_id'];

// Initialize variables for user data
$user_name = '';
$user_email = '';

// Fetch user data from the database
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

// Fetch user details
$user_id = $_SESSION['user_id'];
$result = fetchUserDetails($pdo, $user_id);

if ($result['success']) {
    // Extract user details
    $user_name = $result['user']['name'];
    $user_email = $result['user']['email'];
} else {
    $_SESSION['error_message'] = $result['error'];
    header('Location: ' . ($result['error'] === "User not found." ? 'logout.php' : 'account.php'));
    exit();
}

?>

<!-- Main Content Area -->
<div class="main-content">
    <div class="form-container">
        <h2 class="mb-4">Account Management</h2>
        <hr>    

        <input type="hidden" name="csrf_token" value="<?php echo escape(generateCsrfToken()); ?>">
        <!-- User Information -->
        <div class="mb-4">
            <h3>Your Information</h3>
            <p><strong>Name:</strong> <?php echo $user_name; ?></p>
            <p><strong>Email:</strong> <?php echo $user_email; ?></p>
        </div>

        <hr>

        <!-- Password Reset via Email -->
        <div class="mb-4">
            <h3>Password Reset via Email</h3>
            <a href="reset_password_email.php" class="btn btn-primary">Request reset link</a>
        </div>

        <hr>

        <!-- Password Reset via Security Questions -->
        <div class="mb-4">
            <h3>Password Reset via Security Questions</h3>
            <a href="reset_password_security.php" class="btn btn-primary">Proceed to Security Questions</a>
        </div>

        <hr>

        <!-- Delete Account -->
        <div class="mb-4">
            <h3>Delete Account</h3>
            <!-- Delete Button to Trigger Modal -->
            <button type="button" class="btn btn-danger" data-bs-toggle="modal" data-bs-target="#confirmDeleteModal">
                Delete My Account
            </button>

            <!-- Confirmation Modal -->
            <div class="modal fade" id="confirmDeleteModal" tabindex="-1" aria-labelledby="confirmDeleteModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="confirmDeleteModalLabel">Confirm Account Deletion</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    Are you sure you want to delete your account? This action cannot be undone.
                </div>
                <div class="modal-footer">
                    <!-- Cancel Button -->
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <!-- Delete Form -->
                    <form action="delete_account.php" method="POST" class="mb-0">                   
                        <button type="submit" class="btn btn-danger">Delete My Account</button>
                    </form>
                </div>
                </div>
            </div>
            </div>
        </div>
    </div>
</div>

<!-- Footer Section -->
<?php include 'footer.php';  ?>