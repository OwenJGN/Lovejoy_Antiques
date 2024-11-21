<?php

// Include necessary files
require_once 'header.php';
require_once '../includes/functions.php';
require_once '../includes/db_connect.php';

// Check if the user is logged in
checkAccess('user');

// Fetch user ID from the session
$user_id = $_SESSION['user_id'];

// Initialize variables for user data
$user_name = '';
$user_email = '';

// Fetch user data from the database
try {
    $stmt = $pdo->prepare("SELECT name, email FROM users WHERE id = :id LIMIT 1");
    $stmt->execute([':id' => $user_id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user) {
        $user_name = escape($user['name']);
        $user_email = escape($user['email']);
    } else {
        // If user not found, redirect to logout
        header('Location: logout.php');
        exit();
    }
} catch (PDOException $e) {
    error_log("Database Error: " . $e->getMessage());
    $_SESSION['error_message'] = "An error occurred while fetching your account details. Please try again later.";
    header('Location: account.php');
    exit();
}

// Generate CSRF token
$csrf_token = generateCsrfToken();
?>

<div class="main-content">
    <div class="form-container">
        <h2 class="mb-4">Account Management</h2>
        <hr>    

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
            <form action="reset_password_email.php" method="POST">
                <!-- CSRF Token -->
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                
                <button type="submit" class="btn btn-primary">Send Password Reset Link to Email</button>
            </form>
        </div>

        <hr>

        <!-- Password Reset via Security Questions -->
        <div class="mb-4">
            <h3>Password Reset via Security Questions</h3>
            <form action="reset_password_security.php" method="POST">
                <!-- CSRF Token -->
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                <button type="submit" class="btn btn-primary">Proceed to Security Questions</button>
            </form>
        </div>

        <hr>

        <!-- Delete Account -->
        <div class="mb-4">
            <h3>Delete Account</h3>
            <form action="delete_account.php" method="POST" onsubmit="return confirm('Are you sure you want to delete your account? This action cannot be undone.');">
                <!-- CSRF Token -->
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">

                <button type="submit" class="btn btn-danger">Delete My Account</button>
            </form>
        </div>
    </div>
</div>
</body>
</html>
    <!-- Footer Section -->
    <?php include 'footer.php'; // Assuming you have a separate footer file ?>