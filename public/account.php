<?php
// view_account.php

// Include necessary files and start session
require_once 'header.php';
require_once '..\includes\functions.php';

checkAccess('user');
// Fetch user data if needed
$user_id = $_SESSION['user_id'];
?>

<div class="main-content">
    <div class="form-container">
        <h2 class="mb-4">Account Management</h2>
        <hr>
        <!-- Success and Error Messages -->
        <?php if (isset($_SESSION['success_message'])): ?>
            <div class="alert alert-success">
                <?php 
                    echo escape($_SESSION['success_message']); 
                    unset($_SESSION['success_message']);
                ?>
            </div>
        <?php endif; ?>

        <?php if (isset($_SESSION['error_message'])): ?>
            <div class="alert alert-danger">
                <?php 
                    echo escape($_SESSION['error_message']); 
                    unset($_SESSION['error_message']);
                ?>
            </div>
        <?php endif; ?>

        <!-- Password Reset via Email -->
        <div class="mb-3">
            <h3>Password Reset via Email</h3>
            <form action="request_password_reset.php" method="POST">
                <!-- CSRF Token -->
                <input type="hidden" name="csrf_token" value="<?php echo escape(generateCsrfToken()); ?>">
                
                <button type="submit" class="btn btn-primary">Send Password Reset Link to Email</button>
            </form>
        </div>

        <hr>

        <!-- Password Reset via Security Questions -->
        <div class="mb-3">
            <h3>Password Reset via Security Questions</h3>
            <form action="reset_password_security.php" method="POST">
                <!-- CSRF Token -->
                <input type="hidden" name="csrf_token" value="<?php echo escape(generateCsrfToken()); ?>">

                <div class="mb-3">
                    <label for="email" class="form-label">Registered Email Address:</label>
                    <input type="email" class="form-control" id="email" name="email" required
                           value="<?php echo isset($_POST['email']) ? escape($_POST['email']) : ''; ?>">
                </div>

                <button type="submit" class="btn btn-primary">Proceed to Security Questions</button>
            </form>
        </div>

        <hr>

        <!-- Delete Account -->
        <div class="mb-3">
            <h3>Delete Account</h3>
            <form action="delete_account.php" method="POST" onsubmit="return confirm('Are you sure you want to delete your account? This action cannot be undone.');">
                <!-- CSRF Token -->
                <input type="hidden" name="csrf_token" value="<?php echo escape(generateCsrfToken()); ?>">

                <button type="submit" class="btn btn-danger">Delete My Account</button>
            </form>
        </div>
    </div>
</div>
</body>
</html>
