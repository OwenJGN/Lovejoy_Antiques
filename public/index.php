<?php
/*
 * Homepage
 */

require_once 'header.php'; 
?>

<!-- Hero Section -->
<section class="hero">
    <div class="container">
        <?php if ($isLoggedIn): ?>
            <!-- Greeting for Logged-In Users -->
            <h2>Welcome Back, <?php echo $userName; ?>!</h2>
            <p>Ready to evaluate your antique items? Click below to submit a new evaluation request.</p>
            <a href="request_evaluation.php" class="btn btn-primary btn-lg">Request Evaluation</a>
        <?php else: ?>
            <!-- Call-to-Action for Guests -->
            <h2>Get Your Antiques Evaluated Today</h2>
            <p>Join our community and get expert evaluations of your treasured antique items.</p>
            <a href="register.php" class="btn btn-primary btn-lg me-2">Register</a>
            <a href="login.php" class="btn btn-outline-primary btn-lg">Login</a>
        <?php endif; ?>
    </div>
</section>

<?php
require_once 'footer.php'; 
?>
