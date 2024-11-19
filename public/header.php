<?php
require_once 'init.php';

// Check if user is logged in
$isLoggedIn = isLoggedIn();
$userName = $isLoggedIn ? escape($_SESSION['user_name']) : '';
$isAdmin = isAdmin();

//CSP
$CSP = "default-src 'self'; ";
$CSP .= "script-src 'self' https://cdn.jsdelivr.net https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/; ";
$CSP .= "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; ";
$CSP .= "img-src 'self' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/ data:; ";
$CSP .= "frame-src https://www.google.com/recaptcha/; ";
$CSP .= "font-src 'self'; ";
$CSP .= "connect-src 'self'; ";
$CSP .= "object-src 'none'; ";
$CSP .= "base-uri 'self'; ";
$CSP .= "form-action 'self'; ";
$CSP .= "frame-ancestors 'self'; ";

// Set the CSP header
header("Content-Security-Policy: $CSP");

// Generate CSRF token for forms if needed
$csrf_token = generateCsrfToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Lovejoy’s Antique Evaluation</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="../assets/css/styles.css">
</head>
<body>
    <!-- Header Section -->
    <header>
        <div class="container">
            <h1>Lovejoy’s Antique Evaluation</h1>
            <p>Your trusted partner in antique appraisal and valuation</p>
        </div>
    </header>

    <!-- Navigation Bar -->
    <nav class="navbar navbar-expand-lg navbar-custom shadow-sm">
        <div class="container">
            <a class="navbar-brand" href="index.php">Lovejoy’s Antique</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav"
                aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse justify-content-end" id="navbarNav">
                <ul class="navbar-nav">
                    <?php if ($isLoggedIn): ?>
                        <li class="nav-item">
                            <span class="greeting-text">Hello, <?php echo $userName; ?>!</span>
                        </li>                        
                        <li class="nav-item">
                            <a class="nav-link" href="account.php">Your Account</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="request_evaluation.php">Request Evaluation</a>
                        </li>

                        <?php if ($isAdmin): ?>
                            <li class="nav-item">
                                <a class="nav-link" href="admin_requests.php">View Requests</a>
                            </li>
                        <?php endif; ?>
                        <li class="nav-item">
                            <a class="nav-link" href="logout.php">Logout</a>
                        </li>
                    <?php else: ?>
                        <li class="nav-item">
                            <a class="nav-link" href="register.php">Register</a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="login.php">Login</a>
                        </li>
                    <?php endif; ?>
                </ul>
            </div>
        </div>
    </nav>
