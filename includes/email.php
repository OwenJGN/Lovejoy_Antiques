<?php

require_once 'functions.php';

// Include PHPMailer classes
require 'PHPMailer/src/Exception.php';
require 'PHPMailer/src/PHPMailer.php';
require 'PHPMailer/src/SMTP.php';

// Use PHPMailer namespaces
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

/**
 * Initialize and configure the PHPMailer instance.
*/
function initializeMailer() {
    $mail = new PHPMailer(true);
    try {
        // Server settings
        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com'; 
        $mail->SMTPAuth   = true;
        $mail->Username   = 'lovejoyantiques262924'; 
        $mail->Password   = 'ehfi dtpo fucz jmkl'; 
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = 587; 

        // Recipients
        $mail->setFrom('no-reply@lovejoy.antiques.com', 'Lovejoy Antiques'); 
        $mail->isHTML(true);
    } catch (Exception $e) {
        error_log("Mailer initialization failed. Mailer Error: {$mail->ErrorInfo}");
        return false;
    }
    return $mail;
}

/**
 * Send verification email using PHPMailer.
 */
function sendVerificationEmail($email, $verification_token) {
    $mail = initializeMailer();
    if (!$mail) {
        return false;
    }

    try {
        // Add recipient
        $mail->addAddress($email);

        // Email subject
        $mail->Subject = 'Verify Your Email Address';

        // Verification link
        $verification_link = "http://localhost/lovejoy_antiques/public/verify_email.php?token=" . urlencode($verification_token);

        // Email body
        $mail->Body = "
            <html>
            <head>
                <title>Verify Your Email Address</title>
            </head>
            <body>
                <p>Thank you for registering! Please click the link below to verify your email address. This link will expire in 24 hours.</p>
                <p><a href='$verification_link'>$verification_link</a></p>
                <p>If you did not register, please ignore this email.</p>
            </body>
            </html>
        ";

        // Send the email
        $mail->send();
    } catch (Exception $e) {
        error_log("Verification Email could not be sent to $email. Mailer Error: {$mail->ErrorInfo}");
        return false;
    }

    return true;
}

/**
 * Send password reset email using PHPMailer.
 */
function sendPasswordResetEmail($email, $reset_token) {
    $mail = initializeMailer();
    if (!$mail) {
        return false;
    }

    try {
        // Add recipient
        $mail->addAddress($email);

        // Email subject
        $mail->Subject = 'Password Reset Request';

        // Reset link
        $reset_link = "http://localhost/lovejoy_antiques/public/reset_password.php?token=" . urlencode($reset_token);

        // Email body
        $mail->Body = "
            <html>
            <head>
                <title>Password Reset Request</title>
            </head>
            <body>
                <p>Hello,</p>
                <p>You have requested to reset your password. Please click the link below to proceed:</p>
                <p><a href='$reset_link'>Reset Your Password</a></p>
                <p>This link will expire in 1 hour. If you did not request a password reset, please ignore this email.</p>
                <p>Best regards,<br>Lovejoy Antiques Team</p>
            </body>
            </html>
        ";

        // Send the email
        $mail->send();
    } catch (Exception $e) {
        error_log("Password Reset Email could not be sent to $email. Mailer Error: {$mail->ErrorInfo}");
        return false;
    }

    return true;
}

/**
 * Send 2FA code email using PHPMailer.
 */
function send2FACodeEmail(string $email, string $code){
    $mail = initializeMailer();
    if (!$mail) {
        return false;
    }

    try {
        // Add recipient
        $mail->addAddress($email);

        // Email subject
        $mail->Subject = 'Your 2FA Code for Lovejoy Antiques';

        // Email body
        $mail->Body = "
            <html>
            <head>
                <title>2FA Code</title>
            </head>
            <body>
                <p>Dear User,</p>
                <p>Your Two-Factor Authentication (2FA) code is: <strong>{$code}</strong></p>
                <p>This code will expire in 10 minutes.</p>
                <p>If you did not attempt to log in, please secure your account immediately.</p>
                <p>Best regards,<br>Lovejoy Antiques Team</p>
            </body>
            </html>
        ";

        // Send the email
        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log("2FA Email could not be sent to {$email}. Mailer Error: {$mail->ErrorInfo}");
        return false;
    }
}

?>
