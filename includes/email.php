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
 * Send verification email using PHPMailer
 */
function sendVerificationEmail($email, $verification_token) {
    // Create a new PHPMailer instance
    $mail = new PHPMailer(true);
    try {
        // Server settings
        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com'; // Gmail SMTP server
        $mail->SMTPAuth   = true;
        $mail->Username   = 'lovejoyantiques262924'; // Your Gmail address
        $mail->Password   = 'ehfi dtpo fucz jmkl'; // Your Gmail App Password
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = 587; // Gmail SMTP port

        // Recipients
        $mail->setFrom('no-reply@lovejoy.antiques.com', 'Lovejoy Antiques'); // Replace with your sender info
        $mail->addAddress($email); // Add a recipient

        // Content
        $mail->isHTML(true);
        $mail->Subject = 'Verify Your Email Address';
        $verification_link = "http://localhost/lovejoy_antiques/public/verify_email.php?token=" . urlencode($verification_token);
        $mail->Body    = "
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

        $mail->send();
        // Optionally, log that the email was sent successfully
    } catch (Exception $e) {
        error_log("Verification Email could not be sent to $email. Mailer Error: {$mail->ErrorInfo}");
        return false;
    }
    return true;

}

function sendPasswordResetEmail($email, $reset_token) {
    // Create a new PHPMailer instance
    $mail = new PHPMailer(true);
    try {
        // Server settings
        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com'; // Gmail SMTP server
        $mail->SMTPAuth   = true;
        $mail->Username   = 'lovejoyantiques262924'; // Your Gmail address
        $mail->Password   = 'ehfi dtpo fucz jmkl'; // Your Gmail App Password
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = 587; // Gmail SMTP port

        // Recipients
        $mail->setFrom('no-reply@lovejoy.antiques.com', 'Lovejoy Antiques'); // Replace with your sender info
        $mail->addAddress($email);

        // Content
        $mail->isHTML(true);
        $mail->Subject = 'Password Reset Request';
        $reset_link = "http://localhost/lovejoy_antiques/public/reset_password.php?token=" . urlencode($reset_token);
        $mail->Body    = "
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

        $mail->send();

        // Optionally, log that the email was sent successfully
    } catch (Exception $e) {
        error_log("Password Reset Email could not be sent to $email. Mailer Error: {$mail->ErrorInfo}");
        return false;
    }
    return true;
}
function send2FACodeEmail(string $email, string $code){
    $mail = new PHPMailer(true);
    
    try {
        // Server settings
        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com'; // Gmail SMTP server
        $mail->SMTPAuth   = true;
        $mail->Username   = 'lovejoyantiques262924'; // Your Gmail address
        $mail->Password   = 'ehfi dtpo fucz jmkl'; // Your Gmail App Password
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = 587; // Gmail SMTP port
    
        // Recipients
        $mail->setFrom('no-reply@lovejoy.antiques.com', 'Lovejoy Antiques'); // Replace with your sender info
        $mail->addAddress($email);
    
        // Content
        $mail->isHTML(true);
        $mail->Subject = 'Your 2FA Code for Lovejoy Antiques';
        $mail->Body    = "
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
    
        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log("2FA Email could not be sent to {$email}. Mailer Error: {$mail->ErrorInfo}");
        return false;
    }
}



?>