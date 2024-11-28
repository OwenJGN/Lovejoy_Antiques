<?php
require_once '..\config\config.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Minimal Login Test</title>
    <style>
        /* Minimal CSS for testing */
        .form-container {
            width: 300px;
            margin: 50px auto;
            padding: 2rem;
            border: 1px solid #ccc;
            border-radius: 8px;
            background-color: #fff;
        }
    </style>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
</head>
<body>
    <div class="form-container">
        <h2>Login Test</h2>
        <form action="minimal_login_test.php" method="POST">
            <!-- Email Field -->
            <div class="mb-3">
                <label for="email">Email:</label>
                <input type="email" id="email" name="email" required>
            </div>

            <!-- Password Field -->
            <div class="mb-3">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>

            <!-- reCAPTCHA Widget -->
            <div class="g-recaptcha" data-sitekey="<?php echo RECAPTCHA_SITE_KEY; ?>"></div>

            <!-- Submit Button -->
            <button type="submit">Login</button>
        </form>
    </div>

    <?php
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $recaptcha_response = $_POST['g-recaptcha-response'] ?? '';

        // Verify CAPTCHA
        if (!empty($recaptcha_response)) {
            $captcha_valid = verifyRecaptchaV2($recaptcha_response, RECAPTCHA_SECRET_KEY);
            if ($captcha_valid) {
                echo "<p style='color: green;'>CAPTCHA verified successfully!</p>";
            } else {
                echo "<p style='color: red;'>CAPTCHA verification failed.</p>";
            }
        } else {
            echo "<p style='color: red;'>Please complete the CAPTCHA.</p>";
        }
    }

    /**
     * Verify reCAPTCHA v2 response
     */
    function verifyRecaptchaV2($recaptcha_response, $secret_key) {
        $url = 'https://www.google.com/recaptcha/api/siteverify';
        $data = [
            'secret' => $secret_key,
            'response' => $recaptcha_response
        ];

        // Initialize cURL
        $ch = curl_init($url);

        // Set cURL options
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));

        // Execute cURL request
        $response = curl_exec($ch);
        curl_close($ch);

        // Decode the response
        $result = json_decode($response, true);

        return $result['success'] ?? false;
    }
    ?>
</body>
</html>
