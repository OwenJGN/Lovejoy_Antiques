<?php

/**
 * Encrypt data using AES-256-CBC
 */
function encryptData($data) {
    $iv_length = openssl_cipher_iv_length('AES-256-CBC');
    $iv = openssl_random_pseudo_bytes($iv_length);
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', ENCRYPTION_KEY, 0, $iv);
    // Store the IV with the encrypted data for decryption
    return base64_encode($iv . $encrypted);
}
/**
 * Decrypt data using AES-256-CBC
 */
function decryptData($data) {
    $data = base64_decode($data);
    $iv_length = openssl_cipher_iv_length('AES-256-CBC');
    $iv = substr($data, 0, $iv_length);
    $encrypted = substr($data, $iv_length);
    return openssl_decrypt($encrypted, 'AES-256-CBC', ENCRYPTION_KEY, 0, $iv);
}
/**
 * Check for upload errors
 */
function checkUploadError($file, &$errors) {
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $errors[] = "Error uploading the photo.";
        return false;
    }
    return true;
}

/**
 * Validate MIME type using finfo
 */
function validateMimeType($filePath, &$errors) {
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    if (!$finfo) {
        $errors[] = "Failed to open fileinfo.";
        return false;
    }

    $detected_type = finfo_file($finfo, $filePath);
    finfo_close($finfo);

    if (!in_array($detected_type, ALLOWED_FILE_TYPES)) {
        $errors[] = "Invalid file type. Only JPG, PNG, and GIF are allowed.";
        return false;
    }

    return true;
}

/**
 * Validate file size
 */
function validateFileSize($fileSize, &$errors) {
    if ($fileSize > MAX_FILE_SIZE) {
        $errors[] = "File size exceeds the 2MB limit.";
        return false;
    }
    return true;
}

/**
 * Validate image using getimagesize
 */
function validateImage($filePath, &$errors) {
    $image_info = getimagesize($filePath);
    if ($image_info === false) {
        $errors[] = "Uploaded file is not a valid image.";
        return false;
    }
    return true;
}

/**
 * Read file content
 */
function readFileContent($filePath, &$errors) {
    $file_content = file_get_contents($filePath);
    if ($file_content === false) {
        $errors[] = "Failed to read uploaded file.";
        return false;
    }
    return $file_content;
}

/**
 * Encrypt file content
 */
function encryptFileContent($file_content, &$errors) {
    $encrypted_content = encryptData($file_content);
    if ($encrypted_content === false) {
        $errors[] = "Failed to encrypt the uploaded file.";
        return false;
    }
    return $encrypted_content;
}

/**
 * Generate a unique filename
 */
function generateUniqueFilename($originalName) {
    $ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
    return uniqid('photo_', true) . '.' . $ext;
}

/**
 * Save encrypted file to destination
 */
function saveEncryptedFile($encrypted_content, $destination, &$errors) {
    if (file_put_contents($destination, $encrypted_content) === false) {
        $errors[] = "Failed to save the encrypted file.";
        return false;
    }
    return true;
}

/**
 * Set strict file permissions
 */
function setFilePermissions($filePath, &$errors) {
    if (!chmod($filePath, 0600)) {
        $errors[] = "Failed to set file permissions.";
        return false;
    }
    return true;
}

/**
 * Handle file upload securely with encryption
 */
function handleFileUpload($file, &$errors) {
    $photo_filename = null;

    // Check if a file was uploaded
    if ($file['error'] === UPLOAD_ERR_NO_FILE) {
        // No file uploaded; it's optional
        return $photo_filename;
    }

    //Check for upload errors
    if (!checkUploadError($file, $errors)) {
        return $photo_filename;
    }

    // Validate MIME type
    if (!validateMimeType($file['tmp_name'], $errors)) {
        return $photo_filename;
    }

    //Validate file size
    if (!validateFileSize($file['size'], $errors)) {
        return $photo_filename;
    }

    //Validate image
    if (!validateImage($file['tmp_name'], $errors)) {
        return $photo_filename;
    }

    //Read file content
    $file_content = readFileContent($file['tmp_name'], $errors);
    if ($file_content === false) {
        return $photo_filename;
    }

    //Encrypt file content
    $encrypted_content = encryptFileContent($file_content, $errors);
    if ($encrypted_content === false) {
        return $photo_filename;
    }

    //Generate a unique filename
    $photo_filename = generateUniqueFilename($file['name']);
    $destination = '../uploads/' . $photo_filename;

    //Save encrypted file
    if (!saveEncryptedFile($encrypted_content, $destination, $errors)) {
        $photo_filename = null;
        return $photo_filename;
    }

    //Set file permissions
    if (!setFilePermissions($destination, $errors)) {
        // If setting permissions fails, delete the file for security
        unlink($destination);
        $photo_filename = null;
        return $photo_filename;
    }

    return $photo_filename;
}
?>
