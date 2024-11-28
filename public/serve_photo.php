<?php
// servePhoto.php

require_once 'header.php'; // Include any necessary authentication or setup
require_once '..\includes\functions.php';



// Start session if not already started
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// Check if user is authenticated and authorized (admin)
checkAccess('admin'); 

// Get the requested file from query parameter
$filename = $_GET['file'] ?? '';

if (empty($filename)) {
    http_response_code(400);
    echo "No file specified.";
    exit;
}

// Sanitize the filename to prevent directory traversal
$filename = basename($filename);

$filepath = '../public/uploads/' . $filename;

if (!file_exists($filepath)) {
    http_response_code(404);
    echo "File not found.";
    exit;
}

// Read the encrypted file content
$encrypted_content = file_get_contents($filepath);
if ($encrypted_content === false) {
    http_response_code(500);
    echo "Failed to read file.";
    exit;
}

// Decrypt the content
$decrypted_content = decryptData($encrypted_content);
if ($decrypted_content === false) {
    http_response_code(500);
    echo "Failed to decrypt file.";
    exit;
}

// Determine the MIME type based on the file extension
$extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
$mime_types = [
    'jpg' => 'image/jpeg',
    'jpeg' => 'image/jpeg',
    'png' => 'image/png',
    'gif' => 'image/gif',
    // Add more mappings if necessary
];

$mime_type = $mime_types[$extension] ?? 'application/octet-stream';

// Serve the decrypted file
header('Content-Type: ' . $mime_type);
header('Content-Length: ' . strlen($decrypted_content));
header('Content-Disposition: inline; filename="' . $filename . '"');
echo $decrypted_content;
?>
