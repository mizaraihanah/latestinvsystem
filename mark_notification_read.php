<?php
session_start();
include 'db_connection.php';

header('Content-Type: application/json');

// Check if user is logged in
if (!isset($_SESSION['userID']) || $_SESSION['role'] !== 'Bakery Staff') {
    echo json_encode(['success' => false, 'message' => 'Unauthorized access']);
    exit();
}

if (isset($_GET['id']) && is_numeric($_GET['id'])) {
    $notificationId = $_GET['id'];
    $userId = $_SESSION['userID'];
    
    // Update notification status
    $sql = "UPDATE staff_notifications SET is_read = 1 
            WHERE notification_id = ? AND user_id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("is", $notificationId, $userId);
    
    if ($stmt->execute()) {
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['success' => false, 'message' => 'Failed to update notification']);
    }
    
    $stmt->close();
} else {
    echo json_encode(['success' => false, 'message' => 'Invalid notification ID']);
}

$conn->close();
?>