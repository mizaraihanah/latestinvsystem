<?php
session_start();
include 'db_connection.php';

// Check if user is logged in and has appropriate role
if (!isset($_SESSION['userID']) || $_SESSION['role'] !== 'Bakery Staff') {
    header('Location: index.php');
    exit();
}

// Ensure we have all required parameters
if (!isset($_POST['product_id']) || !isset($_POST['new_stock'])) {
    header('Location: staff_alerts.php?error=Missing required information');
    exit();
}

$productId = trim($_POST['product_id']);
$newStock = intval($_POST['new_stock']);
$note = isset($_POST['note']) ? trim($_POST['note']) : '';
$userId = $_SESSION['userID'];

// Get current stock to calculate the difference
$sqlCurrent = "SELECT stock_quantity, product_name FROM products WHERE product_id = ?";
$stmtCurrent = $conn->prepare($sqlCurrent);
$stmtCurrent->bind_param("s", $productId);
$stmtCurrent->execute();
$resultCurrent = $stmtCurrent->get_result();

if ($resultCurrent->num_rows !== 1) {
    header('Location: staff_alerts.php?error=Product not found');
    $stmtCurrent->close();
    $conn->close();
    exit();
}

$productData = $resultCurrent->fetch_assoc();
$currentStock = $productData['stock_quantity'];
$productName = $productData['product_name'];
$stmtCurrent->close();

// Calculate difference for logging
$stockDifference = $newStock - $currentStock;
$actionType = ($stockDifference > 0) ? "stock_increase" : "stock_decrease";
$stockDifference = abs($stockDifference);

// Start transaction
$conn->begin_transaction();

try {
    // Update the stock quantity
    $sqlUpdate = "UPDATE products SET stock_quantity = ?, last_updated = NOW() WHERE product_id = ?";
    $stmtUpdate = $conn->prepare($sqlUpdate);
    $stmtUpdate->bind_param("is", $newStock, $productId);
    $stmtUpdate->execute();
    $stmtUpdate->close();
    
    // Log the stock update
    $actionDetails = "$actionType: " . ($note ? "($note) " : "") . 
                    "Changed stock from $currentStock to $newStock";
    
    $sqlLog = "INSERT INTO inventory_logs (user_id, action, item_id, action_details, timestamp, ip_address) 
               VALUES (?, ?, ?, ?, NOW(), ?)";
    $stmtLog = $conn->prepare($sqlLog);
    $ipAddress = $_SERVER['REMOTE_ADDR'];
    $stmtLog->bind_param("sssss", $userId, $actionType, $productId, $actionDetails, $ipAddress);
    $stmtLog->execute();
    $stmtLog->close();
    
    // If this resolves a low stock issue, mark related notifications as read
    if ($newStock > 0) {
        $sqlUpdateNotifications = "UPDATE staff_notifications 
                                  SET is_read = 1 
                                  WHERE item_id = ? 
                                  AND type IN ('low_stock', 'out_of_stock') 
                                  AND user_id = ?";
        $stmtUpdateNotifications = $conn->prepare($sqlUpdateNotifications);
        $stmtUpdateNotifications->bind_param("ss", $productId, $userId);
        $stmtUpdateNotifications->execute();
        $stmtUpdateNotifications->close();
    }
    
    // Commit transaction
    $conn->commit();
    
    // Redirect with success message
    header('Location: staff_alerts.php?success=Stock updated successfully');
    
} catch (Exception $e) {
    // Rollback transaction on error
    $conn->rollback();
    header('Location: staff_alerts.php?error=Failed to update stock: ' . $e->getMessage());
}

$conn->close();
?>