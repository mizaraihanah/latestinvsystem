<?php
session_start();
include 'db_connection.php';

header('Content-Type: application/json');

// Check if user is logged in and has correct role
if (!isset($_SESSION['userID']) || $_SESSION['role'] !== 'Inventory Manager') {
    echo json_encode(['error' => 'Unauthorized access']);
    exit();
}

if (isset($_GET['id'])) {
    $orderId = $_GET['id'];
    
    // Get order details
    $orderQuery = "SELECT o.*, u.fullName as created_by_name FROM orders o
                  LEFT JOIN users u ON o.created_by = u.userID
                  WHERE o.order_id = ? AND o.order_type = 'Purchase'";
    $orderStmt = $conn->prepare($orderQuery);
    $orderStmt->bind_param("s", $orderId);
    $orderStmt->execute();
    $orderResult = $orderStmt->get_result();
    
    if ($orderRow = $orderResult->fetch_assoc()) {
        // Get order items
        $itemsQuery = "SELECT oi.*, p.product_name 
                      FROM order_items oi 
                      JOIN products p ON oi.product_id = p.product_id 
                      WHERE oi.order_id = ?";
        $itemsStmt = $conn->prepare($itemsQuery);
        $itemsStmt->bind_param("s", $orderId);
        $itemsStmt->execute();
        $itemsResult = $itemsStmt->get_result();
        
        $items = [];
        while ($itemRow = $itemsResult->fetch_assoc()) {
            $items[] = $itemRow;
        }
        
        // Return the order and items data
        echo json_encode([
            'order' => $orderRow,
            'items' => $items
        ]);
    } else {
        echo json_encode(['error' => 'Order not found']);
    }
    
    $conn->close();
} else {
    echo json_encode(['error' => 'No order ID provided']);
}
?>