<?php
session_start();
include 'db_connection.php';

header('Content-Type: application/json');

if (!isset($_SESSION['userID']) || $_SESSION['role'] !== 'Inventory Manager') {
    echo json_encode(['error' => 'Unauthorized access']);
    exit();
}

if (isset($_GET['id'])) {
    $orderId = $_GET['id'];
    
    // Get order details
    $orderSql = "SELECT o.*, u.fullName FROM orders o 
                LEFT JOIN users u ON o.created_by = u.userID 
                WHERE o.order_id = ?";
    $orderStmt = $conn->prepare($orderSql);
    $orderStmt->bind_param("s", $orderId);
    $orderStmt->execute();
    $orderResult = $orderStmt->get_result();
    
    if ($orderRow = $orderResult->fetch_assoc()) {
        // Get order items
        $itemsSql = "SELECT oi.*, p.product_name 
                    FROM order_items oi 
                    JOIN products p ON oi.product_id = p.product_id 
                    WHERE oi.order_id = ?";
        $itemsStmt = $conn->prepare($itemsSql);
        $itemsStmt->bind_param("s", $orderId);
        $itemsStmt->execute();
        $itemsResult = $itemsStmt->get_result();
        
        $items = [];
        while ($itemRow = $itemsResult->fetch_assoc()) {
            $items[] = $itemRow;
        }
        
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