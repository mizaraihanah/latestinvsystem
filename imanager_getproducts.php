<?php
session_start();
include 'db_connection.php';

header('Content-Type: application/json');

if (!isset($_SESSION['userID'])) {
    echo json_encode(['error' => 'Unauthorized access']);
    exit();
}

// Fetch products
$sql = "SELECT p.*, c.category_name 
        FROM products p 
        LEFT JOIN product_categories c ON p.category_id = c.category_id 
        ORDER BY p.product_name";
$result = $conn->query($sql);

$products = [];
while ($row = $result->fetch_assoc()) {
    $products[] = $row;
}

echo json_encode($products);
$conn->close();
?>

