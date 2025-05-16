<?php
session_start();
include 'db_connection.php';

if (!isset($_SESSION['userID']) || $_SESSION['role'] !== 'Inventory Manager') {
    header("Location: index.php");
    exit();
}

if (!isset($_GET['id'])) {
    echo "No order ID provided";
    exit();
}

$orderId = $_GET['id'];

// Get order details
$orderQuery = "SELECT o.*, u.fullName as created_by_name FROM orders o
              LEFT JOIN users u ON o.created_by = u.userID
              WHERE o.order_id = ? AND o.order_type = 'Purchase'";
$orderStmt = $conn->prepare($orderQuery);
$orderStmt->bind_param("s", $orderId);
$orderStmt->execute();
$orderResult = $orderStmt->get_result();

if (!$orderRow = $orderResult->fetch_assoc()) {
    echo "Order not found";
    exit();
}

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

$conn->close();

// Format the order date
$orderDate = new DateTime($orderRow['order_date']);
$formattedDate = $orderDate->format('F j, Y');

// Get total amount
$totalAmount = $orderRow['total_amount'];
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Purchase Order - <?php echo $orderId; ?></title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .print-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 30px;
        }
        
        .company-info {
            display: flex;
            flex-direction: column;
        }
        
        .company-name {
            font-size: 24px;
            font-weight: bold;
            color: #0561FC;
        }
        
        .company-address {
            font-size: 14px;
            color: #666;
        }
        
        .doc-title {
            text-align: center;
            font-size: 20px;
            font-weight: bold;
            margin-bottom: 20px;
            padding: 10px;
            background-color: #f5f5f5;
            border-radius: 5px;
        }
        
        .order-info {
            display: flex;
            justify-content: space-between;
            margin-bottom: 30px;
        }
        
        .info-group {
            padding: 10px;
        }
        
        .info-item {
            margin-bottom: 5px;
        }
        
        .info-label {
            font-weight: bold;
            color: #555;
        }
        
        .info-value {
            margin-left: 5px;
        }
        
        .supplier-box {
            border: 1px solid #ddd;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        
        .supplier-heading {
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
        }
        
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        th {
            background-color: #f5f5f5;
            font-weight: bold;
        }
        
        .total-row {
            font-weight: bold;
        }
        
        .total-row td {
            padding-top: 20px;
        }
        
        .footer {
            margin-top: 50px;
            border-top: 1px solid #ddd;
            padding-top: 20px;
            font-size: 12px;
            color: #666;
        }
        
        .signature-section {
            display: flex;
            justify-content: space-between;
            margin-top: 50px;
        }
        
        .signature-box {
            width: 45%;
        }
        
        .signature-line {
            border-top: 1px solid #333;
            margin-top: 50px;
            padding-top: 5px;
        }
        
        .print-button {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 10px 20px;
            background-color: #0561FC;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        
        @media print {
            .print-button {
                display: none;
            }
            
            body {
                padding: 0;
                margin: 0;
            }
        }
    </style>
</head>
<body>
    <button class="print-button" onclick="window.print()">Print</button>
    
    <div class="print-header">
        <div class="company-info">
            <div class="company-name">Roti Seri Bakery</div>
            <div class="company-address">
                123 Bakery Street<br>
                Kuala Lumpur, Malaysia<br>
                Tel: +123 456 7890<br>
                Email: info@rotiseribakery.com
            </div>
        </div>
        <div>
            <img src="image/icon/logo.png" alt="Roti Seri Bakery Logo" style="width: 100px;">
        </div>
    </div>
    
    <div class="doc-title">
        PURCHASE ORDER #<?php echo $orderId; ?>
    </div>
    
    <div class="order-info">
        <div class="info-group">
            <div class="info-item">
                <span class="info-label">Order Date:</span>
                <span class="info-value"><?php echo $formattedDate; ?></span>
            </div>
            <div class="info-item">
                <span class="info-label">Status:</span>
                <span class="info-value"><?php echo $orderRow['status']; ?></span>
            </div>
            <div class="info-item">
                <span class="info-label">Created By:</span>
                <span class="info-value"><?php echo $orderRow['created_by_name'] ?? $orderRow['created_by']; ?></span>
            </div>
        </div>
    </div>
    
    <div class="supplier-box">
        <div class="supplier-heading">Supplier Information:</div>
        <div><?php echo $orderRow['customer_name']; ?></div>
    </div>
    
    <table>
        <thead>
            <tr>
                <th style="width: 15%;">Product ID</th>
                <th style="width: 40%;">Product Name</th>
                <th style="width: 15%;">Quantity</th>
                <th style="width: 15%;">Unit Price</th>
                <th style="width: 15%;">Subtotal</th>
            </tr>
        </thead>
        <tbody>
            <?php 
            $total = 0;
            foreach ($items as $item): 
                $subtotal = $item['quantity'] * $item['unit_price'];
                $total += $subtotal;
            ?>
                <tr>
                    <td><?php echo $item['product_id']; ?></td>
                    <td><?php echo $item['product_name']; ?></td>
                    <td><?php echo $item['quantity']; ?></td>
                    <td>RM <?php echo number_format($item['unit_price'], 2); ?></td>
                    <td>RM <?php echo number_format($subtotal, 2); ?></td>
                </tr>
            <?php endforeach; ?>
            
            <!-- Total Row -->
            <tr class="total-row">
                <td colspan="4" style="text-align: right;">Total:</td>
                <td>RM <?php echo number_format($total, 2); ?></td>
            </tr>
        </tbody>
    </table>
    
    <div class="signature-section">
        <div class="signature-box">
            <div class="signature-line">Authorized Signature</div>
        </div>
        <div class="signature-box">
            <div class="signature-line">Supplier Signature</div>
        </div>
    </div>
    
    <div class="footer">
        <p>This is a computer-generated document. No signature is required.</p>
        <p>Printed by: <?php echo $_SESSION['fullName'] . ' (' . $_SESSION['userID'] . ')'; ?> | Printed on: <?php echo date('Y-m-d H:i:s'); ?></p>
    </div>
    
    <script>
        // Auto-print when page loads
        window.onload = function() {
            // Delay print by 500ms to ensure everything loads properly
            setTimeout(function() {
                // window.print();
            }, 500);
        };
    </script>
</body>
</html>