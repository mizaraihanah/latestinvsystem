<?php
session_start();
include 'db_connection.php';

if (!isset($_SESSION['userID']) || $_SESSION['role'] !== 'Inventory Manager') {
    header("Location: index.php");
    exit();
}

$format = isset($_GET['format']) ? $_GET['format'] : 'pdf';
$orderId = isset($_GET['id']) ? $_GET['id'] : '';

if (empty($orderId)) {
    echo "No order ID provided";
    exit();
}

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
    
    // Export as PDF
    if ($format === 'pdf') {
        require_once('vendor/autoload.php'); // Assuming you have TCPDF installed

        // Create new PDF document
        $pdf = new TCPDF(PDF_PAGE_ORIENTATION, PDF_UNIT, PDF_PAGE_FORMAT, true, 'UTF-8', false);
        
        // Set document information
        $pdf->SetCreator('Roti Seri Bakery Inventory System');
        $pdf->SetAuthor('Inventory Manager');
        $pdf->SetTitle('Order Details - ' . $orderId);
        $pdf->SetSubject('Order Details');
        
        // Set default header and footer data
        $pdf->SetHeaderData('', 0, 'Order Details - ' . $orderId, 'Generated on ' . date('Y-m-d H:i:s'));
        
        // Set margins
        $pdf->SetMargins(15, 25, 15);
        $pdf->SetHeaderMargin(5);
        $pdf->SetFooterMargin(10);
        
        // Set auto page breaks
        $pdf->SetAutoPageBreak(TRUE, 25);
        
        // Add a page
        $pdf->AddPage();
        
        // HTML content
        $html = '<h1>Order Details</h1>';
        
        $html .= '<table cellpadding="5" cellspacing="0">
            <tr>
                <td><strong>Order ID:</strong></td>
                <td>' . $orderRow['order_id'] . '</td>
                <td><strong>Date:</strong></td>
                <td>' . $orderRow['order_date'] . '</td>
            </tr>
            <tr>
                <td><strong>Type:</strong></td>
                <td>' . $orderRow['order_type'] . '</td>
                <td><strong>Status:</strong></td>
                <td>' . $orderRow['status'] . '</td>
            </tr>
            <tr>
                <td><strong>Customer/Supplier:</strong></td>
                <td>' . $orderRow['customer_name'] . '</td>
                <td><strong>Created By:</strong></td>
                <td>' . $orderRow['fullName'] . '</td>
            </tr>
        </table>';
        
        $html .= '<h2>Order Items</h2>';
        $html .= '<table border="1" cellpadding="4" cellspacing="0">
            <tr style="background-color:#0561FC; color:white;">
                <th>Product ID</th>
                <th>Product Name</th>
                <th>Quantity</th>
                <th>Unit Price</th>
                <th>Subtotal</th>
            </tr>';
        
        $total = 0;
        foreach ($items as $item) {
            $subtotal = $item['quantity'] * $item['unit_price'];
            $total += $subtotal;
            
            $html .= '<tr>
                <td>' . $item['product_id'] . '</td>
                <td>' . $item['product_name'] . '</td>
                <td>' . $item['quantity'] . '</td>
                <td>RM ' . number_format($item['unit_price'], 2) . '</td>
                <td>RM ' . number_format($subtotal, 2) . '</td>
            </tr>';
        }
        
        $html .= '<tr>
            <td colspan="4" align="right"><strong>Total:</strong></td>
            <td><strong>RM ' . number_format($total, 2) . '</strong></td>
        </tr>';
        
        $html .= '</table>';
        $html .= '<p>Generated on: ' . date('Y-m-d H:i:s') . ' by ' . $_SESSION['fullName'] . '</p>';
        
        // Output the HTML content
        $pdf->writeHTML($html, true, false, true, false, '');
        
        // Close and output PDF document
        $pdf->Output('order_' . $orderId . '.pdf', 'D');
        
        exit();
    }
} else {
    echo "Order not found";
}

$conn->close();
?>