<?php
session_start();
include 'db_connection.php';

if (!isset($_SESSION['userID']) || $_SESSION['role'] !== 'Inventory Manager') {
    header("Location: index.php");
    exit();
}

$format = isset($_GET['format']) ? $_GET['format'] : 'pdf';

// Get filter values from the query string
$supplierFilter = isset($_GET['supplier']) ? $_GET['supplier'] : '';
$dateFrom = isset($_GET['date_from']) ? $_GET['date_from'] : '';
$dateTo = isset($_GET['date_to']) ? $_GET['date_to'] : '';
$statusFilter = isset($_GET['status']) ? $_GET['status'] : '';

// Build the query with potential filters
$query = "SELECT o.*, u.fullName as created_by_name,
          (SELECT COUNT(*) FROM order_items WHERE order_id = o.order_id) as item_count
          FROM orders o
          LEFT JOIN users u ON o.created_by = u.userID
          WHERE o.order_type = 'Purchase'";

$params = [];
$types = "";

if (!empty($supplierFilter)) {
    $query .= " AND o.customer_name LIKE ?";
    $supplierFilterParam = "%$supplierFilter%";
    $params[] = $supplierFilterParam;
    $types .= "s";
}

if (!empty($dateFrom)) {
    $query .= " AND o.order_date >= ?";
    $params[] = $dateFrom;
    $types .= "s";
}

if (!empty($dateTo)) {
    $query .= " AND o.order_date <= ?";
    $params[] = $dateTo;
    $types .= "s";
}

if (!empty($statusFilter)) {
    $query .= " AND o.status = ?";
    $params[] = $statusFilter;
    $types .= "s";
}

$query .= " ORDER BY o.order_date DESC";

// Prepare and execute the query
$stmt = $conn->prepare($query);
if (!empty($params)) {
    $stmt->bind_param($types, ...$params);
}
$stmt->execute();
$result = $stmt->get_result();

$purchases = [];
while ($row = $result->fetch_assoc()) {
    $purchases[] = $row;
}

// Calculate summary statistics
$totalAmount = 0;
foreach ($purchases as $purchase) {
    $totalAmount += $purchase['total_amount'];
}

// Export as PDF
if ($format === 'pdf') {
    // Ensure you have a PDF library like TCPDF installed
    require_once('vendor/autoload.php'); // Adjust path if needed for your PDF library

    // Create new PDF document
    $pdf = new TCPDF(PDF_PAGE_ORIENTATION, PDF_UNIT, PDF_PAGE_FORMAT, true, 'UTF-8', false);
    
    // Set document information
    $pdf->SetCreator('Roti Seri Bakery Inventory System');
    $pdf->SetAuthor('Inventory Manager');
    $pdf->SetTitle('Supplier Purchases Report');
    $pdf->SetSubject('Supplier Purchases Report');
    
    // Set default header data
    $pdf->SetHeaderData('', 0, 'Supplier Purchases Report', 'Generated on ' . date('Y-m-d H:i:s'));
    
    // Set margins
    $pdf->SetMargins(15, 25, 15);
    $pdf->SetHeaderMargin(5);
    $pdf->SetFooterMargin(10);
    
    // Set auto page breaks
    $pdf->SetAutoPageBreak(TRUE, 25);
    
    // Add a page
    $pdf->AddPage();
    
    // Build report title and filters info
    $html = '<h1>Supplier Purchases Report</h1>';
    
    // Add filter information if applied
    $filterInfo = '<p><strong>Filters applied:</strong> ';
    $filterTexts = [];
    
    if (!empty($supplierFilter)) {
        $filterTexts[] = "Supplier: $supplierFilter";
    }
    if (!empty($dateFrom)) {
        $filterTexts[] = "From: $dateFrom";
    }
    if (!empty($dateTo)) {
        $filterTexts[] = "To: $dateTo";
    }
    if (!empty($statusFilter)) {
        $filterTexts[] = "Status: $statusFilter";
    }
    
    if (empty($filterTexts)) {
        $filterInfo .= 'None</p>';
    } else {
        $filterInfo .= implode(', ', $filterTexts) . '</p>';
    }
    
    $html .= $filterInfo;
    
    // Add summary
    $html .= '<div style="margin-bottom: 20px;">
        <table border="0" cellpadding="5">
            <tr>
                <td><strong>Total Orders:</strong></td>
                <td>' . count($purchases) . '</td>
                <td><strong>Total Amount:</strong></td>
                <td>RM ' . number_format($totalAmount, 2) . '</td>
            </tr>
        </table>
    </div>';
    
    // Add orders table
    $html .= '<table border="1" cellpadding="5" cellspacing="0">
        <thead>
            <tr style="background-color: #f5f5f5; font-weight: bold;">
                <th>Order ID</th>
                <th>Supplier</th>
                <th>Order Date</th>
                <th>Items</th>
                <th>Total Amount</th>
                <th>Status</th>
                <th>Created By</th>
            </tr>
        </thead>
        <tbody>';
    
    foreach ($purchases as $purchase) {
        $html .= '<tr>
            <td>' . $purchase['order_id'] . '</td>
            <td>' . $purchase['customer_name'] . '</td>
            <td>' . $purchase['order_date'] . '</td>
            <td>' . $purchase['item_count'] . '</td>
            <td>RM ' . number_format($purchase['total_amount'], 2) . '</td>
            <td>' . $purchase['status'] . '</td>
            <td>' . ($purchase['created_by_name'] ?? $purchase['created_by']) . '</td>
        </tr>';
    }
    
    $html .= '</tbody></table>';
    
    // Add generation info
    $html .= '<p style="margin-top: 30px; font-size: 10px;">Report generated by: ' . $_SESSION['fullName'] . ' (' . $_SESSION['userID'] . ')<br>
    Generated on: ' . date('Y-m-d H:i:s') . '</p>';
    
    // Output the HTML content
    $pdf->writeHTML($html, true, false, true, false, '');
    
    // Close and output PDF document
    $pdf->Output('supplier_purchases_report.pdf', 'D');
    exit();
}
// Export as Excel
else if ($format === 'excel') {
    require_once('vendor/autoload.php'); // Adjust path if needed
    
    use PhpOffice\PhpSpreadsheet\Spreadsheet;
    use PhpOffice\PhpSpreadsheet\Writer\Xlsx;
    
    // Create new spreadsheet
    $spreadsheet = new Spreadsheet();
    $sheet = $spreadsheet->getActiveSheet();
    
    // Set title and headers
    $sheet->setCellValue('A1', 'Supplier Purchases Report');
    $sheet->mergeCells('A1:G1');
    $sheet->getStyle('A1')->getFont()->setBold(true)->setSize(16);
    
    // Add filter information
    $row = 2;
    $sheet->setCellValue('A' . $row, 'Generated on:');
    $sheet->setCellValue('B' . $row, date('Y-m-d H:i:s'));
    
    $row++;
    $sheet->setCellValue('A' . $row, 'Filters:');
    $filterText = '';
    
    if (!empty($supplierFilter)) {
        $filterText .= "Supplier: $supplierFilter, ";
    }
    if (!empty($dateFrom)) {
        $filterText .= "From: $dateFrom, ";
    }
    if (!empty($dateTo)) {
        $filterText .= "To: $dateTo, ";
    }
    if (!empty($statusFilter)) {
        $filterText .= "Status: $statusFilter, ";
    }
    
    $sheet->setCellValue('B' . $row, empty($filterText) ? 'None' : rtrim($filterText, ', '));
    
    $row += 2;
    
    // Add summary
    $sheet->setCellValue('A' . $row, 'Total Orders:');
    $sheet->setCellValue('B' . $row, count($purchases));
    $sheet->setCellValue('C' . $row, 'Total Amount:');
    $sheet->setCellValue('D' . $row, 'RM ' . number_format($totalAmount, 2));
    
    $row += 2;
    
    // Add table headers
    $headers = ['Order ID', 'Supplier', 'Order Date', 'Items', 'Total Amount', 'Status', 'Created By'];
    $col = 'A';
    foreach ($headers as $header) {
        $sheet->setCellValue($col . $row, $header);
        $col++;
    }
    
    $sheet->getStyle('A' . $row . ':G' . $row)->getFont()->setBold(true);
    $sheet->getStyle('A' . $row . ':G' . $row)->getFill()->setFillType(\PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID)->getStartColor()->setRGB('EEEEEE');
    
    $row++;
    
    // Add data rows
    foreach ($purchases as $purchase) {
        $sheet->setCellValue('A' . $row, $purchase['order_id']);
        $sheet->setCellValue('B' . $row, $purchase['customer_name']);
        $sheet->setCellValue('C' . $row, $purchase['order_date']);
        $sheet->setCellValue('D' . $row, $purchase['item_count']);
        $sheet->setCellValue('E' . $row, 'RM ' . number_format($purchase['total_amount'], 2));
        $sheet->setCellValue('F' . $row, $purchase['status']);
        $sheet->setCellValue('G' . $row, $purchase['created_by_name'] ?? $purchase['created_by']);
        $row++;
    }
    
    // Auto-size columns
    foreach (range('A', 'G') as $col) {
        $sheet->getColumnDimension($col)->setAutoSize(true);
    }
    
    // Create the Excel file
    $writer = new Xlsx($spreadsheet);
    
    // Set headers for file download
    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="supplier_purchases_report.xlsx"');
    header('Cache-Control: max-age=0');
    
    $writer->save('php://output');
    exit();
}

// If format is neither PDF nor Excel, redirect back to the purchases page
header("Location: imanager_supplierpurchase.php");
exit();
?>