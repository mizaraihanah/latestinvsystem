<?php
session_start();
include 'db_connection.php';

if (!isset($_SESSION['userID']) || $_SESSION['role'] !== 'Inventory Manager') {
    header("Location: index.php");
    exit();
}

$format = isset($_GET['format']) ? $_GET['format'] : 'pdf';

// Fetch logs
$sql = "SELECT l.*, u.fullName 
        FROM inventory_logs l 
        JOIN users u ON l.user_id = u.userID 
        ORDER BY l.timestamp DESC";
$result = $conn->query($sql);

$logs = [];
while ($row = $result->fetch_assoc()) {
    $logs[] = $row;
}

// Export as PDF
if ($format === 'pdf') {
    require_once('vendor/autoload.php'); // Assuming you have TCPDF installed

    // Create new PDF document
    $pdf = new TCPDF(PDF_PAGE_ORIENTATION, PDF_UNIT, PDF_PAGE_FORMAT, true, 'UTF-8', false);
    
    // Set document information
    $pdf->SetCreator('Roti Seri Bakery Inventory System');
    $pdf->SetAuthor('Inventory Manager');
    $pdf->SetTitle('Inventory Activity Logs');
    $pdf->SetSubject('Inventory Logs');
    
    // Set default header and footer data
    $pdf->SetHeaderData('', 0, 'Inventory Activity Logs', 'Generated on ' . date('Y-m-d H:i:s'));
    
    // Set margins
    $pdf->SetMargins(15, 25, 15);
    $pdf->SetHeaderMargin(5);
    $pdf->SetFooterMargin(10);
    
    // Set auto page breaks
    $pdf->SetAutoPageBreak(TRUE, 25);
    
    // Add a page
    $pdf->AddPage();
    
    // HTML content
    $html = '<h1>Inventory Activity Logs</h1>';
    $html .= '<table border="1" cellpadding="4" cellspacing="0">
        <tr style="background-color:#0561FC; color:white;">
            <th>Timestamp</th>
            <th>User</th>
            <th>Action</th>
            <th>Item ID</th>
            <th>Details</th>
        </tr>';
    
    foreach ($logs as $log) {
        $html .= '<tr>
            <td>' . $log['timestamp'] . '</td>
            <td>' . $log['fullName'] . '</td>
            <td>' . $log['action'] . '</td>
            <td>' . $log['item_id'] . '</td>
            <td>' . $log['action_details'] . '</td>
        </tr>';
    }
    
    $html .= '</table>';
    $html .= '<p>Generated on: ' . date('Y-m-d H:i:s') . ' by ' . $_SESSION['fullName'] . '</p>';
    
    // Output the HTML content
    $pdf->writeHTML($html, true, false, true, false, '');
    
    // Close and output PDF document
    $pdf->Output('inventory_activity_logs.pdf', 'D');
    
    exit();
}
// Export as Excel
else if ($format === 'excel') {
    require_once('vendor/autoload.php'); // Assuming you have PhpSpreadsheet installed
    
    use PhpOffice\PhpSpreadsheet\Spreadsheet;
    use PhpOffice\PhpSpreadsheet\Writer\Xlsx;
    
    // Create new Spreadsheet object
    $spreadsheet = new Spreadsheet();
    $sheet = $spreadsheet->getActiveSheet();
    
    // Set the column headers
    $sheet->setCellValue('A1', 'Timestamp');
    $sheet->setCellValue('B1', 'User');
    $sheet->setCellValue('C1', 'Action');
    $sheet->setCellValue('D1', 'Item ID');
    $sheet->setCellValue('E1', 'Details');
    $sheet->setCellValue('F1', 'IP Address');
    
    // Style the headers
    $headerStyle = [
        'font' => [
            'bold' => true,
            'color' => ['rgb' => 'FFFFFF'],
        ],
        'fill' => [
            'fillType' => \PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID,
            'startColor' => ['rgb' => '0561FC'],
        ],
    ];
    $sheet->getStyle('A1:F1')->applyFromArray($headerStyle);
    
    // Add data
    $row = 2;
    foreach ($logs as $log) {
        $sheet->setCellValue('A' . $row, $log['timestamp']);
        $sheet->setCellValue('B' . $row, $log['fullName']);
        $sheet->setCellValue('C' . $row, $log['action']);
        $sheet->setCellValue('D' . $row, $log['item_id']);
        $sheet->setCellValue('E' . $row, $log['action_details']);
        $sheet->setCellValue('F' . $row, $log['ip_address']);
        $row++;
    }
    
    // Auto size columns
    foreach(range('A','F') as $col) {
        $sheet->getColumnDimension($col)->setAutoSize(true);
    }
    
    // Create the Excel file
    $writer = new Xlsx($spreadsheet);
    
    // Set headers for download
    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="inventory_activity_logs.xlsx"');
    header('Cache-Control: max-age=0');
    
    $writer->save('php://output');
    exit();
}

$conn->close();
?>