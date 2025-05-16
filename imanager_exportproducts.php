/******* export_products.php *******/
<?php
session_start();
include 'db_connection.php';

if (!isset($_SESSION['userID']) || $_SESSION['role'] !== 'Inventory Manager') {
    header("Location: index.php");
    exit();
}

$format = isset($_GET['format']) ? $_GET['format'] : 'pdf';

// Fetch products
$sql = "SELECT p.product_id, p.product_name, c.category_name, p.description, 
        p.stock_quantity, p.reorder_threshold, p.unit_price, p.last_updated 
        FROM products p 
        LEFT JOIN product_categories c ON p.category_id = c.category_id 
        ORDER BY p.product_name";
$result = $conn->query($sql);

$products = [];
while ($row = $result->fetch_assoc()) {
    $products[] = $row;
}

// Export as PDF
if ($format === 'pdf') {
    require_once('vendor/autoload.php'); // Assuming you have TCPDF installed

    // Create new PDF document
    $pdf = new TCPDF(PDF_PAGE_ORIENTATION, PDF_UNIT, PDF_PAGE_FORMAT, true, 'UTF-8', false);
    
    // Set document information
    $pdf->SetCreator('Roti Seri Bakery Inventory System');
    $pdf->SetAuthor('Inventory Manager');
    $pdf->SetTitle('Products Inventory Report');
    $pdf->SetSubject('Products Inventory');
    
    // Set default header and footer data
    $pdf->SetHeaderData('', 0, 'Products Inventory Report', 'Generated on ' . date('Y-m-d H:i:s'));
    
    // Set margins
    $pdf->SetMargins(15, 25, 15);
    $pdf->SetHeaderMargin(5);
    $pdf->SetFooterMargin(10);
    
    // Set auto page breaks
    $pdf->SetAutoPageBreak(TRUE, 25);
    
    // Add a page
    $pdf->AddPage();
    
    // HTML content
    $html = '<h1>Products Inventory Report</h1>';
    $html .= '<table border="1" cellpadding="4" cellspacing="0">
        <tr style="background-color:#0561FC; color:white;">
            <th>Product ID</th>
            <th>Product Name</th>
            <th>Category</th>
            <th>Stock Quantity</th>
            <th>Reorder Level</th>
            <th>Unit Price (RM)</th>
            <th>Last Updated</th>
        </tr>';
    
    foreach ($products as $product) {
        $rowColor = '';
        if ($product['stock_quantity'] <= $product['reorder_threshold']) {
            $rowColor = 'background-color:#fff3cd;';
        }
        if ($product['stock_quantity'] == 0) {
            $rowColor = 'background-color:#f8d7da;';
        }
        
        $html .= '<tr style="' . $rowColor . '">
            <td>' . $product['product_id'] . '</td>
            <td>' . $product['product_name'] . '</td>
            <td>' . $product['category_name'] . '</td>
            <td>' . $product['stock_quantity'] . '</td>
            <td>' . $product['reorder_threshold'] . '</td>
            <td>' . number_format($product['unit_price'], 2) . '</td>
            <td>' . $product['last_updated'] . '</td>
        </tr>';
    }
    
    $html .= '</table>';
    $html .= '<p>Generated on: ' . date('Y-m-d H:i:s') . ' by ' . $_SESSION['fullName'] . '</p>';
    
    // Output the HTML content
    $pdf->writeHTML($html, true, false, true, false, '');
    
    // Close and output PDF document
    $pdf->Output('products_inventory_report.pdf', 'D');
    
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
    $sheet->setCellValue('A1', 'Product ID');
    $sheet->setCellValue('B1', 'Product Name');
    $sheet->setCellValue('C1', 'Category');
    $sheet->setCellValue('D1', 'Description');
    $sheet->setCellValue('E1', 'Stock Quantity');
    $sheet->setCellValue('F1', 'Reorder Level');
    $sheet->setCellValue('G1', 'Unit Price (RM)');
    $sheet->setCellValue('H1', 'Last Updated');
    
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
    $sheet->getStyle('A1:H1')->applyFromArray($headerStyle);
    
    // Add data
    $row = 2;
    foreach ($products as $product) {
        $sheet->setCellValue('A' . $row, $product['product_id']);
        $sheet->setCellValue('B' . $row, $product['product_name']);
        $sheet->setCellValue('C' . $row, $product['category_name']);
        $sheet->setCellValue('D' . $row, $product['description']);
        $sheet->setCellValue('E' . $row, $product['stock_quantity']);
        $sheet->setCellValue('F' . $row, $product['reorder_threshold']);
        $sheet->setCellValue('G' . $row, $product['unit_price']);
        $sheet->setCellValue('H' . $row, $product['last_updated']);
        
        // Highlight low stock items
        if ($product['stock_quantity'] <= $product['reorder_threshold']) {
            $lowStockStyle = [
                'fill' => [
                    'fillType' => \PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID,
                    'startColor' => ['rgb' => 'FFF3CD'],
                ],
            ];
            $sheet->getStyle('A' . $row . ':H' . $row)->applyFromArray($lowStockStyle);
        }
        
        // Highlight out of stock items
        if ($product['stock_quantity'] == 0) {
            $outOfStockStyle = [
                'fill' => [
                    'fillType' => \PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID,
                    'startColor' => ['rgb' => 'F8D7DA'],
                ],
            ];
            $sheet->getStyle('A' . $row . ':H' . $row)->applyFromArray($outOfStockStyle);
        }
        
        $row++;
    }
    
    // Auto size columns
    foreach(range('A','H') as $col) {
        $sheet->getColumnDimension($col)->setAutoSize(true);
    }
    
    // Create the Excel file
    $writer = new Xlsx($spreadsheet);
    
    // Set headers for download
    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="products_inventory_report.xlsx"');
    header('Cache-Control: max-age=0');
    
    $writer->save('php://output');
    exit();
}

$conn->close();
?>
