<?php
session_start();

// Redirect to login page if user is not logged in or not an Inventory Manager
if (!isset($_SESSION['userID']) || $_SESSION['role'] !== 'Inventory Manager') {
    header("Location: index.php");
    exit();
}

// Include database connection
include 'db_connection.php';

// Fetch user fullName for the welcome message
$userID = $_SESSION['userID'];
$sql = "SELECT fullName FROM users WHERE userID = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("s", $userID);
$stmt->execute();
$result = $stmt->get_result();

if ($row = $result->fetch_assoc()) {
    $fullName = $row['fullName'];
} else {
    $fullName = "Inventory Manager";
}

$stmt->close();

// Set default filter values
$dateFrom = isset($_GET['date_from']) ? $_GET['date_from'] : date('Y-m-01'); // Default to first day of current month
$dateTo = isset($_GET['date_to']) ? $_GET['date_to'] : date('Y-m-d'); // Default to today
$categoryFilter = isset($_GET['category']) ? $_GET['category'] : '';
$productFilter = isset($_GET['product']) ? $_GET['product'] : '';
$paymentMethodFilter = isset($_GET['payment_method']) ? $_GET['payment_method'] : '';

// Build the query with potential filters
$query = "SELECT 
            sale_date, 
            COUNT(DISTINCT sale_id) as transactions,
            SUM(quantity_sold) as total_items,
            SUM(total_amount) as total_sales,
            GROUP_CONCAT(DISTINCT payment_method) as payment_methods
          FROM sales_data 
          WHERE 1=1";

$params = [];
$types = "";

if (!empty($dateFrom)) {
    $query .= " AND sale_date >= ?";
    $params[] = $dateFrom;
    $types .= "s";
}

if (!empty($dateTo)) {
    $query .= " AND sale_date <= ?";
    $params[] = $dateTo;
    $types .= "s";
}

if (!empty($categoryFilter)) {
    $query .= " AND category_id = ?";
    $params[] = $categoryFilter;
    $types .= "i";
}

if (!empty($productFilter)) {
    $query .= " AND product_id = ?";
    $params[] = $productFilter;
    $types .= "s";
}

if (!empty($paymentMethodFilter)) {
    $query .= " AND payment_method = ?";
    $params[] = $paymentMethodFilter;
    $types .= "s";
}

$query .= " GROUP BY sale_date ORDER BY sale_date";

// Prepare and execute the query
$stmt = $conn->prepare($query);
if (!empty($params)) {
    $stmt->bind_param($types, ...$params);
}
$stmt->execute();
$result = $stmt->get_result();

// Get detailed sales for the selected period
$detailedQuery = "SELECT 
                    srv.sale_date,
                    srv.product_id,
                    srv.product_name,
                    srv.category_name,
                    SUM(srv.quantity_sold) as quantity_sold,
                    srv.unit_price,
                    SUM(srv.total_amount) as total_amount
                  FROM sales_report_view srv
                  WHERE 1=1";

$detailedParams = [];
$detailedTypes = "";

if (!empty($dateFrom)) {
    $detailedQuery .= " AND srv.sale_date >= ?";
    $detailedParams[] = $dateFrom;
    $detailedTypes .= "s";
}

if (!empty($dateTo)) {
    $detailedQuery .= " AND srv.sale_date <= ?";
    $detailedParams[] = $dateTo;
    $detailedTypes .= "s";
}

if (!empty($categoryFilter)) {
    $detailedQuery .= " AND srv.category_id = ?";
    $detailedParams[] = $categoryFilter;
    $detailedTypes .= "i";
}

if (!empty($productFilter)) {
    $detailedQuery .= " AND srv.product_id = ?";
    $detailedParams[] = $productFilter;
    $detailedTypes .= "s";
}

if (!empty($paymentMethodFilter)) {
    $detailedQuery .= " AND srv.payment_method = ?";
    $detailedParams[] = $paymentMethodFilter;
    $detailedTypes .= "s";
}

$detailedQuery .= " GROUP BY srv.product_id, srv.sale_date 
                   ORDER BY srv.sale_date DESC, srv.total_amount DESC";

$detailedStmt = $conn->prepare($detailedQuery);
if (!empty($detailedParams)) {
    $detailedStmt->bind_param($detailedTypes, ...$detailedParams);
}
$detailedStmt->execute();
$detailedResult = $detailedStmt->get_result();

// Get product categories for the filter dropdown
$categoryQuery = "SELECT category_id, category_name FROM product_categories ORDER BY category_name";
$categoryResult = $conn->query($categoryQuery);

// Get products for the filter dropdown
$productQuery = "SELECT product_id, product_name FROM products ORDER BY product_name";
$productResult = $conn->query($productQuery);

// Calculate summary statistics
$summaryQuery = "SELECT 
                    COUNT(DISTINCT sale_id) as total_transactions,
                    SUM(quantity_sold) as total_items_sold,
                    SUM(total_amount) as total_revenue,
                    COUNT(DISTINCT sale_date) as total_days,
                    AVG(total_amount) as avg_sale_amount,
                    MAX(total_amount) as max_sale_amount,
                    COUNT(DISTINCT product_id) as unique_products
                FROM sales_data
                WHERE 1=1";

$summaryParams = [];
$summaryTypes = "";

if (!empty($dateFrom)) {
    $summaryQuery .= " AND sale_date >= ?";
    $summaryParams[] = $dateFrom;
    $summaryTypes .= "s";
}

if (!empty($dateTo)) {
    $summaryQuery .= " AND sale_date <= ?";
    $summaryParams[] = $dateTo;
    $summaryTypes .= "s";
}

if (!empty($categoryFilter)) {
    $summaryQuery .= " AND category_id = ?";
    $summaryParams[] = $categoryFilter;
    $summaryTypes .= "i";
}

if (!empty($productFilter)) {
    $summaryQuery .= " AND product_id = ?";
    $summaryParams[] = $productFilter;
    $summaryTypes .= "s";
}

if (!empty($paymentMethodFilter)) {
    $summaryQuery .= " AND payment_method = ?";
    $summaryParams[] = $paymentMethodFilter;
    $summaryTypes .= "s";
}

$summaryStmt = $conn->prepare($summaryQuery);
if (!empty($summaryParams)) {
    $summaryStmt->bind_param($summaryTypes, ...$summaryParams);
}
$summaryStmt->execute();
$summaryResult = $summaryStmt->get_result();
$summaryData = $summaryResult->fetch_assoc();

// Get payment method breakdown
$paymentMethodQuery = "SELECT 
                           payment_method,
                           COUNT(*) as transaction_count,
                           SUM(total_amount) as total_amount
                       FROM sales_data
                       WHERE 1=1";

$paymentParams = [];
$paymentTypes = "";

if (!empty($dateFrom)) {
    $paymentMethodQuery .= " AND sale_date >= ?";
    $paymentParams[] = $dateFrom;
    $paymentTypes .= "s";
}

if (!empty($dateTo)) {
    $paymentMethodQuery .= " AND sale_date <= ?";
    $paymentParams[] = $dateTo;
    $paymentTypes .= "s";
}

if (!empty($categoryFilter)) {
    $paymentMethodQuery .= " AND category_id = ?";
    $paymentParams[] = $categoryFilter;
    $paymentTypes .= "i";
}

if (!empty($productFilter)) {
    $paymentMethodQuery .= " AND product_id = ?";
    $paymentParams[] = $productFilter;
    $paymentTypes .= "s";
}

$paymentMethodQuery .= " GROUP BY payment_method";

$paymentStmt = $conn->prepare($paymentMethodQuery);
if (!empty($paymentParams)) {
    $paymentStmt->bind_param($paymentTypes, ...$paymentParams);
}
$paymentStmt->execute();
$paymentResult = $paymentStmt->get_result();

// Get category sales breakdown
$categoryBreakdownQuery = "SELECT 
                              pc.category_id,
                              pc.category_name,
                              SUM(sd.quantity_sold) as items_sold,
                              SUM(sd.total_amount) as total_amount,
                              COUNT(DISTINCT sd.sale_id) as transaction_count
                           FROM sales_data sd
                           JOIN product_categories pc ON sd.category_id = pc.category_id
                           WHERE 1=1";

$categoryParams = [];
$categoryTypes = "";

if (!empty($dateFrom)) {
    $categoryBreakdownQuery .= " AND sd.sale_date >= ?";
    $categoryParams[] = $dateFrom;
    $categoryTypes .= "s";
}

if (!empty($dateTo)) {
    $categoryBreakdownQuery .= " AND sd.sale_date <= ?";
    $categoryParams[] = $dateTo;
    $categoryTypes .= "s";
}

if (!empty($categoryFilter)) {
    $categoryBreakdownQuery .= " AND sd.category_id = ?";
    $categoryParams[] = $categoryFilter;
    $categoryTypes .= "i";
}

if (!empty($productFilter)) {
    $categoryBreakdownQuery .= " AND sd.product_id = ?";
    $categoryParams[] = $productFilter;
    $categoryTypes .= "s";
}

if (!empty($paymentMethodFilter)) {
    $categoryBreakdownQuery .= " AND sd.payment_method = ?";
    $categoryParams[] = $paymentMethodFilter;
    $categoryTypes .= "s";
}

$categoryBreakdownQuery .= " GROUP BY pc.category_id, pc.category_name
                           ORDER BY total_amount DESC";

$categoryBreakdownStmt = $conn->prepare($categoryBreakdownQuery);
if (!empty($categoryParams)) {
    $categoryBreakdownStmt->bind_param($categoryTypes, ...$categoryParams);
}
$categoryBreakdownStmt->execute();
$categoryBreakdownResult = $categoryBreakdownStmt->get_result();

// Get top 5 selling products
$topProductsQuery = "SELECT 
                        p.product_id,
                        p.product_name,
                        pc.category_name,
                        SUM(sd.quantity_sold) as total_quantity,
                        SUM(sd.total_amount) as total_amount
                     FROM sales_data sd
                     JOIN products p ON sd.product_id = p.product_id
                     JOIN product_categories pc ON sd.category_id = pc.category_id
                     WHERE 1=1";

$topProductsParams = [];
$topProductsTypes = "";

if (!empty($dateFrom)) {
    $topProductsQuery .= " AND sd.sale_date >= ?";
    $topProductsParams[] = $dateFrom;
    $topProductsTypes .= "s";
}

if (!empty($dateTo)) {
    $topProductsQuery .= " AND sd.sale_date <= ?";
    $topProductsParams[] = $dateTo;
    $topProductsTypes .= "s";
}

if (!empty($categoryFilter)) {
    $topProductsQuery .= " AND sd.category_id = ?";
    $topProductsParams[] = $categoryFilter;
    $topProductsTypes .= "i";
}

if (!empty($paymentMethodFilter)) {
    $topProductsQuery .= " AND sd.payment_method = ?";
    $topProductsParams[] = $paymentMethodFilter;
    $topProductsTypes .= "s";
}

$topProductsQuery .= " GROUP BY p.product_id, p.product_name, pc.category_name
                      ORDER BY total_amount DESC
                      LIMIT 5";

$topProductsStmt = $conn->prepare($topProductsQuery);
if (!empty($topProductsParams)) {
    $topProductsStmt->bind_param($topProductsTypes, ...$topProductsParams);
}
$topProductsStmt->execute();
$topProductsResult = $topProductsStmt->get_result();

// Prepare data for charts in JSON format
$dailySalesData = [];
while ($row = $result->fetch_assoc()) {
    $dailySalesData[] = [
        'date' => $row['sale_date'],
        'sales' => floatval($row['total_sales']),
        'items' => intval($row['total_items']),
        'transactions' => intval($row['transactions'])
    ];
}

// Prepare category breakdown data for charts
$categoryLabels = [];
$categorySales = [];
$categoryItems = [];
$categoryBreakdownResult->data_seek(0);
while ($row = $categoryBreakdownResult->fetch_assoc()) {
    $categoryLabels[] = $row['category_name'];
    $categorySales[] = floatval($row['total_amount']);
    $categoryItems[] = intval($row['items_sold']);
}

// Prepare payment method data for charts
$paymentLabels = [];
$paymentAmounts = [];
$paymentResult->data_seek(0);
while ($row = $paymentResult->fetch_assoc()) {
    $paymentLabels[] = $row['payment_method'];
    $paymentAmounts[] = floatval($row['total_amount']);
}

// Prepare top products data for charts
$productLabels = [];
$productAmounts = [];
$topProductsResult->data_seek(0);
while ($row = $topProductsResult->fetch_assoc()) {
    $productLabels[] = $row['product_name'];
    $productAmounts[] = floatval($row['total_amount']);
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sales Report - Roti Seri Bakery</title>
    <link rel="stylesheet" href="admin_dashboard.css">
    <link rel="stylesheet" href="sidebar.css">
    <link rel="stylesheet" href="imanager_salesreport.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>

<body>
    <div class="sidebar-container">
        <div class="header-section">
            <div class="company-logo">
                <img src="image/icon/logo.png" class="logo-icon" alt="Company Logo">
                <div class="company-text">
                    <span class="company-name">RotiSeri</span>
                    <span class="company-name2">Inventory</span>
                </div>
            </div>

            <nav class="nav-container" role="navigation">
                <a href="imanager_dashboard.php" class="nav-item">
                    <i class="fas fa-home"></i>
                    <div class="nav-text">Home</div>
                </a>
                <a href="imanager_invmanagement.php" class="nav-item">
                    <i class="fas fa-boxes"></i>
                    <div class="nav-text">Manage Inventory</div>
                </a>
                <a href="imanager_supplierpurchase.php" class="nav-item">
                    <i class="fas fa-truck-loading"></i>
                    <div class="nav-text">View Supplier Purchases</div>
                </a>
                <a href="imanager_salesreport.php" class="nav-item active">
                    <i class="fas fa-chart-line"></i>
                    <div class="nav-text">Sales Report</div>
                </a>
                <a href="profile.php" class="nav-item">
                    <i class="fas fa-user-circle"></i>
                    <div class="nav-text">My Profile</div>
                </a>
                <a href="logout.php" class="nav-item">
                    <i class="fas fa-sign-out-alt nav-icon"></i>
                    <div class="nav-text">Log Out</div>
                </a>
            </nav>
        </div>

        <div class="footer-section"></div>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <div class="dashboard-header">
            <h1>Sales Report</h1>
            <p>Welcome, <?php echo htmlspecialchars($fullName); ?>!</p>
        </div>

        <!-- Filter Section -->
        <div class="filter-section">
            <h2><i class="fas fa-filter"></i> Filter Sales Data</h2>
            <form method="GET" action="imanager_salesreport.php" id="filterForm">
                <div class="filter-row">
                    <div class="filter-group">
                        <label for="date_from">Date From:</label>
                        <input type="date" name="date_from" id="date_from" value="<?php echo $dateFrom; ?>">
                    </div>

                    <div class="filter-group">
                        <label for="date_to">Date To:</label>
                        <input type="date" name="date_to" id="date_to" value="<?php echo $dateTo; ?>">
                    </div>
                </div>

                <div class="filter-row">
                    <div class="filter-group">
                        <label for="category">Category:</label>
                        <select name="category" id="category">
                            <option value="">All Categories</option>
                            <?php 
                            $categoryResult->data_seek(0);
                            while ($category = $categoryResult->fetch_assoc()): 
                            ?>
                                <option value="<?php echo $category['category_id']; ?>" 
                                    <?php echo ($categoryFilter == $category['category_id']) ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($category['category_name']); ?>
                                </option>
                            <?php endwhile; ?>
                        </select>
                    </div>

                    <div class="filter-group">
                        <label for="product">Product:</label>
                        <select name="product" id="product">
                            <option value="">All Products</option>
                            <?php 
                            while ($product = $productResult->fetch_assoc()): 
                            ?>
                                <option value="<?php echo $product['product_id']; ?>" 
                                    <?php echo ($productFilter == $product['product_id']) ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($product['product_name']); ?>
                                </option>
                            <?php endwhile; ?>
                        </select>
                    </div>

                    <div class="filter-group">
                        <label for="payment_method">Payment Method:</label>
                        <select name="payment_method" id="payment_method">
                            <option value="">All Methods</option>
                            <option value="Cash" <?php echo ($paymentMethodFilter == 'Cash') ? 'selected' : ''; ?>>Cash</option>
                            <option value="Card" <?php echo ($paymentMethodFilter == 'Card') ? 'selected' : ''; ?>>Card</option>
                            <option value="Online" <?php echo ($paymentMethodFilter == 'Online') ? 'selected' : ''; ?>>Online</option>
                        </select>
                    </div>
                </div>

                <div class="filter-buttons">
                    <button type="submit" class="filter-btn apply-btn"><i class="fas fa-search"></i> Apply Filters</button>
                    <button type="button" class="filter-btn reset-btn" id="resetFilters"><i class="fas fa-sync"></i> Reset Filters</button>
                </div>
            </form>
        </div>

        <!-- Summary Statistics -->
        <div class="stats-container">
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-cash-register"></i>
                </div>
                <div class="stat-details">
                    <h3>Total Sales</h3>
                    <p class="stat-value">RM <?php echo number_format($summaryData['total_revenue'] ?? 0, 2); ?></p>
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-shopping-basket"></i>
                </div>
                <div class="stat-details">
                    <h3>Items Sold</h3>
                    <p class="stat-value"><?php echo number_format($summaryData['total_items_sold'] ?? 0); ?></p>
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-receipt"></i>
                </div>
                <div class="stat-details">
                    <h3>Transactions</h3>
                    <p class="stat-value"><?php echo number_format($summaryData['total_transactions'] ?? 0); ?></p>
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-chart-bar"></i>
                </div>
                <div class="stat-details">
                    <h3>Avg. Transaction</h3>
                    <p class="stat-value">RM <?php echo number_format($summaryData['avg_sale_amount'] ?? 0, 2); ?></p>
                </div>
            </div>
        </div>

        <!-- Charts Section -->
        <div class="charts-section">
            <div class="chart-container full-width">
                <h2><i class="fas fa-chart-line"></i> Daily Sales Trend</h2>
                <div class="chart-box">
                    <canvas id="dailySalesChart"></canvas>
                </div>
            </div>
            
            <div class="chart-container">
                <h2><i class="fas fa-chart-pie"></i> Sales by Category</h2>
                <div class="chart-box">
                    <canvas id="categorySalesChart"></canvas>
                </div>
            </div>
            
            <div class="chart-container">
                <h2><i class="fas fa-chart-bar"></i> Top 5 Products</h2>
                <div class="chart-box">
                    <canvas id="topProductsChart"></canvas>
                </div>
            </div>
            
            <div class="chart-container">
                <h2><i class="fas fa-wallet"></i> Payment Methods</h2>
                <div class="chart-box">
                    <canvas id="paymentMethodsChart"></canvas>
                </div>
            </div>
        </div>

        <!-- Detailed Sales Table -->
        <div class="table-section">
            <div class="table-header">
                <h2><i class="fas fa-table"></i> Detailed Sales Report</h2>
                <div class="period-info">
                    Period: <?php echo date('d M Y', strtotime($dateFrom)); ?> - <?php echo date('d M Y', strtotime($dateTo)); ?>
                </div>
            </div>
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Date</th>
                            <th>Product</th>
                            <th>Category</th>
                            <th>Quantity</th>
                            <th>Unit Price</th>
                            <th>Total</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if ($detailedResult->num_rows > 0): ?>
                            <?php while ($row = $detailedResult->fetch_assoc()): ?>
                                <tr>
                                    <td><?php echo date('d M Y', strtotime($row['sale_date'])); ?></td>
                                    <td><?php echo htmlspecialchars($row['product_name']); ?></td>
                                    <td><?php echo htmlspecialchars($row['category_name']); ?></td>
                                    <td><?php echo $row['quantity_sold']; ?></td>
                                    <td>RM <?php echo number_format($row['unit_price'], 2); ?></td>
                                    <td>RM <?php echo number_format($row['total_amount'], 2); ?></td>
                                </tr>
                            <?php endwhile; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="6" class="no-data">No sales data found for the selected criteria.</td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Category Breakdown Table -->
        <div class="table-section">
            <div class="table-header">
                <h2><i class="fas fa-tags"></i> Sales by Category</h2>
            </div>
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Category</th>
                            <th>Items Sold</th>
                            <th>Transactions</th>
                            <th>Total Sales</th>
                            <th>% of Total</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php 
                        $categoryBreakdownResult->data_seek(0);
                        $totalSales = $summaryData['total_revenue'] ?? 0;
                        if ($categoryBreakdownResult->num_rows > 0):
                            while ($row = $categoryBreakdownResult->fetch_assoc()):
                                $percentage = ($totalSales > 0) ? ($row['total_amount'] / $totalSales) * 100 : 0;
                        ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($row['category_name']); ?></td>
                                    <td><?php echo number_format($row['items_sold']); ?></td>
                                    <td><?php echo number_format($row['transaction_count']); ?></td>
                                    <td>RM <?php echo number_format($row['total_amount'], 2); ?></td>
                                    <td><?php echo number_format($percentage, 1); ?>%</td>
                                </tr>
                        <?php 
                            endwhile;
                        else:
                        ?>
                            <tr>
                                <td colspan="5" class="no-data">No category data available.</td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script src="imanager_salesreport.js"></script>
    <script>
        // JavaScript to handle the sales report functionality
        document.addEventListener('DOMContentLoaded', function() {
            // Initialize event listeners
            initEventListeners();
            
            // Initialize charts
            initializeCharts();
        });

        // Daily sales data from PHP
        const dailySalesData = <?php echo json_encode($dailySalesData); ?>;
        
        // Category data from PHP
        const categoryLabels = <?php echo json_encode($categoryLabels); ?>;
        const categorySales = <?php echo json_encode($categorySales); ?>;
        const categoryItems = <?php echo json_encode($categoryItems); ?>;
        
        // Payment methods data from PHP
        const paymentLabels = <?php echo json_encode($paymentLabels); ?>;
        const paymentAmounts = <?php echo json_encode($paymentAmounts); ?>;
        
        // Top products data from PHP
        const productLabels = <?php echo json_encode($productLabels); ?>;
        const productAmounts = <?php echo json_encode($productAmounts); ?>;
    </script>
</body>
</html>