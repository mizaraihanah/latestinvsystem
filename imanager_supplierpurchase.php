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

// Fetch all suppliers for the filter dropdown
$supplierQuery = "SELECT DISTINCT customer_name FROM orders WHERE order_type = 'Purchase' ORDER BY customer_name";
$supplierResult = $conn->query($supplierQuery);

// Calculate summary statistics
$totalQuery = "SELECT COUNT(*) as total_orders, SUM(total_amount) as total_spent, 
              COUNT(DISTINCT customer_name) as supplier_count
              FROM orders WHERE order_type = 'Purchase'";
$totalResult = $conn->query($totalQuery);
$totalStats = $totalResult->fetch_assoc();

// Get recently received orders (completed in the last 30 days)
$recentQuery = "SELECT COUNT(*) as recent_orders, SUM(total_amount) as recent_spent
               FROM orders 
               WHERE order_type = 'Purchase' 
               AND status = 'Completed' 
               AND order_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)";
$recentResult = $conn->query($recentQuery);
$recentStats = $recentResult->fetch_assoc();

// Get pending order count and value
$pendingQuery = "SELECT COUNT(*) as pending_orders, SUM(total_amount) as pending_amount
                FROM orders 
                WHERE order_type = 'Purchase' 
                AND status = 'Pending'";
$pendingResult = $conn->query($pendingQuery);
$pendingStats = $pendingResult->fetch_assoc();

// Get top suppliers by order count
$topSuppliersQuery = "SELECT customer_name, COUNT(*) as order_count, SUM(total_amount) as total_spent
                     FROM orders 
                     WHERE order_type = 'Purchase'
                     GROUP BY customer_name
                     ORDER BY order_count DESC
                     LIMIT 5";
$topSuppliersResult = $conn->query($topSuppliersQuery);

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Supplier Purchases - Roti Seri Bakery</title>
    <link rel="stylesheet" href="admin_dashboard.css">
    <link rel="stylesheet" href="sidebar.css">
    <style>
        /* Essential styles for Supplier Purchases Page */
        .main-content {
            margin-left: 230px;
            padding: 20px;
        }

        /* Stats Container */
        .stats-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }

        .stat-card {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            padding: 15px;
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .stat-icon {
            width: 40px;
            height: 40px;
            background-color: #f0f7ff;
            border-radius: 8px;
            display: flex;
            justify-content: center;
            align-items: center;
            color: #0561FC;
        }

        .pending-icon {
            background-color: #fff8e1;
            color: #ff9800;
        }

        .stat-details h3 {
            margin: 0;
            font-size: 14px;
            color: #666;
        }

        .stat-value {
            font-size: 20px;
            font-weight: bold;
            color: #333;
            margin: 5px 0 0 0;
        }

        .stat-subtext {
            font-size: 12px;
            color: #888;
            margin: 0;
        }

        /* Filter Section */
        .filter-section {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            padding: 15px;
            margin-bottom: 20px;
        }

        .filter-section h2 {
            margin-top: 0;
            margin-bottom: 15px;
            font-size: 18px;
        }

        #filterForm {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            align-items: flex-end;
        }

        .filter-group {
            flex: 1;
            min-width: 150px;
        }

        .filter-group label {
            display: block;
            font-size: 14px;
            margin-bottom: 5px;
        }

        .filter-group select,
        .filter-group input {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }

        .filter-buttons {
            display: flex;
            gap: 10px;
        }

        .filter-btn {
            padding: 8px 12px;
            border-radius: 4px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 5px;
        }

        .apply-btn {
            background-color: #0561FC;
            color: white;
            border: none;
        }

        .reset-btn {
            background-color: #f5f5f5;
            color: #333;
            border: 1px solid #ddd;
        }

        /* Purchases Table */
        .purchases-table-container {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
            overflow: hidden;
        }

        .table-header {
            padding: 15px;
            border-bottom: 1px solid #eee;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .table-actions {
            display: flex;
            gap: 10px;
        }

        .export-btn {
            padding: 8px 12px;
            background-color: #f5f5f5;
            color: #333;
            border: 1px solid #ddd;
            border-radius: 4px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 5px;
        }

        .table-responsive {
            overflow-x: auto;
            padding: 0 15px 15px;
        }

        .purchases-table {
            width: 100%;
            border-collapse: collapse;
        }

        .purchases-table th,
        .purchases-table td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }

        .purchases-table th {
            background-color: #f8f9fa;
            font-weight: bold;
        }

        /* Status Badges */
        .status-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 20px;
            font-size: 12px;
            background-color: #f5f5f5;
        }

        .status-pending {
            background-color: #fff8e1;
            color: #ff9800;
        }

        .status-processing {
            background-color: #e3f2fd;
            color: #2196f3;
        }

        .status-completed {
            background-color: #e8f5e9;
            color: #4caf50;
        }

        .status-cancelled {
            background-color: #feebee;
            color: #f44336;
        }

        /* Action Buttons */
        .action-buttons {
            display: flex;
            gap: 5px;
        }

        .action-btn {
            width: 28px;
            height: 28px;
            border-radius: 4px;
            display: flex;
            justify-content: center;
            align-items: center;
            border: none;
            cursor: pointer;
        }

        .view-btn {
            background-color: #e3f2fd;
            color: #2196f3;
        }

        .print-btn {
            background-color: #e8f5e9;
            color: #4caf50;
        }

        /* Analytics Section */
        .analytics-section {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            overflow: hidden;
            margin-bottom: 20px;
        }

        .analytics-header {
            padding: 15px;
            border-bottom: 1px solid #eee;
        }

        .analytics-container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            padding: 15px;
        }

        .chart-box {
            background-color: #f8f9fa;
            border-radius: 8px;
            padding: 15px;
            min-height: 250px;
        }

        .chart-box h3 {
            margin-top: 0;
            margin-bottom: 15px;
            font-size: 16px;
            text-align: center;
        }

        .recent-stats {
            display: flex;
            flex-direction: column;
            gap: 15px;
            justify-content: center;
            align-items: center;
            height: 100%;
        }

        .recent-stat {
            text-align: center;
            padding: 15px;
            background-color: white;
            border-radius: 8px;
            width: 80%;
        }

        .recent-value {
            display: block;
            font-size: 24px;
            font-weight: bold;
            color: #0561FC;
            margin-bottom: 5px;
        }

        .recent-label {
            display: block;
            font-size: 14px;
            color: #666;
        }

        /* Modal styles */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            z-index: 1000;
        }

        .modal-content {
            background-color: white;
            margin: 50px auto;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
            width: 80%;
            max-width: 800px;
            position: relative;
        }

        .close-modal {
            position: absolute;
            top: 10px;
            right: 15px;
            font-size: 24px;
            color: #aaa;
            cursor: pointer;
        }

        /* Responsive adjustments */
        @media (max-width: 768px) {
            .analytics-container {
                grid-template-columns: 1fr;
            }
            
            .filter-group {
                min-width: 100%;
            }
        }
    </style>
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
                <a href="imanager_supplierpurchase.php" class="nav-item active">
                    <i class="fas fa-truck-loading"></i>
                    <div class="nav-text">View Supplier Purchases</div>
                </a>
                <a href="imanager_salesreport.php" class="nav-item">
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
            <h1>Supplier Purchases</h1>
            <p>Welcome, <?php echo htmlspecialchars($fullName); ?>!</p>
        </div>

        <!-- Summary Statistics -->
        <div class="stats-container">
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-shopping-cart"></i>
                </div>
                <div class="stat-details">
                    <h3>Total Orders</h3>
                    <p class="stat-value"><?php echo number_format($totalStats['total_orders']); ?></p>
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-money-bill-wave"></i>
                </div>
                <div class="stat-details">
                    <h3>Total Spent</h3>
                    <p class="stat-value">RM <?php echo number_format($totalStats['total_spent'], 2); ?></p>
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-truck"></i>
                </div>
                <div class="stat-details">
                    <h3>Suppliers</h3>
                    <p class="stat-value"><?php echo number_format($totalStats['supplier_count']); ?></p>
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon pending-icon">
                    <i class="fas fa-clock"></i>
                </div>
                <div class="stat-details">
                    <h3>Pending Orders</h3>
                    <p class="stat-value"><?php echo number_format($pendingStats['pending_orders']); ?></p>
                    <p class="stat-subtext">RM <?php echo number_format($pendingStats['pending_amount'], 2); ?></p>
                </div>
            </div>
        </div>

        <!-- Filter Section -->
        <div class="filter-section">
            <h2><i class="fas fa-filter"></i> Filter Purchases</h2>
            <form method="GET" action="imanager_supplierpurchase.php" id="filterForm">
                <div class="filter-group">
                    <label for="supplier">Supplier:</label>
                    <select name="supplier" id="supplier">
                        <option value="">All Suppliers</option>
                        <?php while ($supplier = $supplierResult->fetch_assoc()): ?>
                            <option value="<?php echo htmlspecialchars($supplier['customer_name']); ?>" 
                                <?php echo ($supplierFilter === $supplier['customer_name']) ? 'selected' : ''; ?>>
                                <?php echo htmlspecialchars($supplier['customer_name']); ?>
                            </option>
                        <?php endwhile; ?>
                    </select>
                </div>

                <div class="filter-group">
                    <label for="date_from">Date From:</label>
                    <input type="date" name="date_from" id="date_from" value="<?php echo $dateFrom; ?>">
                </div>

                <div class="filter-group">
                    <label for="date_to">Date To:</label>
                    <input type="date" name="date_to" id="date_to" value="<?php echo $dateTo; ?>">
                </div>

                <div class="filter-group">
                    <label for="status">Status:</label>
                    <select name="status" id="status">
                        <option value="">All Statuses</option>
                        <option value="Pending" <?php echo ($statusFilter === 'Pending') ? 'selected' : ''; ?>>Pending</option>
                        <option value="Processing" <?php echo ($statusFilter === 'Processing') ? 'selected' : ''; ?>>Processing</option>
                        <option value="Completed" <?php echo ($statusFilter === 'Completed') ? 'selected' : ''; ?>>Completed</option>
                        <option value="Cancelled" <?php echo ($statusFilter === 'Cancelled') ? 'selected' : ''; ?>>Cancelled</option>
                    </select>
                </div>

                <div class="filter-buttons">
                    <button type="submit" class="filter-btn apply-btn"><i class="fas fa-search"></i> Apply Filters</button>
                    <button type="button" class="filter-btn reset-btn" id="resetFilters"><i class="fas fa-sync"></i> Reset Filters</button>
                </div>
            </form>
        </div>

        <!-- Purchases Table -->
        <div class="purchases-table-container">
            <div class="table-header">
                <h2><i class="fas fa-list"></i> Purchase Orders</h2>
                <div class="table-actions">
                    <button class="export-btn" id="exportPDF"><i class="fas fa-file-pdf"></i> Export PDF</button>
                    <button class="export-btn" id="exportExcel"><i class="fas fa-file-excel"></i> Export Excel</button>
                </div>
            </div>
            
            <div class="table-responsive">
                <table class="purchases-table">
                    <thead>
                        <tr>
                            <th>Order ID</th>
                            <th>Supplier</th>
                            <th>Order Date</th>
                            <th>Items</th>
                            <th>Total Amount</th>
                            <th>Status</th>
                            <th>Created By</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if ($result->num_rows > 0): ?>
                            <?php while ($row = $result->fetch_assoc()): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($row['order_id']); ?></td>
                                    <td><?php echo htmlspecialchars($row['customer_name']); ?></td>
                                    <td><?php echo htmlspecialchars($row['order_date']); ?></td>
                                    <td><?php echo htmlspecialchars($row['item_count']); ?></td>
                                    <td>RM <?php echo number_format($row['total_amount'], 2); ?></td>
                                    <td>
                                        <span class="status-badge status-<?php echo strtolower($row['status']); ?>">
                                            <?php echo htmlspecialchars($row['status']); ?>
                                        </span>
                                    </td>
                                    <td><?php echo htmlspecialchars($row['created_by_name']); ?></td>
                                    <td>
                                        <div class="action-buttons">
                                            <button class="action-btn view-btn" data-id="<?php echo $row['order_id']; ?>" 
                                                    onclick="viewPurchaseDetails('<?php echo $row['order_id']; ?>')">
                                                <i class="fas fa-eye"></i>
                                            </button>
                                            <button class="action-btn print-btn" data-id="<?php echo $row['order_id']; ?>"
                                                    onclick="printPurchaseOrder('<?php echo $row['order_id']; ?>')">
                                                <i class="fas fa-print"></i>
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            <?php endwhile; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="8" class="no-records">No purchase orders found</td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Analytics Dashboard -->
        <div class="analytics-section">
            <div class="analytics-header">
                <h2><i class="fas fa-chart-pie"></i> Purchase Analytics</h2>
            </div>
            
            <div class="analytics-container">
                <div class="chart-box">
                    <h3>Top Suppliers</h3>
                    <canvas id="topSuppliersChart"></canvas>
                </div>
                
                <div class="chart-box">
                    <h3>Recent Orders</h3>
                    <div class="recent-stats">
                        <div class="recent-stat">
                            <span class="recent-value"><?php echo number_format($recentStats['recent_orders']); ?></span>
                            <span class="recent-label">Orders in Last 30 Days</span>
                        </div>
                        <div class="recent-stat">
                            <span class="recent-value">RM <?php echo number_format($recentStats['recent_spent'], 2); ?></span>
                            <span class="recent-label">Amount Spent</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Purchase Details Modal -->
    <div id="purchaseDetailsModal" class="modal">
        <div class="modal-content">
            <span class="close-modal">&times;</span>
            <h2>Purchase Order Details</h2>
            <div id="purchaseDetailsContent">
                <!-- Content will be loaded here -->
            </div>
        </div>
    </div>

    <script src="imanager_supplierpurchase.js"></script>
    <script>
        // Data for Top Suppliers Chart
        const topSuppliersData = {
            labels: [
                <?php 
                $topSupplierNames = [];
                $topSupplierCounts = [];
                $topSupplierColors = ['#4e73df', '#1cc88a', '#36b9cc', '#f6c23e', '#e74a3b'];
                
                $topSuppliersResult->data_seek(0);
                $i = 0;
                while ($supplier = $topSuppliersResult->fetch_assoc()) {
                    $topSupplierNames[] = "'" . addslashes($supplier['customer_name']) . "'";
                    $topSupplierCounts[] = $supplier['order_count'];
                    $i++;
                }
                echo implode(", ", $topSupplierNames);
                ?>
            ],
            values: [<?php echo implode(", ", $topSupplierCounts); ?>],
            colors: <?php echo json_encode($topSupplierColors); ?>
        };

        // Initialize Charts on page load
        document.addEventListener('DOMContentLoaded', function() {
            // Top Suppliers Chart
            const topSuppliersCtx = document.getElementById('topSuppliersChart').getContext('2d');
            new Chart(topSuppliersCtx, {
                type: 'doughnut',
                data: {
                    labels: topSuppliersData.labels,
                    datasets: [{
                        data: topSuppliersData.values,
                        backgroundColor: topSuppliersData.colors,
                        hoverBackgroundColor: topSuppliersData.colors,
                        hoverBorderColor: "rgba(234, 236, 244, 1)",
                    }]
                },
                options: {
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right',
                        }
                    },
                    cutout: '70%',
                }
            });
        });
    </script>
</body>
</html>