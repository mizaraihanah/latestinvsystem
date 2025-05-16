<?php
session_start();

// Redirect to login page if user is not logged in
if (!isset($_SESSION['userID']) || $_SESSION['role'] !== 'Bakery Staff') {
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
    $fullName = "Staff"; 
}

$stmt->close();

// Fetch inventory stats
$sql_products = "SELECT COUNT(*) AS total_products FROM products";
$result_products = $conn->query($sql_products);
$row_products = $result_products->fetch_assoc();
$totalProducts = $row_products['total_products'];

// Get count of products below threshold (low stock)
$threshold_sql = "SELECT COUNT(*) as low_stock_count FROM products WHERE stock_quantity <= reorder_threshold";
$threshold_result = $conn->query($threshold_sql);
$threshold_row = $threshold_result->fetch_assoc();
$low_stock_count = $threshold_row['low_stock_count'];

// Get count of out of stock products
$outofstock_sql = "SELECT COUNT(*) as outofstock_count FROM products WHERE stock_quantity = 0";
$outofstock_result = $conn->query($outofstock_sql);
$outofstock_row = $outofstock_result->fetch_assoc();
$outofstock_count = $outofstock_row['outofstock_count'];

// Get count of suppliers
$supplier_sql = "SELECT COUNT(DISTINCT customer_name) as supplier_count FROM orders WHERE order_type = 'Purchase'";
$supplier_result = $conn->query($supplier_sql);
$supplier_row = $supplier_result->fetch_assoc();
$supplier_count = $supplier_row['supplier_count'] ?? 0;

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Staff Dashboard - Roti Seri Bakery</title>
    <link rel="stylesheet" href="staff_dashboard.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>

<body>
    <div class="sidebar">
        <div class="sidebar-header">
            <div class="logo-container">
                <img src="image/icon/logo.png" alt="Roti Seri Logo" class="logo">
                <div class="company-text">
                    <span class="company-name">RotiSeri</span>
                    <span class="company-role">Staff</span>
                </div>
            </div>
        </div>
        
        <nav class="sidebar-nav">
            <a href="staff_dashboard.php" class="nav-item active">
                <i class="fas fa-home"></i>
                <span>Home</span>
            </a>
            <a href="staff_manageinventory.php" class="nav-item">
                <i class="fas fa-boxes"></i>
                <span>Manage Inventory</span>
            </a>
            <a href="staff_suppliers.php" class="nav-item">
                <i class="fas fa-truck"></i>
                <span>Manage Suppliers</span>
            </a>
            <a href="staff_alerts.php" class="nav-item">
                <i class="fas fa-bell"></i>
                <span>Alerts</span>
                <?php if ($low_stock_count > 0): ?>
                <span class="badge"><?php echo $low_stock_count; ?></span>
                <?php endif; ?>
            </a>
            <a href="profile.php" class="nav-item">
                <i class="fas fa-user-circle"></i>
                <span>My Profile</span>
            </a>
            <a href="logout.php" class="nav-item">
                <i class="fas fa-sign-out-alt"></i>
                <span>Logout</span>
            </a>
        </nav>
    </div>

    <div class="main-content">
        <div class="header">
            <div class="welcome-container">
                <h1>Welcome, <?php echo htmlspecialchars($fullName); ?>!</h1>
                <p>Today is <?php echo date('l, F j, Y'); ?></p>
            </div>
            <div class="user-info">
                <span class="user-name"><?php echo htmlspecialchars($fullName); ?></span>
                <span class="user-role">Bakery Staff</span>
            </div>
        </div>

        <div class="dashboard-stats">
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-boxes"></i>
                </div>
                <div class="stat-info">
                    <h3>Total Products</h3>
                    <p><?php echo $totalProducts; ?></p>
                </div>
            </div>
            
            <div class="stat-card alert">
                <div class="stat-icon">
                    <i class="fas fa-exclamation-triangle"></i>
                </div>
                <div class="stat-info">
                    <h3>Low Stock Items</h3>
                    <p><?php echo $low_stock_count; ?></p>
                </div>
            </div>
            
            <div class="stat-card danger">
                <div class="stat-icon">
                    <i class="fas fa-times-circle"></i>
                </div>
                <div class="stat-info">
                    <h3>Out of Stock</h3>
                    <p><?php echo $outofstock_count; ?></p>
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-truck"></i>
                </div>
                <div class="stat-info">
                    <h3>Suppliers</h3>
                    <p><?php echo $supplier_count; ?></p>
                </div>
            </div>
        </div>

        <div class="dashboard-widgets">
            <div class="widget">
                <div class="widget-header">
                    <h3>Recent Activity</h3>
                </div>
                <div class="widget-content recent-activity">
                    <p class="no-data-message">No recent activity to display.</p>
                    <!-- Will be populated with actual data in the future -->
                </div>
            </div>
            
            <div class="widget">
                <div class="widget-header">
                    <h3>Stock Overview</h3>
                </div>
                <div class="widget-content">
                    <canvas id="stockChart"></canvas>
                </div>
            </div>
        </div>

        <div class="dashboard-widgets">
            <div class="widget full-width">
                <div class="widget-header">
                    <h3>Low Stock Items</h3>
                    <a href="staff_alerts.php" class="view-all">View All</a>
                </div>
                <div class="widget-content">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Product ID</th>
                                <th>Product Name</th>
                                <th>Current Stock</th>
                                <th>Threshold</th>
                                <th>Status</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td colspan="6" class="no-data-message">No low stock items to display.</td>
                            </tr>
                            <!-- Will be populated with actual data in the future -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Sample data for the chart - will be replaced with actual data from the database
        const ctx = document.getElementById('stockChart').getContext('2d');
        const stockChart = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: ['Normal Stock', 'Low Stock', 'Out of Stock'],
                datasets: [{
                    data: [<?php echo $totalProducts - $low_stock_count; ?>, 
                          <?php echo $low_stock_count - $outofstock_count; ?>, 
                          <?php echo $outofstock_count; ?>],
                    backgroundColor: ['#4CAF50', '#FFC107', '#F44336'],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'right',
                    },
                    title: {
                        display: true,
                        text: 'Inventory Status Distribution'
                    }
                }
            }
        });
    </script>
</body>

</html>