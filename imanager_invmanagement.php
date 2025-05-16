<?php
session_start();

// Redirect to login page if user is not logged in
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

// Function to generate a unique product ID
function generateProductID($conn) {
    $prefix = "PROD";
    $sql = "SELECT MAX(CAST(SUBSTRING(product_id, 5) AS UNSIGNED)) as max_id FROM products WHERE product_id LIKE 'PROD%'";
    $result = $conn->query($sql);
    $row = $result->fetch_assoc();
    $maxID = $row['max_id'] ?? 0;
    $newID = $maxID + 1;
    return $prefix . str_pad($newID, 4, '0', STR_PAD_LEFT);
}

// Function to log inventory activities
function logInventoryActivity($conn, $userID, $action, $itemID, $details) {
    $sql = "INSERT INTO inventory_logs (user_id, action, item_id, action_details, timestamp, ip_address) 
            VALUES (?, ?, ?, ?, NOW(), ?)";
    $stmt = $conn->prepare($sql);
    $ipAddress = $_SERVER['REMOTE_ADDR'];
    $stmt->bind_param("sssss", $userID, $action, $itemID, $details, $ipAddress);
    $stmt->execute();
    $stmt->close();
}

// Fetch product categories
$sql_categories = "SELECT * FROM product_categories ORDER BY category_name";
$result_categories = $conn->query($sql_categories);

// Fetch products with their categories
$sql_products = "SELECT p.*, c.category_name 
                FROM products p 
                LEFT JOIN product_categories c ON p.category_id = c.category_id 
                ORDER BY p.product_name";
$result_products = $conn->query($sql_products);

// Fetch inventory logs
$sql_logs = "SELECT l.*, u.fullName 
            FROM inventory_logs l 
            JOIN users u ON l.user_id = u.userID 
            ORDER BY l.timestamp DESC 
            LIMIT 100";
$result_logs = $conn->query($sql_logs);

// Fetch orders
$sql_orders = "SELECT o.*, u.fullName 
              FROM orders o 
              LEFT JOIN users u ON o.created_by = u.userID 
              ORDER BY o.order_date DESC";
$result_orders = $conn->query($sql_orders);

// Perform CRUD operations based on form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // Add New Product Category
    if (isset($_POST['add_category'])) {
        $categoryName = trim($_POST['category_name']);
        $categoryDesc = trim($_POST['category_description']);
        
        if (!empty($categoryName)) {
            $sql = "INSERT INTO product_categories (category_name, description) VALUES (?, ?)";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param("ss", $categoryName, $categoryDesc);
            
            if ($stmt->execute()) {
                $categoryId = $conn->insert_id;
                logInventoryActivity($conn, $userID, "add_category", $categoryId, "Added new category: $categoryName");
                header("Location: imanager_invmanagement.php?success=Category added successfully");
            } else {
                header("Location: imanager_invmanagement.php?error=Failed to add category");
            }
            $stmt->close();
            exit();
        }
    }
    
    // Update Product Category
    if (isset($_POST['update_category'])) {
        $categoryId = $_POST['category_id'];
        $categoryName = trim($_POST['category_name']);
        $categoryDesc = trim($_POST['category_description']);
        
        if (!empty($categoryId) && !empty($categoryName)) {
            $sql = "UPDATE product_categories SET category_name = ?, description = ? WHERE category_id = ?";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param("ssi", $categoryName, $categoryDesc, $categoryId);
            
            if ($stmt->execute()) {
                logInventoryActivity($conn, $userID, "update_category", $categoryId, "Updated category: $categoryName");
                header("Location: imanager_invmanagement.php?success=Category updated successfully");
            } else {
                header("Location: imanager_invmanagement.php?error=Failed to update category");
            }
            $stmt->close();
            exit();
        }
    }
    
    // Delete Product Category
    if (isset($_POST['delete_category'])) {
        $categoryId = $_POST['category_id'];
        
        // Check if category is in use
        $checkSql = "SELECT COUNT(*) AS product_count FROM products WHERE category_id = ?";
        $checkStmt = $conn->prepare($checkSql);
        $checkStmt->bind_param("i", $categoryId);
        $checkStmt->execute();
        $checkResult = $checkStmt->get_result();
        $row = $checkResult->fetch_assoc();
        
        if ($row['product_count'] > 0) {
            header("Location: imanager_invmanagement.php?error=Cannot delete category that is in use by products");
            $checkStmt->close();
            exit();
        }
        
        $sql = "DELETE FROM product_categories WHERE category_id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $categoryId);
        
        if ($stmt->execute()) {
            logInventoryActivity($conn, $userID, "delete_category", $categoryId, "Deleted category ID: $categoryId");
            header("Location: imanager_invmanagement.php?success=Category deleted successfully");
        } else {
            header("Location: imanager_invmanagement.php?error=Failed to delete category");
        }
        $stmt->close();
        exit();
    }
    
    // Add New Product
    if (isset($_POST['add_product'])) {
        $productName = trim($_POST['product_name']);
        $productDesc = trim($_POST['product_description']);
        $categoryId = $_POST['category_id'];
        $stockQuantity = $_POST['stock_quantity'];
        $reorderThreshold = $_POST['reorder_threshold'];
        $unitPrice = $_POST['unit_price'];
        $productId = generateProductID($conn);
        
        if (!empty($productName) && !empty($categoryId)) {
            $sql = "INSERT INTO products (product_id, product_name, description, category_id, stock_quantity, reorder_threshold, unit_price, last_updated) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, NOW())";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param("sssiids", $productId, $productName, $productDesc, $categoryId, $stockQuantity, $reorderThreshold, $unitPrice);
            
            if ($stmt->execute()) {
                logInventoryActivity($conn, $userID, "add_product", $productId, "Added new product: $productName");
                header("Location: imanager_invmanagement.php?success=Product added successfully");
            } else {
                header("Location: imanager_invmanagement.php?error=Failed to add product");
            }
            $stmt->close();
            exit();
        }
    }
    
    // Update Product
    if (isset($_POST['update_product'])) {
        $productId = $_POST['product_id'];
        $productName = trim($_POST['product_name']);
        $productDesc = trim($_POST['product_description']);
        $categoryId = $_POST['category_id'];
        $stockQuantity = $_POST['stock_quantity'];
        $reorderThreshold = $_POST['reorder_threshold'];
        $unitPrice = $_POST['unit_price'];
        
        if (!empty($productId) && !empty($productName)) {
            $sql = "UPDATE products 
                    SET product_name = ?, description = ?, category_id = ?, 
                        stock_quantity = ?, reorder_threshold = ?, unit_price = ?, last_updated = NOW() 
                    WHERE product_id = ?";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param("sssiids", $productName, $productDesc, $categoryId, $stockQuantity, $reorderThreshold, $unitPrice, $productId);
            
            if ($stmt->execute()) {
                logInventoryActivity($conn, $userID, "update_product", $productId, "Updated product: $productName");
                header("Location: imanager_invmanagement.php?success=Product updated successfully");
            } else {
                header("Location: imanager_invmanagement.php?error=Failed to update product: " . $stmt->error);
            }
            $stmt->close();
            exit();
        }
    }
    
    // Delete Product
    if (isset($_POST['delete_product'])) {
        $productId = $_POST['product_id'];
        
        // Check if product is in any orders
        $checkSql = "SELECT COUNT(*) AS order_count FROM order_items WHERE product_id = ?";
        $checkStmt = $conn->prepare($checkSql);
        $checkStmt->bind_param("s", $productId);
        $checkStmt->execute();
        $checkResult = $checkStmt->get_result();
        $row = $checkResult->fetch_assoc();
        
        if ($row['order_count'] > 0) {
            header("Location: imanager_invmanagement.php?error=Cannot delete product that is in use by orders");
            $checkStmt->close();
            exit();
        }
        
        $sql = "DELETE FROM products WHERE product_id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("s", $productId);
        
        if ($stmt->execute()) {
            logInventoryActivity($conn, $userID, "delete_product", $productId, "Deleted product ID: $productId");
            header("Location: imanager_invmanagement.php?success=Product deleted successfully");
        } else {
            header("Location: imanager_invmanagement.php?error=Failed to delete product");
        }
        $stmt->close();
        exit();
    }
    
    // Create New Order
    if (isset($_POST['add_order'])) {
        $orderType = $_POST['order_type'];
        $customerName = trim($_POST['customer_name']);
        $orderDate = $_POST['order_date'];
        $status = 'Pending';
        
        // Start a transaction
        $conn->begin_transaction();
        
        try {
            // Insert order
            $orderIdPrefix = ($orderType == 'Purchase') ? 'PO' : 'SO';
            $orderIdQuery = "SELECT MAX(CAST(SUBSTRING(order_id, 3) AS UNSIGNED)) as max_id FROM orders WHERE order_id LIKE '$orderIdPrefix%'";
            $orderIdResult = $conn->query($orderIdQuery);
            $orderIdRow = $orderIdResult->fetch_assoc();
            $maxOrderId = $orderIdRow['max_id'] ?? 0;
            $newOrderId = $orderIdPrefix . str_pad($maxOrderId + 1, 6, '0', STR_PAD_LEFT);
            
            $orderSql = "INSERT INTO orders (order_id, order_type, customer_name, order_date, status, created_by) 
                        VALUES (?, ?, ?, ?, ?, ?)";
            $orderStmt = $conn->prepare($orderSql);
            $orderStmt->bind_param("ssssss", $newOrderId, $orderType, $customerName, $orderDate, $status, $userID);
            $orderStmt->execute();
            
            // Insert order items
            $productIds = $_POST['product_id'];
            $quantities = $_POST['quantity'];
            $prices = $_POST['price'];
            
            $itemSql = "INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES (?, ?, ?, ?)";
            $itemStmt = $conn->prepare($itemSql);
            
            $totalAmount = 0;
            
            for ($i = 0; $i < count($productIds); $i++) {
                if (!empty($productIds[$i]) && !empty($quantities[$i]) && !empty($prices[$i])) {
                    $itemStmt->bind_param("ssid", $newOrderId, $productIds[$i], $quantities[$i], $prices[$i]);
                    $itemStmt->execute();
                    
                    $totalAmount += $quantities[$i] * $prices[$i];
                    
                    // Update inventory for Purchase orders
                    if ($orderType == 'Purchase') {
                        $updateStockSql = "UPDATE products SET stock_quantity = stock_quantity + ?, last_updated = NOW() WHERE product_id = ?";
                        $updateStockStmt = $conn->prepare($updateStockSql);
                        $updateStockStmt->bind_param("is", $quantities[$i], $productIds[$i]);
                        $updateStockStmt->execute();
                        
                        logInventoryActivity($conn, $userID, "stock_update", $productIds[$i], "Increased stock by {$quantities[$i]} via purchase order $newOrderId");
                        $updateStockStmt->close();
                    }
                    // Update inventory for Sales orders
                    else if ($orderType == 'Sales') {
                        $updateStockSql = "UPDATE products SET stock_quantity = stock_quantity - ?, last_updated = NOW() WHERE product_id = ?";
                        $updateStockStmt = $conn->prepare($updateStockSql);
                        $updateStockStmt->bind_param("is", $quantities[$i], $productIds[$i]);
                        $updateStockStmt->execute();
                        
                        logInventoryActivity($conn, $userID, "stock_update", $productIds[$i], "Decreased stock by {$quantities[$i]} via sales order $newOrderId");
                        $updateStockStmt->close();
                    }
                }
            }
            
            // Update total amount
            $updateOrderSql = "UPDATE orders SET total_amount = ? WHERE order_id = ?";
            $updateOrderStmt = $conn->prepare($updateOrderSql);
            $updateOrderStmt->bind_param("ds", $totalAmount, $newOrderId);
            $updateOrderStmt->execute();
            
            logInventoryActivity($conn, $userID, "create_order", $newOrderId, "Created new $orderType order: $newOrderId");
            
            $conn->commit();
            header("Location: imanager_invmanagement.php?success=Order created successfully");
        } catch (Exception $e) {
            $conn->rollback();
            header("Location: imanager_invmanagement.php?error=Failed to create order: " . $e->getMessage());
        }
        exit();
    }
    
    // Update Order Status
    if (isset($_POST['update_order_status'])) {
        $orderId = $_POST['order_id'];
        $newStatus = $_POST['status'];
        
        $sql = "UPDATE orders SET status = ? WHERE order_id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ss", $newStatus, $orderId);
        
        if ($stmt->execute()) {
            logInventoryActivity($conn, $userID, "update_order", $orderId, "Updated order status to: $newStatus");
            header("Location: imanager_invmanagement.php?success=Order status updated successfully");
        } else {
            header("Location: imanager_invmanagement.php?error=Failed to update order status");
        }
        $stmt->close();
        exit();
    }
    
    // Delete Order
    if (isset($_POST['delete_order'])) {
        $orderId = $_POST['order_id'];
        
        // Start a transaction
        $conn->begin_transaction();
        
        try {
            // Get order type
            $orderTypeSql = "SELECT order_type FROM orders WHERE order_id = ?";
            $orderTypeStmt = $conn->prepare($orderTypeSql);
            $orderTypeStmt->bind_param("s", $orderId);
            $orderTypeStmt->execute();
            $orderTypeResult = $orderTypeStmt->get_result();
            $orderTypeRow = $orderTypeResult->fetch_assoc();
            $orderType = $orderTypeRow['order_type'];
            
            // Get order items
            $itemsSql = "SELECT product_id, quantity FROM order_items WHERE order_id = ?";
            $itemsStmt = $conn->prepare($itemsSql);
            $itemsStmt->bind_param("s", $orderId);
            $itemsStmt->execute();
            $itemsResult = $itemsStmt->get_result();
            
            // Revert inventory changes
            while ($itemRow = $itemsResult->fetch_assoc()) {
                $productId = $itemRow['product_id'];
                $quantity = $itemRow['quantity'];
                
                if ($orderType == 'Purchase') {
                    // If deleting a purchase, subtract the quantity
                    $updateStockSql = "UPDATE products SET stock_quantity = stock_quantity - ?, last_updated = NOW() WHERE product_id = ?";
                } else {
                    // If deleting a sale, add the quantity back
                    $updateStockSql = "UPDATE products SET stock_quantity = stock_quantity + ?, last_updated = NOW() WHERE product_id = ?";
                }
                
                $updateStockStmt = $conn->prepare($updateStockSql);
                $updateStockStmt->bind_param("is", $quantity, $productId);
                $updateStockStmt->execute();
                
                $action = ($orderType == 'Purchase') ? "Decreased" : "Increased";
                logInventoryActivity($conn, $userID, "stock_update", $productId, "$action stock by $quantity due to deletion of $orderType order $orderId");
                $updateStockStmt->close();
            }
            
            // Delete order items
            $deleteItemsSql = "DELETE FROM order_items WHERE order_id = ?";
            $deleteItemsStmt = $conn->prepare($deleteItemsSql);
            $deleteItemsStmt->bind_param("s", $orderId);
            $deleteItemsStmt->execute();
            
            // Delete order
            $deleteOrderSql = "DELETE FROM orders WHERE order_id = ?";
            $deleteOrderStmt = $conn->prepare($deleteOrderSql);
            $deleteOrderStmt->bind_param("s", $orderId);
            $deleteOrderStmt->execute();
            
            logInventoryActivity($conn, $userID, "delete_order", $orderId, "Deleted $orderType order: $orderId");
            
            $conn->commit();
            header("Location: imanager_invmanagement.php?success=Order deleted successfully");
        } catch (Exception $e) {
            $conn->rollback();
            header("Location: imanager_invmanagement.php?error=Failed to delete order: " . $e->getMessage());
        }
        exit();
    }
    
    // Update Reorder Thresholds
    if (isset($_POST['update_thresholds'])) {
        $productIds = $_POST['threshold_product_id'];
        $thresholds = $_POST['threshold_value'];
        
        $sql = "UPDATE products SET reorder_threshold = ? WHERE product_id = ?";
        $stmt = $conn->prepare($sql);
        
        $successCount = 0;
        for ($i = 0; $i < count($productIds); $i++) {
            if (!empty($productIds[$i]) && isset($thresholds[$i])) {
                $stmt->bind_param("is", $thresholds[$i], $productIds[$i]);
                if ($stmt->execute()) {
                    logInventoryActivity($conn, $userID, "update_threshold", $productIds[$i], "Updated reorder threshold to: {$thresholds[$i]}");
                    $successCount++;
                }
            }
        }
        
        if ($successCount > 0) {
            header("Location: imanager_invmanagement.php?success=Updated reorder thresholds for $successCount products");
        } else {
            header("Location: imanager_invmanagement.php?error=Failed to update reorder thresholds");
        }
        $stmt->close();
        exit();
    }
}

// Get count of products below threshold
$threshold_sql = "SELECT COUNT(*) as low_stock_count FROM products WHERE stock_quantity <= reorder_threshold";
$threshold_result = $conn->query($threshold_sql);
$threshold_row = $threshold_result->fetch_assoc();
$low_stock_count = $threshold_row['low_stock_count'];

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Inventory Management</title>
    <link rel="stylesheet" href="admin_dashboard.css">
    <link rel="stylesheet" href="sidebar.css">
    <link rel="stylesheet" href="imanager_invmanagement.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>
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
                <a href="imanager_invmanagement.php" class="nav-item active">
                    <i class="fas fa-boxes"></i>
                    <div class="nav-text">Manage Inventory</div>
                </a>
                <a href="imanager_supplierpurchase.php" class="nav-item">
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
            <h1>Inventory Management</h1>
            <p>Welcome, <?php echo htmlspecialchars($fullName); ?>!</p>
            
            <?php if (isset($_GET['success'])): ?>
                <div class="alert alert-success"><?php echo htmlspecialchars($_GET['success']); ?></div>
            <?php endif; ?>
            
            <?php if (isset($_GET['error'])): ?>
                <div class="alert alert-danger"><?php echo htmlspecialchars($_GET['error']); ?></div>
            <?php endif; ?>
        </div>

        <!-- Inventory Overview -->
        <div class="inventory-overview">
            <div class="card">
                <div class="card-header">
                    <h2><i class="fas fa-tachometer-alt"></i> Inventory Dashboard</h2>
                    <div class="card-actions">
                        <button class="export-btn" onclick="exportProductsPDF()"><i class="fas fa-file-pdf"></i> Export PDF</button>
                        <button class="export-btn" onclick="exportProductsExcel()"><i class="fas fa-file-excel"></i> Export Excel</button>
                    </div>
                </div>
                <div class="dashboard-stats">
                    <div class="stat-card">
                        <i class="fas fa-boxes"></i>
                        <div class="stat-info">
                            <h3>Total Products</h3>
                            <p><?php echo $result_products->num_rows; ?></p>
                        </div>
                    </div>
                    <div class="stat-card">
                        <i class="fas fa-tags"></i>
                        <div class="stat-info">
                            <h3>Categories</h3>
                            <p><?php echo $result_categories->num_rows; ?></p>
                        </div>
                    </div>
                    <div class="stat-card <?php echo ($low_stock_count > 0) ? 'alert-status' : ''; ?>">
                        <i class="fas fa-exclamation-triangle"></i>
                        <div class="stat-info">
                            <h3>Low Stock Items</h3>
                            <p><?php echo $low_stock_count; ?></p>
                        </div>
                    </div>
                    <div class="stat-card">
                        <i class="fas fa-shopping-cart"></i>
                        <div class="stat-info">
                            <h3>Orders</h3>
                            <p><?php echo $result_orders->num_rows; ?></p>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Tab Navigation -->
        <div class="tab-navigation">
            <button class="tab-button active" onclick="openTab('products')">Products</button>
            <button class="tab-button" onclick="openTab('categories')">Categories</button>
            <button class="tab-button" onclick="openTab('orders')">Orders</button>
            <button class="tab-button" onclick="openTab('stock-levels')">Stock Levels</button>
            <button class="tab-button" onclick="openTab('logs')">Activity Logs</button>
        </div>

        <!-- Products Tab -->
        <div id="products" class="tab-content active">
            <div class="card">
                <div class="card-header">
                    <h2><i class="fas fa-box"></i> Manage Products</h2>
                    <button class="add-btn" onclick="showAddProductModal()"><i class="fas fa-plus"></i> Add Product</button>
                </div>
                <div class="table-responsive">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Product Name</th>
                                <th>Category</th>
                                <th>Stock Qty</th>
                                <th>Reorder Level</th>
                                <th>Unit Price</th>
                                <th>Last Updated</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php while ($product = $result_products->fetch_assoc()): ?>
                                <tr class="<?php echo ($product['stock_quantity'] <= $product['reorder_threshold']) ? 'low-stock' : ''; ?>">
                                    <td><?php echo htmlspecialchars($product['product_id']); ?></td>
                                    <td><?php echo htmlspecialchars($product['product_name']); ?></td>
                                    <td><?php echo htmlspecialchars($product['category_name']); ?></td>
                                    <td><?php echo htmlspecialchars($product['stock_quantity']); ?></td>
                                    <td><?php echo htmlspecialchars($product['reorder_threshold']); ?></td>
                                    <td>RM <?php echo number_format($product['unit_price'], 2); ?></td>
                                    <td><?php echo htmlspecialchars($product['last_updated']); ?></td>
                                    <td>
                                        <button class="action-btn edit-btn" onclick="showEditProductModal('<?php echo $product['product_id']; ?>', '<?php echo addslashes($product['product_name']); ?>', '<?php echo addslashes($product['description']); ?>', '<?php echo $product['category_id']; ?>', '<?php echo $product['stock_quantity']; ?>', '<?php echo $product['reorder_threshold']; ?>', '<?php echo $product['unit_price']; ?>')">
                                            <i class="fas fa-edit"></i>
                                        </button>
                                        <button class="action-btn delete-btn" onclick="confirmDeleteProduct('<?php echo $product['product_id']; ?>', '<?php echo addslashes($product['product_name']); ?>')">
                                            <i class="fas fa-trash"></i>
                                        </button>
                                    </td>
                                </tr>
                            <?php endwhile; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Categories Tab -->
        <div id="categories" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <h2><i class="fas fa-tags"></i> Manage Categories</h2>
                    <button class="add-btn" onclick="showAddCategoryModal()"><i class="fas fa-plus"></i> Add Category</button>
                </div>
                <div class="table-responsive">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Category Name</th>
                                <th>Description</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php 
                            if ($result_categories) {
                                $result_categories->data_seek(0); // Reset result pointer
                                while ($category = $result_categories->fetch_assoc()): 
                            ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($category['category_id']); ?></td>
                                    <td><?php echo htmlspecialchars($category['category_name']); ?></td>
                                    <td><?php echo htmlspecialchars($category['description']); ?></td>
                                    <td>
                                        <button class="action-btn edit-btn" onclick="showEditCategoryModal('<?php echo $category['category_id']; ?>', '<?php echo addslashes($category['category_name']); ?>', '<?php echo addslashes($category['description']); ?>')">
                                            <i class="fas fa-edit"></i>
                                        </button>
                                        <button class="action-btn delete-btn" onclick="confirmDeleteCategory('<?php echo $category['category_id']; ?>', '<?php echo addslashes($category['category_name']); ?>')">
                                            <i class="fas fa-trash"></i>
                                        </button>
                                    </td>
                                </tr>
                            <?php endwhile; } ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Orders Tab -->
        <div id="orders" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <h2><i class="fas fa-shopping-cart"></i> Manage Orders</h2>
                    <button class="add-btn" onclick="showAddOrderModal()"><i class="fas fa-plus"></i> Create Order</button>
                </div>
                <div class="table-responsive">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Order ID</th>
                                <th>Type</th>
                                <th>Customer/Supplier</th>
                                <th>Date</th>
                                <th>Total Amount</th>
                                <th>Status</th>
                                <th>Created By</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php 
                            if ($result_orders) {
                                while ($order = $result_orders->fetch_assoc()): 
                            ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($order['order_id']); ?></td>
                                    <td><?php echo htmlspecialchars($order['order_type']); ?></td>
                                    <td><?php echo htmlspecialchars($order['customer_name']); ?></td>
                                    <td><?php echo htmlspecialchars($order['order_date']); ?></td>
                                    <td>RM <?php echo number_format($order['total_amount'], 2); ?></td>
                                    <td>
                                        <span class="status-badge status-<?php echo strtolower($order['status']); ?>">
                                            <?php echo htmlspecialchars($order['status']); ?>
                                        </span>
                                    </td>
                                    <td><?php echo htmlspecialchars($order['fullName']); ?></td>
                                    <td>
                                        <button class="action-btn view-btn" onclick="viewOrderDetails('<?php echo $order['order_id']; ?>')">
                                            <i class="fas fa-eye"></i>
                                        </button>
                                        <button class="action-btn edit-btn" onclick="showUpdateOrderStatusModal('<?php echo $order['order_id']; ?>', '<?php echo $order['status']; ?>')">
                                            <i class="fas fa-edit"></i>
                                        </button>
                                        <button class="action-btn delete-btn" onclick="confirmDeleteOrder('<?php echo $order['order_id']; ?>')">
                                            <i class="fas fa-trash"></i>
                                        </button>
                                    </td>
                                </tr>
                            <?php endwhile; } ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Stock Levels Tab -->
        <div id="stock-levels" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <h2><i class="fas fa-chart-line"></i> Stock Levels Monitoring</h2>
                    <button class="add-btn" onclick="showUpdateThresholdsModal()"><i class="fas fa-cog"></i> Update Thresholds</button>
                </div>
                <div class="stock-levels-container">
                    <div class="stock-chart-container">
                        <canvas id="stockLevelsChart"></canvas>
                    </div>
                    <div class="table-responsive">
                        <h3>Low Stock Items</h3>
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Product ID</th>
                                    <th>Product Name</th>
                                    <th>Category</th>
                                    <th>Current Stock</th>
                                    <th>Reorder Threshold</th>
                                    <th>Stock Level</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody id="lowStockTable">
                                <!-- Will be populated via JavaScript -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- Activity Logs Tab -->
        <div id="logs" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <h2><i class="fas fa-history"></i> Inventory Activity Logs</h2>
                    <div class="card-actions">
                        <button class="export-btn" onclick="exportLogsPDF()"><i class="fas fa-file-pdf"></i> Export PDF</button>
                        <button class="export-btn" onclick="exportLogsExcel()"><i class="fas fa-file-excel"></i> Export Excel</button>
                    </div>
                </div>
                <div class="table-responsive">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>User</th>
                                <th>Action</th>
                                <th>Item ID</th>
                                <th>Details</th>
                                <th>IP Address</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php while ($log = $result_logs->fetch_assoc()): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($log['timestamp']); ?></td>
                                    <td><?php echo htmlspecialchars($log['fullName']); ?></td>
                                    <td><?php echo htmlspecialchars($log['action']); ?></td>
                                    <td><?php echo htmlspecialchars($log['item_id']); ?></td>
                                    <td><?php echo htmlspecialchars($log['action_details']); ?></td>
                                    <td><?php echo htmlspecialchars($log['ip_address']); ?></td>
                                </tr>
                            <?php endwhile; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Modals -->
        <!-- Add Category Modal -->
        <div id="addCategoryModal" class="modal">
            <div class="modal-content">
                <span class="close" onclick="closeModal('addCategoryModal')">&times;</span>
                <h2>Add New Category</h2>
                <form id="addCategoryForm" action="imanager_invmanagement.php" method="POST">
                    <div class="form-group">
                        <label for="category_name">Category Name:</label>
                        <input type="text" id="category_name" name="category_name" required>
                    </div>
                    <div class="form-group">
                        <label for="category_description">Description:</label>
                        <textarea id="category_description" name="category_description" rows="3"></textarea>
                    </div>
                    <div class="form-actions">
                        <button type="submit" name="add_category">Save Category</button>
                        <button type="button" onclick="closeModal('addCategoryModal')">Cancel</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Edit Category Modal -->
        <div id="editCategoryModal" class="modal">
            <div class="modal-content">
                <span class="close" onclick="closeModal('editCategoryModal')">&times;</span>
                <h2>Edit Category</h2>
                <form id="editCategoryForm" action="imanager_invmanagement.php" method="POST">
                    <input type="hidden" id="edit_category_id" name="category_id">
                    <div class="form-group">
                        <label for="edit_category_name">Category Name:</label>
                        <input type="text" id="edit_category_name" name="category_name" required>
                    </div>
                    <div class="form-group">
                        <label for="edit_category_description">Description:</label>
                        <textarea id="edit_category_description" name="category_description" rows="3"></textarea>
                    </div>
                    <div class="form-actions">
                        <button type="submit" name="update_category">Update Category</button>
                        <button type="button" onclick="closeModal('editCategoryModal')">Cancel</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Delete Category Confirmation Modal -->
        <div id="deleteCategoryModal" class="modal">
            <div class="modal-content">
                <span class="close" onclick="closeModal('deleteCategoryModal')">&times;</span>
                <h2>Confirm Deletion</h2>
                <p>Are you sure you want to delete the category: <span id="delete_category_name"></span>?</p>
                <p class="warning-text">This action cannot be undone.</p>
                <form id="deleteCategoryForm" action="imanager_invmanagement.php" method="POST">
                    <input type="hidden" id="delete_category_id" name="category_id">
                    <div class="form-actions">
                        <button type="submit" name="delete_category" class="delete-confirm-btn">Delete</button>
                        <button type="button" onclick="closeModal('deleteCategoryModal')">Cancel</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Add Product Modal -->
        <div id="addProductModal" class="modal">
            <div class="modal-content">
                <span class="close" onclick="closeModal('addProductModal')">&times;</span>
                <h2>Add New Product</h2>
                <form id="addProductForm" action="imanager_invmanagement.php" method="POST">
                    <div class="form-group">
                        <label for="product_name">Product Name:</label>
                        <input type="text" id="product_name" name="product_name" required>
                    </div>
                    <div class="form-group">
                        <label for="product_description">Description:</label>
                        <textarea id="product_description" name="product_description" rows="3"></textarea>
                    </div>
                    <div class="form-group">
                        <label for="category_id">Category:</label>
                        <select id="category_id" name="category_id" required>
                            <option value="">Select Category</option>
                            <?php 
                            if ($result_categories) {
                                $result_categories->data_seek(0); // Reset result pointer
                                while ($category = $result_categories->fetch_assoc()): 
                            ?>
                                <option value="<?php echo $category['category_id']; ?>">
                                    <?php echo htmlspecialchars($category['category_name']); ?>
                                </option>
                            <?php endwhile; } ?>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="stock_quantity">Initial Stock Quantity:</label>
                        <input type="number" id="stock_quantity" name="stock_quantity" min="0" value="0" required>
                    </div>
                    <div class="form-group">
                        <label for="reorder_threshold">Reorder Threshold:</label>
                        <input type="number" id="reorder_threshold" name="reorder_threshold" min="0" value="10" required>
                    </div>
                    <div class="form-group">
                        <label for="unit_price">Unit Price (RM):</label>
                        <input type="number" id="unit_price" name="unit_price" min="0" step="0.01" value="0.00" required>
                    </div>
                    <div class="form-actions">
                        <button type="submit" name="add_product">Save Product</button>
                        <button type="button" onclick="closeModal('addProductModal')">Cancel</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Edit Product Modal -->
        <div id="editProductModal" class="modal">
            <div class="modal-content">
                <span class="close" onclick="closeModal('editProductModal')">&times;</span>
                <h2>Edit Product</h2>
                <form id="editProductForm" action="imanager_invmanagement.php" method="POST">
                    <input type="hidden" id="edit_product_id" name="product_id">
                    <div class="form-group">
                        <label for="edit_product_name">Product Name:</label>
                        <input type="text" id="edit_product_name" name="product_name" required>
                    </div>
                    <div class="form-group">
                        <label for="edit_product_description">Description:</label>
                        <textarea id="edit_product_description" name="product_description" rows="3"></textarea>
                    </div>
                    <div class="form-group">
                        <label for="edit_category_id">Category:</label>
                        <select id="edit_category_id" name="category_id" required>
                            <?php 
                            if ($result_categories) {
                                $result_categories->data_seek(0); // Reset result pointer
                                while ($category = $result_categories->fetch_assoc()): 
                            ?>
                                <option value="<?php echo $category['category_id']; ?>">
                                    <?php echo htmlspecialchars($category['category_name']); ?>
                                </option>
                            <?php endwhile; } ?>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="edit_stock_quantity">Stock Quantity:</label>
                        <input type="number" id="edit_stock_quantity" name="stock_quantity" min="0" required>
                    </div>
                    <div class="form-group">
                        <label for="edit_reorder_threshold">Reorder Threshold:</label>
                        <input type="number" id="edit_reorder_threshold" name="reorder_threshold" min="0" required>
                    </div>
                    <div class="form-group">
                        <label for="edit_unit_price">Unit Price (RM):</label>
                        <input type="number" id="edit_unit_price" name="unit_price" min="0" step="0.01" required>
                    </div>
                    <div class="form-actions">
                        <button type="submit" name="update_product">Update Product</button>
                        <button type="button" onclick="closeModal('editProductModal')">Cancel</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Delete Product Confirmation Modal -->
        <div id="deleteProductModal" class="modal">
            <div class="modal-content">
                <span class="close" onclick="closeModal('deleteProductModal')">&times;</span>
                <h2>Confirm Deletion</h2>
                <p>Are you sure you want to delete the product: <span id="delete_product_name"></span>?</p>
                <p class="warning-text">This action cannot be undone.</p>
                <form id="deleteProductForm" action="imanager_invmanagement.php" method="POST">
                    <input type="hidden" id="delete_product_id" name="product_id">
                    <div class="form-actions">
                        <button type="submit" name="delete_product" class="delete-confirm-btn">Delete</button>
                        <button type="button" onclick="closeModal('deleteProductModal')">Cancel</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Add Order Modal -->
        <div id="addOrderModal" class="modal">
            <div class="modal-content wider-modal">
                <span class="close" onclick="closeModal('addOrderModal')">&times;</span>
                <h2>Create New Order</h2>
                <form id="addOrderForm" action="imanager_invmanagement.php" method="POST">
                    <div class="form-row">
                        <div class="form-group">
                            <label for="order_type">Order Type:</label>
                            <select id="order_type" name="order_type" required>
                                <option value="Purchase">Purchase (From Supplier)</option>
                                <option value="Sales">Sales (To Customer)</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="customer_name">Customer/Supplier Name:</label>
                            <input type="text" id="customer_name" name="customer_name" required>
                        </div>
                        <div class="form-group">
                            <label for="order_date">Order Date:</label>
                            <input type="date" id="order_date" name="order_date" required value="<?php echo date('Y-m-d'); ?>">
                        </div>
                    </div>
                    
                    <h3>Order Items</h3>
                    <div class="order-items" id="orderItemsContainer">
                        <div class="order-item">
                            <div class="form-group">
                                <label for="product_id_0">Product:</label>
                                <select id="product_id_0" name="product_id[]" class="product-select" onchange="updatePrice(0)" required>
                                    <option value="">Select Product</option>
                                    <?php 
                                    if ($result_products) {
                                        $result_products->data_seek(0); // Reset result pointer
                                        while ($product = $result_products->fetch_assoc()): 
                                    ?>
                                        <option value="<?php echo $product['product_id']; ?>" data-price="<?php echo $product['unit_price']; ?>">
                                            <?php echo htmlspecialchars($product['product_name']); ?> - RM<?php echo number_format($product['unit_price'], 2); ?>
                                        </option>
                                    <?php endwhile; } ?>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="quantity_0">Quantity:</label>
                                <input type="number" id="quantity_0" name="quantity[]" min="1" value="1" onchange="updateSubtotal(0)" required>
                            </div>
                            <div class="form-group">
                                <label for="price_0">Unit Price (RM):</label>
                                <input type="number" id="price_0" name="price[]" min="0" step="0.01" value="0.00" onchange="updateSubtotal(0)" required>
                            </div>
                            <div class="form-group">
                                <label for="subtotal_0">Subtotal (RM):</label>
                                <input type="text" id="subtotal_0" class="subtotal" readonly value="0.00">
                            </div>
                            <button type="button" class="remove-item-btn" onclick="removeOrderItem(this)" style="display: none;">
                                <i class="fas fa-times"></i>
                            </button>
                        </div>
                    </div>
                    
                    <div class="form-actions">
                        <button type="button" onclick="addOrderItem()">+ Add Another Item</button>
                    </div>
                    
                    <div class="order-total">
                        <h3>Total: RM <span id="orderTotal">0.00</span></h3>
                    </div>
                    
                    <div class="form-actions">
                        <button type="submit" name="add_order">Create Order</button>
                        <button type="button" onclick="closeModal('addOrderModal')">Cancel</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Update Order Status Modal -->
        <div id="updateOrderStatusModal" class="modal">
            <div class="modal-content">
                <span class="close" onclick="closeModal('updateOrderStatusModal')">&times;</span>
                <h2>Update Order Status</h2>
                <form id="updateOrderStatusForm" action="imanager_invmanagement.php" method="POST">
                    <input type="hidden" id="update_order_id" name="order_id">
                    <div class="form-group">
                        <label for="order_status">Status:</label>
                        <select id="order_status" name="status" required>
                            <option value="Pending">Pending</option>
                            <option value="Processing">Processing</option>
                            <option value="Completed">Completed</option>
                            <option value="Cancelled">Cancelled</option>
                        </select>
                    </div>
                    <div class="form-actions">
                        <button type="submit" name="update_order_status">Update Status</button>
                        <button type="button" onclick="closeModal('updateOrderStatusModal')">Cancel</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Delete Order Confirmation Modal -->
        <div id="deleteOrderModal" class="modal">
            <div class="modal-content">
                <span class="close" onclick="closeModal('deleteOrderModal')">&times;</span>
                <h2>Confirm Deletion</h2>
                <p>Are you sure you want to delete the order: <span id="delete_order_id"></span>?</p>
                <p class="warning-text">This action cannot be undone and will revert all inventory changes made by this order.</p>
                <form id="deleteOrderForm" action="imanager_invmanagement.php" method="POST">
                    <input type="hidden" id="delete_order_id_input" name="order_id">
                    <div class="form-actions">
                        <button type="submit" name="delete_order" class="delete-confirm-btn">Delete</button>
                        <button type="button" onclick="closeModal('deleteOrderModal')">Cancel</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- Update Thresholds Modal -->
        <div id="updateThresholdsModal" class="modal">
            <div class="modal-content wider-modal">
                <span class="close" onclick="closeModal('updateThresholdsModal')">&times;</span>
                <h2>Update Reorder Thresholds</h2>
                <form id="updateThresholdsForm" action="imanager_invmanagement.php" method="POST">
                    <div class="table-responsive">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Product ID</th>
                                    <th>Product Name</th>
                                    <th>Current Stock</th>
                                    <th>Current Threshold</th>
                                    <th>New Threshold</th>
                                </tr>
                            </thead>
                            <tbody id="thresholdTableBody">
                                <!-- Will be populated via JavaScript -->
                            </tbody>
                        </table>
                    </div>
                    <div class="form-actions">
                        <button type="submit" name="update_thresholds">Update Thresholds</button>
                        <button type="button" onclick="closeModal('updateThresholdsModal')">Cancel</button>
                    </div>
                </form>
            </div>
        </div>

        <!-- View Order Details Modal -->
        <div id="viewOrderModal" class="modal">
            <div class="modal-content wider-modal">
                <span class="close" onclick="closeModal('viewOrderModal')">&times;</span>
                <h2>Order Details</h2>
                <div id="orderDetailsContainer">
                    <div class="order-header">
                        <div class="order-info">
                            <p><strong>Order ID:</strong> <span id="view_order_id"></span></p>
                            <p><strong>Type:</strong> <span id="view_order_type"></span></p>
                            <p><strong>Customer/Supplier:</strong> <span id="view_customer_name"></span></p>
                        </div>
                        <div class="order-info">
                            <p><strong>Date:</strong> <span id="view_order_date"></span></p>
                            <p><strong>Status:</strong> <span id="view_order_status"></span></p>
                            <p><strong>Created By:</strong> <span id="view_created_by"></span></p>
                        </div>
                    </div>
                    <h3>Order Items</h3>
                    <div class="table-responsive">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Product ID</th>
                                    <th>Product Name</th>
                                    <th>Quantity</th>
                                    <th>Unit Price</th>
                                    <th>Subtotal</th>
                                </tr>
                            </thead>
                            <tbody id="orderItemsTable">
                                <!-- Will be populated via JavaScript -->
                            </tbody>
                            <tfoot>
                                <tr>
                                    <td colspan="4" class="text-right"><strong>Total:</strong></td>
                                    <td><strong>RM <span id="view_total_amount"></span></strong></td>
                                </tr>
                            </tfoot>
                        </table>
                    </div>
                    <div class="form-actions">
                        <button type="button" onclick="printOrder()"><i class="fas fa-print"></i> Print</button>
                        <button type="button" onclick="exportOrderPDF()"><i class="fas fa-file-pdf"></i> Export PDF</button>
                        <button type="button" onclick="closeModal('viewOrderModal')">Close</button>
                    </div>
                </div>
            </div>
        </div>

    </div>

    <script>
    // Global variables
    let productData = [];
    let stockChart;
    let orderItemCount = 1;

    // Tab Navigation
    function openTab(tabName) {
        // Hide all tab content
        const tabContents = document.getElementsByClassName('tab-content');
        for (let i = 0; i < tabContents.length; i++) {
            tabContents[i].classList.remove('active');
        }
        
        // Remove active class from all tab buttons
        const tabButtons = document.getElementsByClassName('tab-button');
        for (let i = 0; i < tabButtons.length; i++) {
            tabButtons[i].classList.remove('active');
        }
        
        // Show the selected tab content and mark the button as active
        document.getElementById(tabName).classList.add('active');
        
        // Find and activate the corresponding button
        const buttons = document.getElementsByClassName('tab-button');
        for (let i = 0; i < buttons.length; i++) {
            if (buttons[i].textContent.toLowerCase().includes(tabName.replace('-', ' '))) {
                buttons[i].classList.add('active');
            }
        }
        
        // Save active tab to localStorage
        localStorage.setItem('activeInventoryTab', tabName);
        
        // Load specific tab data if needed
        if (tabName === 'stock-levels') {
            // Check if data is already loaded
            if (productData && productData.length > 0) {
                initializeStockChart();
            } else {
                // Try to load data first
                loadStockLevelsData();
            }
        }
    }

    // Modal functions
    function closeModal(modalId) {
        document.getElementById(modalId).style.display = 'none';
    }

    // Function to load product data
    function loadStockLevelsData() {
        // Use AJAX to fetch the product data
        fetch('imanager_getproducts.php')
            .then(response => response.json())
            .then(data => {
                // Store data in the global variable
                productData = data.map(product => ({
                    id: product.product_id,
                    name: product.product_name,
                    category: product.category_name,
                    stock: parseInt(product.stock_quantity),
                    threshold: parseInt(product.reorder_threshold),
                    price: parseFloat(product.unit_price)
                }));
                
                // Now that we have the data, populate the low stock table
                const lowStockTable = document.getElementById('lowStockTable');
                if (lowStockTable) {
                    lowStockTable.innerHTML = '';
                    
                    productData.forEach(product => {
                        // Calculate percentage for the progress bar
                        const percentage = Math.min(Math.round((product.stock / Math.max(product.threshold * 2, 1)) * 100), 100);
                        
                        // Determine status and bar color
                        let statusClass = '';
                        let statusText = '';
                        let barColor = '';
                        
                        if (product.stock === 0) {
                            statusClass = 'status-badge status-outofstock';
                            statusText = 'Out of Stock';
                            barColor = '#f44336'; // Red
                        } else if (product.stock <= product.threshold) {
                            statusClass = 'status-badge status-low';
                            statusText = 'Low Stock';
                            barColor = '#ff9800'; // Orange/Amber
                        } else {
                            statusClass = 'status-badge status-normal';
                            statusText = 'Normal';
                            barColor = '#4caf50'; // Green
                        }
                        
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${product.id}</td>
                            <td>${product.name}</td>
                            <td>${product.category}</td>
                            <td>${product.stock}</td>
                            <td>${product.threshold}</td>
                            <td>
                                <div class="progress-container" style="width: 100%; background-color: #f1f1f1; border-radius: 4px; overflow: hidden;">
                                    <div class="progress-bar" style="width: ${percentage}%; height: 20px; background-color: ${barColor};"></div>
                                </div>
                            </td>
                            <td><span class="${statusClass}">${statusText}</span></td>
                        `;
                        
                        // Only add to the low stock table if it's low stock or out of stock
                        if (product.stock <= product.threshold) {
                            lowStockTable.appendChild(row);
                        }
                    });
                    
                    if (lowStockTable.innerHTML === '') {
                        lowStockTable.innerHTML = '<tr><td colspan="7" class="text-center">No low stock items found</td></tr>';
                    }
                }
                
                // Initialize chart if we're on the stock-levels tab
                if (document.getElementById('stock-levels').classList.contains('active')) {
                    initializeStockChart();
                }
            })
            .catch(error => {
                console.error('Error fetching products:', error);
                // Display error message in the table
                const lowStockTable = document.getElementById('lowStockTable');
                if (lowStockTable) {
                    lowStockTable.innerHTML = '<tr><td colspan="7" class="text-center">Error loading product data. Please try again.</td></tr>';
                }
            });
    }
    
    // Initialize the stock chart
    function initializeStockChart() {
        const ctx = document.getElementById('stockLevelsChart').getContext('2d');
        
        // Destroy existing chart if it exists
        if (stockChart) {
            stockChart.destroy();
        }
        
        // Ensure productData is available
        if (!productData || productData.length === 0) {
            console.log('No product data available for chart');
            return;
        }
        
        // Get data for the chart
        const labels = [];
        const stockData = [];
        const thresholdData = [];
        const backgroundColors = [];
        
        productData.forEach(product => {
            labels.push(product.name);
            stockData.push(product.stock);
            thresholdData.push(product.threshold);
            
            // Red if out of stock, orange if low, green if ok
            if (product.stock === 0) {
                backgroundColors.push('rgba(255, 99, 132, 0.7)');
            } else if (product.stock <= product.threshold) {
                backgroundColors.push('rgba(255, 159, 64, 0.7)');
            } else {
                backgroundColors.push('rgba(75, 192, 192, 0.7)');
            }
        });
        
        stockChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Current Stock',
                        data: stockData,
                        backgroundColor: backgroundColors,
                        borderColor: backgroundColors.map(color => color.replace('0.7', '1')),
                        borderWidth: 1
                    },
                    {
                        label: 'Reorder Threshold',
                        data: thresholdData,
                        type: 'line',
                        fill: false,
                        borderColor: 'rgba(255, 99, 132, 1)',
                        borderWidth: 2,
                        pointRadius: 0
                    }
                ]
            },
            options: {
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Quantity'
                        }
                    },
                    x: {
                        ticks: {
                            autoSkip: false,
                            maxRotation: 90,
                            minRotation: 45
                        }
                    }
                },
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'Inventory Stock Levels & Reorder Thresholds'
                    }
                }
            }
        });
    }

    // Category Functions
    function showAddCategoryModal() {
        document.getElementById('addCategoryForm').reset();
        document.getElementById('addCategoryModal').style.display = 'block';
    }

    function showEditCategoryModal(id, name, description) {
        document.getElementById('edit_category_id').value = id;
        document.getElementById('edit_category_name').value = name;
        document.getElementById('edit_category_description').value = description;
        document.getElementById('editCategoryModal').style.display = 'block';
    }

    function confirmDeleteCategory(id, name) {
        document.getElementById('delete_category_id').value = id;
        document.getElementById('delete_category_name').textContent = name;
        document.getElementById('deleteCategoryModal').style.display = 'block';
    }

    // Product Functions
    function showAddProductModal() {
        document.getElementById('addProductForm').reset();
        document.getElementById('addProductModal').style.display = 'block';
    }

    function showEditProductModal(id, name, description, categoryId, stockQty, threshold, price) {
        document.getElementById('edit_product_id').value = id;
        document.getElementById('edit_product_name').value = name;
        document.getElementById('edit_product_description').value = description;
        document.getElementById('edit_category_id').value = categoryId;
        document.getElementById('edit_stock_quantity').value = stockQty;
        document.getElementById('edit_reorder_threshold').value = threshold;
        document.getElementById('edit_unit_price').value = parseFloat(price).toFixed(2);
        document.getElementById('editProductModal').style.display = 'block';
    }

    function confirmDeleteProduct(id, name) {
        document.getElementById('delete_product_id').value = id;
        document.getElementById('delete_product_name').textContent = name;
        document.getElementById('deleteProductModal').style.display = 'block';
    }
    
    // Order Management Functions
    function showAddOrderModal() {
        document.getElementById('addOrderForm').reset();
        document.getElementById('orderItemsContainer').innerHTML = '';
        addOrderItem(); // Start with one item
        document.getElementById('addOrderModal').style.display = 'block';
    }
    
    function addOrderItem() {
        const container = document.getElementById('orderItemsContainer');
        const index = orderItemCount;
        orderItemCount++;
        
        const itemRow = document.createElement('div');
        itemRow.className = 'order-item';
        itemRow.innerHTML = `
            <div class="form-group">
                <label for="product_id_${index}">Product:</label>
                <select id="product_id_${index}" name="product_id[]" class="product-select" onchange="updatePrice(${index})" required>
                    <option value="">Select Product</option>
                    <?php 
                    if ($result_products) {
                        $result_products->data_seek(0); // Reset result pointer
                        while ($product = $result_products->fetch_assoc()): 
                    ?>
                        <option value="<?php echo $product['product_id']; ?>" data-price="<?php echo $product['unit_price']; ?>">
                            <?php echo htmlspecialchars($product['product_name']); ?> - RM<?php echo number_format($product['unit_price'], 2); ?>
                        </option>
                    <?php endwhile; } ?>
                </select>
            </div>
            <div class="form-group">
                <label for="quantity_${index}">Quantity:</label>
                <input type="number" id="quantity_${index}" name="quantity[]" min="1" value="1" onchange="updateSubtotal(${index})" required>
            </div>
            <div class="form-group">
                <label for="price_${index}">Unit Price (RM):</label>
                <input type="number" id="price_${index}" name="price[]" min="0" step="0.01" value="0.00" onchange="updateSubtotal(${index})" required>
            </div>
            <div class="form-group">
                <label for="subtotal_${index}">Subtotal (RM):</label>
                <input type="text" id="subtotal_${index}" class="subtotal" readonly value="0.00">
            </div>
            <button type="button" class="remove-item-btn" onclick="removeOrderItem(this)">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        document.getElementById('orderItemsContainer').appendChild(itemRow);
        
        // Show all remove buttons if there's more than one item
        const removeButtons = document.querySelectorAll('.remove-item-btn');
        if (removeButtons.length > 1) {
            removeButtons.forEach(btn => {
                btn.style.display = 'block';
            });
        }
    }
    
    function removeOrderItem(button) {
        const container = document.getElementById('orderItemsContainer');
        const items = container.getElementsByClassName('order-item');
        
        if (items.length > 1) {
            button.parentElement.remove();
            updateOrderTotal();
            
            // Hide the remove button if only one item is left
            if (items.length <= 2) { // Will be 2 before the removal takes effect
                document.querySelector('.remove-item-btn').style.display = 'none';
            }
        }
    }
    
    function updatePrice(index) {
        const selectElement = document.getElementById(`product_id_${index}`);
        const priceInput = document.getElementById(`price_${index}`);
        
        if (selectElement.selectedIndex > 0) {
            const selectedOption = selectElement.options[selectElement.selectedIndex];
            const price = selectedOption.getAttribute('data-price');
            priceInput.value = parseFloat(price).toFixed(2);
            updateSubtotal(index);
        }
    }
    
    function updateSubtotal(index) {
        const quantity = parseFloat(document.getElementById(`quantity_${index}`).value) || 0;
        const price = parseFloat(document.getElementById(`price_${index}`).value) || 0;
        const subtotal = quantity * price;
        
        document.getElementById(`subtotal_${index}`).value = subtotal.toFixed(2);
        updateOrderTotal();
    }
    
    function updateOrderTotal() {
        const subtotalInputs = document.getElementsByClassName('subtotal');
        let total = 0;
        
        for (let i = 0; i < subtotalInputs.length; i++) {
            total += parseFloat(subtotalInputs[i].value) || 0;
        }
        
        document.getElementById('orderTotal').textContent = total.toFixed(2);
    }
    
    function showUpdateOrderStatusModal(orderId, status) {
        document.getElementById('update_order_id').value = orderId;
        document.getElementById('order_status').value = status;
        document.getElementById('updateOrderStatusModal').style.display = 'block';
    }
    
    function confirmDeleteOrder(orderId) {
        document.getElementById('delete_order_id_input').value = orderId;
        document.getElementById('delete_order_id').textContent = orderId;
        document.getElementById('deleteOrderModal').style.display = 'block';
    }
    
    function viewOrderDetails(orderId) {
        // Fetch order details via AJAX
        fetch('imanager_getorderdetails.php?id=' + orderId)
            .then(response => response.json())
            .then(data => {
                // Populate order header
                document.getElementById('view_order_id').textContent = data.order.order_id;
                document.getElementById('view_order_type').textContent = data.order.order_type;
                document.getElementById('view_customer_name').textContent = data.order.customer_name;
                document.getElementById('view_order_date').textContent = data.order.order_date;
                document.getElementById('view_order_status').textContent = data.order.status;
                document.getElementById('view_created_by').textContent = data.order.created_by;
                document.getElementById('view_total_amount').textContent = parseFloat(data.order.total_amount).toFixed(2);
                
                // Populate order items
                const itemsTable = document.getElementById('orderItemsTable');
                itemsTable.innerHTML = '';
                
                data.items.forEach(item => {
                    const row = document.createElement('tr');
                    const subtotal = parseFloat(item.quantity) * parseFloat(item.unit_price);
                    row.innerHTML = `
                        <td>${item.product_id}</td>
                        <td>${item.product_name}</td>
                        <td>${item.quantity}</td>
                        <td>RM ${parseFloat(item.unit_price).toFixed(2)}</td>
                        <td>RM ${subtotal.toFixed(2)}</td>
                    `;
                    itemsTable.appendChild(row);
                });
                
                document.getElementById('viewOrderModal').style.display = 'block';
            })
            .catch(error => {
                console.error('Error fetching order details:', error);
                alert('Failed to load order details.');
            });
    }

    // Stock Level Management
    function showUpdateThresholdsModal() {
        // Fetch current product data
        fetch('imanager_getproducts.php')
            .then(response => response.json())
            .then(data => {
                const tableBody = document.getElementById('thresholdTableBody');
                tableBody.innerHTML = '';
                
                data.forEach(product => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${product.product_id}</td>
                        <td>${product.product_name}</td>
                        <td>${product.stock_quantity}</td>
                        <td>${product.reorder_threshold}</td>
                        <td>
                            <input type="hidden" name="threshold_product_id[]" value="${product.product_id}">
                            <input type="number" name="threshold_value[]" value="${product.reorder_threshold}" min="0" class="form-control">
                        </td>
                    `;
                    tableBody.appendChild(row);
                });
                
                document.getElementById('updateThresholdsModal').style.display = 'block';
            })
            .catch(error => {
                console.error('Error fetching products:', error);
                alert('Failed to load product data.');
            });
    }

    // Export Functions
    function exportProductsPDF() {
        window.open('imanager_exportproducts.php?format=pdf', '_blank');
    }
    
    function exportProductsExcel() {
        window.open('imanager_exportproducts.php?format=excel', '_blank');
    }
    
    function exportLogsPDF() {
        window.open('imanager_exportlogs.php?format=pdf', '_blank');
    }
    
    function exportLogsExcel() {
        window.open('imanager_exportlogs.php?format=excel', '_blank');
    }
    
    function printOrder() {
        const printContents = document.getElementById('orderDetailsContainer').innerHTML;
        const originalContents = document.body.innerHTML;
        
        document.body.innerHTML = `
            <div style="padding: 20px;">
                <h1 style="text-align: center;">Order Details</h1>
                ${printContents}
            </div>
        `;
        
        window.print();
        document.body.innerHTML = originalContents;
        
        // Reattach event listeners
        document.querySelectorAll('.close').forEach(el => {
            el.addEventListener('click', function() {
                closeModal(this.closest('.modal').id);
            });
        });
    }
    
    function exportOrderPDF() {
        const orderId = document.getElementById('view_order_id').textContent;
        window.open('imanager_exportorder.php?id=' + orderId + '&format=pdf', '_blank');
    }

    // Utility Functions
    function formatCurrency(amount) {
        return 'RM ' + parseFloat(amount).toFixed(2);
    }

    // Close modals when clicking outside
    window.onclick = function(event) {
        if (event.target.classList.contains('modal')) {
            event.target.style.display = 'none';
        }
    };

    // Close modals with Escape key
    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape') {
            const modals = document.getElementsByClassName('modal');
            for (let i = 0; i < modals.length; i++) {
                if (modals[i].style.display === 'block') {
                    modals[i].style.display = 'none';
                }
            }
        }
    });

    // Initialize components when the DOM is loaded
    document.addEventListener('DOMContentLoaded', function() {
        // Load stock level data
        loadStockLevelsData();
        
        // Initialize tabs
        const activeTab = localStorage.getItem('activeInventoryTab') || 'products';
        openTab(activeTab);
        
        // Initialize order date to today
        const orderDateInput = document.getElementById('order_date');
        if (orderDateInput) {
            orderDateInput.valueAsDate = new Date();
        }
        
        // Initialize order items if container exists
        if (document.getElementById('orderItemsContainer')) {
            addOrderItem();
        }
    });
</script>
</body>
</html>