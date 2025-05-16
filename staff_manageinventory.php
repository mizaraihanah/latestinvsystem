<?php
session_start();

// Redirect to login page if user is not logged in or not a Bakery Staff
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

// Add inventory item
if (isset($_POST['add_item'])) {
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
            header("Location: staff_manageinventory.php?success=Product added successfully");
        } else {
            header("Location: staff_manageinventory.php?error=Failed to add product");
        }
        $stmt->close();
        exit();
    }
}

// Update inventory item
if (isset($_POST['update_item'])) {
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
            header("Location: staff_manageinventory.php?success=Product updated successfully");
        } else {
            header("Location: staff_manageinventory.php?error=Failed to update product: " . $stmt->error);
        }
        $stmt->close();
        exit();
    }
}

// Delete inventory item
if (isset($_POST['delete_item'])) {
    $productId = $_POST['product_id'];
    
    // Check if product is in any orders
    $checkSql = "SELECT COUNT(*) AS order_count FROM order_items WHERE product_id = ?";
    $checkStmt = $conn->prepare($checkSql);
    $checkStmt->bind_param("s", $productId);
    $checkStmt->execute();
    $checkResult = $checkStmt->get_result();
    $row = $checkResult->fetch_assoc();
    
    if ($row['order_count'] > 0) {
        header("Location: staff_manageinventory.php?error=Cannot delete product that is in use by orders");
        $checkStmt->close();
        exit();
    }
    
    $sql = "DELETE FROM products WHERE product_id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $productId);
    
    if ($stmt->execute()) {
        logInventoryActivity($conn, $userID, "delete_product", $productId, "Deleted product ID: $productId");
        header("Location: staff_manageinventory.php?success=Product deleted successfully");
    } else {
        header("Location: staff_manageinventory.php?error=Failed to delete product");
    }
    $stmt->close();
    exit();
}

// Update order status
if (isset($_POST['update_order_status'])) {
    $orderId = $_POST['order_id'];
    $newStatus = $_POST['status'];
    
    $sql = "UPDATE orders SET status = ?, status_changed_at = NOW() WHERE order_id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ss", $newStatus, $orderId);
    
    if ($stmt->execute()) {
        logInventoryActivity($conn, $userID, "update_order", $orderId, "Updated order status to: $newStatus");
        header("Location: staff_manageinventory.php?tab=orders&success=Order status updated successfully");
    } else {
        header("Location: staff_manageinventory.php?tab=orders&error=Failed to update order status");
    }
    $stmt->close();
    exit();
}

// Set default search and filter values
$searchTerm = isset($_GET['search']) ? $_GET['search'] : '';
$categoryFilter = isset($_GET['category']) ? $_GET['category'] : '';
$stockFilter = isset($_GET['stock_status']) ? $_GET['stock_status'] : '';
$activeTab = isset($_GET['tab']) ? $_GET['tab'] : 'inventory';

// Build the query with potential search/filters
$query = "SELECT p.*, c.category_name 
          FROM products p 
          LEFT JOIN product_categories c ON p.category_id = c.category_id 
          WHERE 1=1";

$params = [];
$types = "";

if (!empty($searchTerm)) {
    $query .= " AND (p.product_name LIKE ? OR p.product_id LIKE ?)";
    $searchParam = "%$searchTerm%";
    $params[] = $searchParam;
    $params[] = $searchParam;
    $types .= "ss";
}

if (!empty($categoryFilter)) {
    $query .= " AND p.category_id = ?";
    $params[] = $categoryFilter;
    $types .= "i";
}

if ($stockFilter === 'low') {
    $query .= " AND p.stock_quantity <= p.reorder_threshold AND p.stock_quantity > 0";
} else if ($stockFilter === 'out') {
    $query .= " AND p.stock_quantity = 0";
}

$query .= " ORDER BY p.product_name";

// Prepare and execute the query
$stmt = $conn->prepare($query);
if (!empty($params)) {
    $stmt->bind_param($types, ...$params);
}
$stmt->execute();
$result_products = $stmt->get_result();
$stmt->close();

// Fetch order data if on orders tab
if ($activeTab === 'orders') {
    $orderQuery = "SELECT o.*, 
                  (SELECT COUNT(*) FROM order_items WHERE order_id = o.order_id) as item_count 
                  FROM orders o
                  ORDER BY o.order_date DESC";
    $result_orders = $conn->query($orderQuery);
}

// Fetch product categories for the dropdown
$categoryQuery = "SELECT * FROM product_categories ORDER BY category_name";
$result_categories = $conn->query($categoryQuery);

// Fetch low stock notifications
$notificationQuery = "SELECT p.product_id, p.product_name, p.stock_quantity, p.reorder_threshold, c.category_name 
                     FROM products p
                     JOIN product_categories c ON p.category_id = c.category_id
                     WHERE p.stock_quantity <= p.reorder_threshold
                     ORDER BY (p.stock_quantity = 0) DESC, (p.stock_quantity / p.reorder_threshold) ASC
                     LIMIT 5";
$result_notifications = $conn->query($notificationQuery);

// Count low stock and out of stock
$lowStockQuery = "SELECT 
                     SUM(CASE WHEN stock_quantity <= reorder_threshold AND stock_quantity > 0 THEN 1 ELSE 0 END) as low_stock_count,
                     SUM(CASE WHEN stock_quantity = 0 THEN 1 ELSE 0 END) as out_of_stock_count
                  FROM products";
$stockResult = $conn->query($lowStockQuery);
$stockCounts = $stockResult->fetch_assoc();
$lowStockCount = $stockCounts['low_stock_count'];
$outOfStockCount = $stockCounts['out_of_stock_count'];
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Inventory - Roti Seri Bakery</title>
    <link rel="stylesheet" href="staff_dashboard.css">
    <link rel="stylesheet" href="staff_manageinventory.css">
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
            <a href="staff_dashboard.php" class="nav-item">
                <i class="fas fa-home"></i>
                <span>Home</span>
            </a>
            <a href="staff_manageinventory.php" class="nav-item active">
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
                <?php if ($lowStockCount + $outOfStockCount > 0): ?>
                <span class="badge"><?php echo $lowStockCount + $outOfStockCount; ?></span>
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
                <h1>Inventory Management</h1>
                <p>Welcome, <?php echo htmlspecialchars($fullName); ?>!</p>
            </div>
            
            <?php if ($lowStockCount + $outOfStockCount > 0): ?>
            <div class="notification-bell" onclick="toggleNotifications()">
                <i class="fas fa-bell"></i>
                <span class="notification-count"><?php echo $lowStockCount + $outOfStockCount; ?></span>
                
                <div class="notification-dropdown" id="notificationDropdown">
                    <div class="notification-header">
                        <h3>Stock Alerts</h3>
                    </div>
                    <div class="notification-body">
                        <?php if ($result_notifications->num_rows > 0): ?>
                            <?php while ($notification = $result_notifications->fetch_assoc()): ?>
                                <div class="notification-item">
                                    <div class="notification-icon <?php echo ($notification['stock_quantity'] == 0) ? 'danger' : 'warning'; ?>">
                                        <i class="fas <?php echo ($notification['stock_quantity'] == 0) ? 'fa-times-circle' : 'fa-exclamation-triangle'; ?>"></i>
                                    </div>
                                    <div class="notification-content">
                                        <div class="notification-title">
                                            <?php echo ($notification['stock_quantity'] == 0) ? 'Out of Stock' : 'Low Stock'; ?>
                                        </div>
                                        <div class="notification-message">
                                            <?php echo htmlspecialchars($notification['product_name']); ?> - 
                                            <?php echo $notification['stock_quantity']; ?> left (min: <?php echo $notification['reorder_threshold']; ?>)
                                        </div>
                                    </div>
                                </div>
                            <?php endwhile; ?>
                            <a href="staff_alerts.php" class="view-all-link">View All Alerts</a>
                        <?php else: ?>
                            <div class="no-notifications">No stock alerts to display.</div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
            <?php endif; ?>
        </div>

        <?php if (isset($_GET['success'])): ?>
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i>
                <?php echo htmlspecialchars($_GET['success']); ?>
                <button class="close-alert" onclick="this.parentElement.style.display='none';">&times;</button>
            </div>
        <?php endif; ?>
        
        <?php if (isset($_GET['error'])): ?>
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-circle"></i>
                <?php echo htmlspecialchars($_GET['error']); ?>
                <button class="close-alert" onclick="this.parentElement.style.display='none';">&times;</button>
            </div>
        <?php endif; ?>

        <div class="tabs">
            <button class="tab-btn <?php echo ($activeTab === 'inventory') ? 'active' : ''; ?>" 
                    onclick="location.href='staff_manageinventory.php?tab=inventory'">
                <i class="fas fa-boxes"></i> Inventory Items
            </button>
            <button class="tab-btn <?php echo ($activeTab === 'orders') ? 'active' : ''; ?>"
                    onclick="location.href='staff_manageinventory.php?tab=orders'">
                <i class="fas fa-shopping-cart"></i> Orders
            </button>
        </div>

        <!-- Inventory Tab -->
        <?php if ($activeTab === 'inventory'): ?>
            <div class="inventory-actions">
                <div class="search-filters">
                    <form method="GET" action="staff_manageinventory.php">
                        <input type="hidden" name="tab" value="inventory">
                        <div class="search-bar">
                            <input type="text" name="search" placeholder="Search products..." value="<?php echo htmlspecialchars($searchTerm); ?>">
                            <button type="submit"><i class="fas fa-search"></i></button>
                        </div>
                        <div class="filters">
                            <select name="category">
                                <option value="">All Categories</option>
                                <?php 
                                $result_categories->data_seek(0);
                                while ($category = $result_categories->fetch_assoc()): 
                                ?>
                                    <option value="<?php echo $category['category_id']; ?>" 
                                        <?php echo ($categoryFilter == $category['category_id']) ? 'selected' : ''; ?>>
                                        <?php echo htmlspecialchars($category['category_name']); ?>
                                    </option>
                                <?php endwhile; ?>
                            </select>
                            <select name="stock_status">
                                <option value="">All Stock Status</option>
                                <option value="low" <?php echo ($stockFilter === 'low') ? 'selected' : ''; ?>>Low Stock</option>
                                <option value="out" <?php echo ($stockFilter === 'out') ? 'selected' : ''; ?>>Out of Stock</option>
                            </select>
                            <button type="submit" class="filter-btn">Apply Filters</button>
                            <button type="button" class="filter-btn reset" onclick="window.location='staff_manageinventory.php'">Reset</button>
                        </div>
                    </form>
                </div>
                <button class="add-item-btn" onclick="showAddModal()">
                    <i class="fas fa-plus"></i> Add New Item
                </button>
            </div>

            <div class="inventory-table-container">
                <table class="inventory-table">
                    <thead>
                        <tr>
                            <th>Product ID</th>
                            <th>Product Name</th>
                            <th>Category</th>
                            <th>Stock Quantity</th>
                            <th>Reorder Level</th>
                            <th>Unit Price</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if ($result_products->num_rows > 0): ?>
                            <?php while ($product = $result_products->fetch_assoc()): ?>
                                <?php 
                                $statusClass = 'normal';
                                $statusText = 'Normal';
                                if ($product['stock_quantity'] == 0) {
                                    $statusClass = 'out';
                                    $statusText = 'Out of Stock';
                                } else if ($product['stock_quantity'] <= $product['reorder_threshold']) {
                                    $statusClass = 'low';
                                    $statusText = 'Low Stock';
                                }
                                ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($product['product_id']); ?></td>
                                    <td><?php echo htmlspecialchars($product['product_name']); ?></td>
                                    <td><?php echo htmlspecialchars($product['category_name']); ?></td>
                                    <td><?php echo htmlspecialchars($product['stock_quantity']); ?></td>
                                    <td><?php echo htmlspecialchars($product['reorder_threshold']); ?></td>
                                    <td>RM <?php echo number_format($product['unit_price'], 2); ?></td>
                                    <td><span class="status <?php echo $statusClass; ?>"><?php echo $statusText; ?></span></td>
                                    <td>
                                        <div class="action-buttons">
                                            <button class="action-btn view-btn" title="View Details" 
                                                    onclick="viewItemDetails('<?php echo addslashes(json_encode($product)); ?>')">
                                                <i class="fas fa-eye"></i>
                                            </button>
                                            <button class="action-btn edit-btn" title="Edit Item" 
                                                    onclick="showEditModal(<?php echo htmlspecialchars(json_encode($product)); ?>)">
                                                <i class="fas fa-edit"></i>
                                            </button>
                                            <button class="action-btn delete-btn" title="Delete Item"
                                                    onclick="confirmDelete('<?php echo $product['product_id']; ?>', '<?php echo addslashes($product['product_name']); ?>')">
                                                <i class="fas fa-trash"></i>
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            <?php endwhile; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="8" class="no-data">No products found matching your criteria</td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>

        <!-- Orders Tab -->
        <?php elseif ($activeTab === 'orders'): ?>
            <div class="orders-table-container">
                <table class="inventory-table">
                    <thead>
                        <tr>
                            <th>Order ID</th>
                            <th>Type</th>
                            <th>Customer/Supplier</th>
                            <th>Order Date</th>
                            <th>Items</th>
                            <th>Total Amount</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (isset($result_orders) && $result_orders->num_rows > 0): ?>
                            <?php while ($order = $result_orders->fetch_assoc()): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($order['order_id']); ?></td>
                                    <td><?php echo htmlspecialchars($order['order_type']); ?></td>
                                    <td><?php echo htmlspecialchars($order['customer_name']); ?></td>
                                    <td><?php echo htmlspecialchars($order['order_date']); ?></td>
                                    <td><?php echo htmlspecialchars($order['item_count']); ?></td>
                                    <td>RM <?php echo number_format($order['total_amount'], 2); ?></td>
                                    <td>
                                        <span class="status <?php echo strtolower($order['status']); ?>">
                                            <?php echo htmlspecialchars($order['status']); ?>
                                        </span>
                                    </td>
                                    <td>
                                        <div class="action-buttons">
                                            <button class="action-btn view-btn" title="View Details" 
                                                    onclick="viewOrderDetails('<?php echo $order['order_id']; ?>')">
                                                <i class="fas fa-eye"></i>
                                            </button>
                                            <button class="action-btn edit-btn" title="Update Status"
                                                    onclick="showUpdateStatusModal('<?php echo $order['order_id']; ?>', '<?php echo $order['status']; ?>')">
                                                <i class="fas fa-edit"></i>
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            <?php endwhile; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="8" class="no-data">No orders found</td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>

    <!-- Add Item Modal -->
    <div id="addItemModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Add New Inventory Item</h2>
                <span class="close" onclick="closeModal('addItemModal')">&times;</span>
            </div>
            <div class="modal-body">
                <form id="addItemForm" action="staff_manageinventory.php" method="POST">
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
                            $result_categories->data_seek(0);
                            while ($category = $result_categories->fetch_assoc()): 
                            ?>
                                <option value="<?php echo $category['category_id']; ?>">
                                    <?php echo htmlspecialchars($category['category_name']); ?>
                                </option>
                            <?php endwhile; ?>
                        </select>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label for="stock_quantity">Initial Stock Quantity:</label>
                            <input type="number" id="stock_quantity" name="stock_quantity" min="0" value="0" required>
                        </div>
                        <div class="form-group">
                            <label for="reorder_threshold">Reorder Threshold:</label>
                            <input type="number" id="reorder_threshold" name="reorder_threshold" min="0" value="10" required>
                        </div>
                    </div>
                    <div class="form-group">
                        <label for="unit_price">Unit Price (RM):</label>
                        <input type="number" id="unit_price" name="unit_price" min="0" step="0.01" value="0.00" required>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="cancel-btn" onclick="closeModal('addItemModal')">Cancel</button>
                        <button type="submit" name="add_item" class="save-btn">Add Item</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Edit Item Modal -->
    <div id="editItemModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Edit Inventory Item</h2>
                <span class="close" onclick="closeModal('editItemModal')">&times;</span>
            </div>
            <div class="modal-body">
                <form id="editItemForm" action="staff_manageinventory.php" method="POST">
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
                            $result_categories->data_seek(0);
                            while ($category = $result_categories->fetch_assoc()): 
                            ?>
                                <option value="<?php echo $category['category_id']; ?>">
                                    <?php echo htmlspecialchars($category['category_name']); ?>
                                </option>
                            <?php endwhile; ?>
                        </select>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label for="edit_stock_quantity">Stock Quantity:</label>
                            <input type="number" id="edit_stock_quantity" name="stock_quantity" min="0" required>
                        </div>
                        <div class="form-group">
                            <label for="edit_reorder_threshold">Reorder Threshold:</label>
                            <input type="number" id="edit_reorder_threshold" name="reorder_threshold" min="0" required>
                        </div>
                    </div>
                    <div class="form-group">
                        <label for="edit_unit_price">Unit Price (RM):</label>
                        <input type="number" id="edit_unit_price" name="unit_price" min="0" step="0.01" required>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="cancel-btn" onclick="closeModal('editItemModal')">Cancel</button>
                        <button type="submit" name="update_item" class="save-btn">Update Item</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- View Item Details Modal -->
    <div id="viewItemModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Item Details</h2>
                <span class="close" onclick="closeModal('viewItemModal')">&times;</span>
            </div>
            <div class="modal-body">
                <div class="item-details">
                    <div class="detail-row">
                        <div class="detail-label">Product ID:</div>
                        <div class="detail-value" id="view_product_id"></div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Product Name:</div>
                        <div class="detail-value" id="view_product_name"></div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Description:</div>
                        <div class="detail-value" id="view_product_description"></div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Category:</div>
                        <div class="detail-value" id="view_category_name"></div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Stock Quantity:</div>
                        <div class="detail-value" id="view_stock_quantity"></div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Reorder Threshold:</div>
                        <div class="detail-value" id="view_reorder_threshold"></div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Unit Price:</div>
                        <div class="detail-value" id="view_unit_price"></div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Last Updated:</div>
                        <div class="detail-value" id="view_last_updated"></div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Status:</div>
                        <div class="detail-value" id="view_status"></div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="action-btn edit-btn" id="view_edit_btn">
                        <i class="fas fa-edit"></i> Edit Item
                    </button>
                    <button type="button" class="close-btn" onclick="closeModal('viewItemModal')">Close</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Delete Confirmation Modal -->
    <div id="deleteConfirmModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Confirm Deletion</h2>
                <span class="close" onclick="closeModal('deleteConfirmModal')">&times;</span>
            </div>
            <div class="modal-body">
                <p>Are you sure you want to delete <span id="delete_item_name" class="highlighted-text"></span>?</p>
                <p class="warning-text">This action cannot be undone!</p>
                <form id="deleteItemForm" action="staff_manageinventory.php" method="POST">
                    <input type="hidden" id="delete_product_id" name="product_id">
                    <div class="modal-footer">
                        <button type="button" class="cancel-btn" onclick="closeModal('deleteConfirmModal')">Cancel</button>
                        <button type="submit" name="delete_item" class="delete-btn">Delete Item</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- View Order Details Modal -->
    <div id="viewOrderModal" class="modal">
        <div class="modal-content wider-modal">
            <div class="modal-header">
                <h2>Order Details</h2>
                <span class="close" onclick="closeModal('viewOrderModal')">&times;</span>
            </div>
            <div class="modal-body">
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
                </div>
                <div class="modal-footer">
                    <button type="button" class="action-btn edit-btn" id="updateStatusBtn">
                        <i class="fas fa-edit"></i> Update Status
                    </button>
                    <button type="button" class="close-btn" onclick="closeModal('viewOrderModal')">Close</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Update Order Status Modal -->
    <div id="updateOrderStatusModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Update Order Status</h2>
                <span class="close" onclick="closeModal('updateOrderStatusModal')">&times;</span>
            </div>
            <div class="modal-body">
                <form id="updateOrderStatusForm" action="staff_manageinventory.php" method="POST">
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
                    <div class="modal-footer">
                        <button type="button" class="cancel-btn" onclick="closeModal('updateOrderStatusModal')">Cancel</button>
                        <button type="submit" name="update_order_status" class="save-btn">Update Status</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script src="staff_manageinventory.js"></script>
</body>
</html>