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

// Mark all notifications as read
if (isset($_GET['mark_all_read'])) {
    $updateSql = "UPDATE staff_notifications SET is_read = 1 WHERE user_id = ?";
    $updateStmt = $conn->prepare($updateSql);
    $updateStmt->bind_param("s", $userID);
    $updateStmt->execute();
    $updateStmt->close();
    
    header("Location: staff_alerts.php");
    exit();
}

// Mark a specific notification as read
if (isset($_GET['mark_read']) && is_numeric($_GET['mark_read'])) {
    $notificationId = $_GET['mark_read'];
    $markSql = "UPDATE staff_notifications SET is_read = 1 
                WHERE notification_id = ? AND user_id = ?";
    $markStmt = $conn->prepare($markSql);
    $markStmt->bind_param("is", $notificationId, $userID);
    $markStmt->execute();
    $markStmt->close();
    
    header("Location: staff_alerts.php");
    exit();
}

// Get all notifications for this user
$notifyQuery = "SELECT n.*, 
               CASE 
                   WHEN n.type = 'order_status' THEN o.customer_name 
                   WHEN n.type IN ('low_stock', 'out_of_stock') THEN p.product_name 
                   ELSE NULL 
               END AS item_name,
               n.item_id
               FROM staff_notifications n
               LEFT JOIN orders o ON n.type = 'order_status' AND n.item_id = o.order_id
               LEFT JOIN products p ON n.type IN ('low_stock', 'out_of_stock') AND n.item_id = p.product_id
               WHERE n.user_id = ?
               ORDER BY n.created_at DESC";
               
$notifyStmt = $conn->prepare($notifyQuery);

// Add error handling
if ($notifyStmt === false) {
    // Handle the error - the query has a syntax error
    echo "Error preparing statement: " . $conn->error;
    exit();
}

$notifyStmt->bind_param("s", $userID);
$notifyStmt->execute();
$notifications = $notifyStmt->get_result();
$notifyStmt->close();

// Count unread notifications
$countQuery = "SELECT COUNT(*) as unread_count FROM staff_notifications WHERE user_id = ? AND is_read = 0";
$countStmt = $conn->prepare($countQuery);
$countStmt->bind_param("s", $userID);
$countStmt->execute();
$countResult = $countStmt->get_result();
$unreadCount = $countResult->fetch_assoc()['unread_count'];
$countStmt->close();

// Get low stock items
$lowStockQuery = "SELECT p.*, c.category_name
                 FROM products p
                 JOIN product_categories c ON p.category_id = c.category_id
                 WHERE p.stock_quantity <= p.reorder_threshold
                 ORDER BY (p.stock_quantity = 0) DESC, (p.stock_quantity / p.reorder_threshold) ASC";
$lowStockResult = $conn->query($lowStockQuery);

// Get recent order status changes
$recentOrdersQuery = "SELECT o.*, 
                     (SELECT COUNT(*) FROM order_items WHERE order_id = o.order_id) as item_count
                     FROM orders o
                     WHERE o.status_changed_at IS NOT NULL
                     ORDER BY o.status_changed_at DESC
                     LIMIT 10";
$recentOrdersResult = $conn->query($recentOrdersQuery);

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Alerts - Roti Seri Bakery</title>
    <link rel="stylesheet" href="staff_dashboard.css">
    <link rel="stylesheet" href="staff_alerts.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
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
            <a href="staff_manageinventory.php" class="nav-item">
                <i class="fas fa-boxes"></i>
                <span>Manage Inventory</span>
            </a>
            <a href="staff_suppliers.php" class="nav-item">
                <i class="fas fa-truck"></i>
                <span>Manage Suppliers</span>
            </a>
            <a href="staff_alerts.php" class="nav-item active">
                <i class="fas fa-bell"></i>
                <span>Alerts</span>
                <?php if ($unreadCount > 0): ?>
                <span class="badge"><?php echo $unreadCount; ?></span>
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
                <h1>Alerts & Notifications</h1>
                <p>Welcome, <?php echo htmlspecialchars($fullName); ?>!</p>
            </div>
            
            <div class="action-buttons">
                <?php if ($unreadCount > 0): ?>
                <a href="staff_alerts.php?mark_all_read=1" class="action-btn">
                    <i class="fas fa-check-double"></i> Mark All as Read
                </a>
                <?php endif; ?>
                <a href="staff_manageinventory.php?stock_status=low" class="action-btn">
                    <i class="fas fa-boxes"></i> Manage Inventory
                </a>
            </div>
        </div>

        <!-- Low Stock Items Section -->
        <div class="alert-section">
            <div class="section-header">
                <h2><i class="fas fa-exclamation-triangle"></i> Low Stock Items</h2>
                <span class="count-badge"><?php echo $lowStockResult->num_rows; ?> items</span>
            </div>
            
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Product ID</th>
                            <th>Product Name</th>
                            <th>Category</th>
                            <th>Current Stock</th>
                            <th>Threshold</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if ($lowStockResult && $lowStockResult->num_rows > 0): ?>
                            <?php while ($item = $lowStockResult->fetch_assoc()): ?>
                                <?php 
                                    $statusClass = 'low';
                                    $statusText = 'Low Stock';
                                    if ($item['stock_quantity'] == 0) {
                                        $statusClass = 'out';
                                        $statusText = 'Out of Stock';
                                    }
                                ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($item['product_id']); ?></td>
                                    <td><?php echo htmlspecialchars($item['product_name']); ?></td>
                                    <td><?php echo htmlspecialchars($item['category_name']); ?></td>
                                    <td><?php echo htmlspecialchars($item['stock_quantity']); ?></td>
                                    <td><?php echo htmlspecialchars($item['reorder_threshold']); ?></td>
                                    <td><span class="status <?php echo $statusClass; ?>"><?php echo $statusText; ?></span></td>
                                    <td>
                                        <a href="javascript:void(0)" onclick="showEditStockModal('<?php echo $item['product_id']; ?>', '<?php echo addslashes($item['product_name']); ?>', '<?php echo $item['stock_quantity']; ?>')" class="table-action-btn">
                                            <i class="fas fa-edit"></i> Update Stock
                                        </a>
                                    </td>
                                </tr>
                            <?php endwhile; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="7" class="no-data">No low stock items found.</td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Recent Order Status Changes -->
        <?php if (isset($recentOrdersResult) && $recentOrdersResult !== false && $recentOrdersResult->num_rows > 0): ?>
        <div class="alert-section">
            <div class="section-header">
                <h2><i class="fas fa-shopping-cart"></i> Recent Order Updates</h2>
                <a href="staff_manageinventory.php?tab=orders" class="action-link">View All Orders</a>
            </div>
            
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Order ID</th>
                            <th>Type</th>
                            <th>Customer/Supplier</th>
                            <th>Items</th>
                            <th>Total</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while ($order = $recentOrdersResult->fetch_assoc()): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($order['order_id']); ?></td>
                                <td><?php echo htmlspecialchars($order['order_type']); ?></td>
                                <td><?php echo htmlspecialchars($order['customer_name']); ?></td>
                                <td><?php echo htmlspecialchars($order['item_count']); ?></td>
                                <td>RM <?php echo number_format($order['total_amount'], 2); ?></td>
                                <td><span class="status <?php echo strtolower($order['status']); ?>"><?php echo $order['status']; ?></span></td>
                                <td>
                                    <a href="javascript:void(0)" onclick="viewOrderDetails('<?php echo $order['order_id']; ?>')" class="table-action-btn">
                                        <i class="fas fa-eye"></i> View Details
                                    </a>
                                </td>
                            </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <?php endif; ?>

        <!-- All Notifications -->
        <div class="alert-section">
            <div class="section-header">
                <h2><i class="fas fa-bell"></i> Notifications</h2>
                <?php if ($unreadCount > 0): ?>
                <span class="unread-badge"><?php echo $unreadCount; ?> unread</span>
                <?php endif; ?>
            </div>
            
            <div class="notifications-container">
                <?php if ($notifications && $notifications->num_rows > 0): ?>
                    <?php while ($notification = $notifications->fetch_assoc()): ?>
                        <?php 
                            $iconClass = 'info';
                            $iconName = 'info-circle';
                            
                            if ($notification['type'] == 'low_stock') {
                                $iconClass = 'warning';
                                $iconName = 'exclamation-triangle';
                            } else if ($notification['type'] == 'out_of_stock') {
                                $iconClass = 'danger';
                                $iconName = 'times-circle';
                            } else if ($notification['type'] == 'order_status') {
                                $iconClass = 'info';
                                $iconName = 'shopping-cart';
                            }
                            
                            $unreadClass = $notification['is_read'] ? '' : 'unread';
                            $dateTime = new DateTime($notification['created_at']);
                            $formattedDate = $dateTime->format('M j, Y g:i A');
                        ?>
                        <div class="notification-item <?php echo $unreadClass; ?>" data-id="<?php echo $notification['notification_id']; ?>">
                            <div class="notification-icon <?php echo $iconClass; ?>">
                                <i class="fas fa-<?php echo $iconName; ?>"></i>
                            </div>
                            <div class="notification-content">
                                <div class="notification-header">
                                    <span class="notification-title">
                                        <?php 
                                            if ($notification['type'] == 'low_stock') {
                                                echo 'Low Stock Alert';
                                            } else if ($notification['type'] == 'out_of_stock') {
                                                echo 'Out of Stock Alert';
                                            } else {
                                                echo 'Order Status Update';
                                            }
                                        ?>
                                    </span>
                                    <span class="notification-time"><?php echo $formattedDate; ?></span>
                                </div>
                                <div class="notification-message"><?php echo htmlspecialchars($notification['message']); ?></div>
                                <?php if (!empty($notification['item_name'])): ?>
                                <div class="notification-item-name">Item: <?php echo htmlspecialchars($notification['item_name']); ?></div>
                                <?php endif; ?>
                                
                                <div class="notification-actions">
                                    <?php if ($notification['type'] == 'low_stock' || $notification['type'] == 'out_of_stock'): ?>
                                        <a href="javascript:void(0)" onclick="showEditStockModal('<?php echo $notification['item_id']; ?>', '<?php echo addslashes($notification['item_name']); ?>')" class="action-link">
                                            <i class="fas fa-edit"></i> Update Stock
                                        </a>
                                    <?php elseif ($notification['type'] == 'order_status'): ?>
                                        <a href="javascript:void(0)" onclick="viewOrderDetails('<?php echo $notification['item_id']; ?>')" class="action-link">
                                            <i class="fas fa-eye"></i> View Order
                                        </a>
                                    <?php endif; ?>
                                    
                                    <?php if (!$notification['is_read']): ?>
                                    <a href="staff_alerts.php?mark_read=<?php echo $notification['notification_id']; ?>" class="action-link mark-read">
                                        <i class="fas fa-check"></i> Mark as Read
                                    </a>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                    <?php endwhile; ?>
                <?php else: ?>
                    <div class="no-notifications">
                        <i class="fas fa-check-circle"></i>
                        <p>No notifications to display.</p>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- Update Stock Modal -->
    <div id="updateStockModal" class="modal" style="display: none;">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Update Stock Level</h2>
                <span class="close" onclick="closeModal('updateStockModal')">&times;</span>
            </div>
            <div class="modal-body">
                <form id="updateStockForm" action="update_stock.php" method="POST">
                    <input type="hidden" id="update_product_id" name="product_id">
                    
                    <div class="form-group">
                        <label for="product_name">Product Name:</label>
                        <input type="text" id="update_product_name" disabled>
                    </div>
                    
                    <div class="form-group">
                        <label for="current_stock">Current Stock:</label>
                        <input type="number" id="update_current_stock" disabled>
                    </div>
                    
                    <div class="form-group">
                        <label for="new_stock">New Stock Quantity:</label>
                        <input type="number" id="update_new_stock" name="new_stock" min="0" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="stock_note">Note/Reason:</label>
                        <textarea id="update_stock_note" name="note" rows="2" placeholder="Optional: reason for stock update"></textarea>
                    </div>
                    
                    <div class="modal-footer">
                        <button type="button" class="cancel-btn" onclick="closeModal('updateStockModal')">Cancel</button>
                        <button type="submit" class="save-btn">Update Stock</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- View Order Details Modal -->
    <div id="viewOrderModal" class="modal" style="display: none;">
        <div class="modal-content wider-modal">
            <div class="modal-header">
                <h2>Order Details</h2>
                <span class="close" onclick="closeModal('viewOrderModal')">&times;</span>
            </div>
            <div class="modal-body">
                <div id="orderDetailsContainer">
                    <div class="loading-spinner">
                        <div class="spinner"></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="staff_alerts.js"></script>
    <script>
        // Function to close modal
        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }
        
        // Function to show the update stock modal
        function showEditStockModal(productId, productName, currentStock = 0) {
            document.getElementById('update_product_id').value = productId;
            document.getElementById('update_product_name').value = productName;
            document.getElementById('update_current_stock').value = currentStock;
            document.getElementById('update_new_stock').value = currentStock;
            document.getElementById('updateStockModal').style.display = 'block';
        }
        
        // Function to view order details
        function viewOrderDetails(orderId) {
            // Show loading state
            document.getElementById('orderDetailsContainer').innerHTML = '<div class="loading-spinner"><div class="spinner"></div></div>';
            
            // Show the modal
            document.getElementById('viewOrderModal').style.display = 'block';
            
            // Fetch order details
            fetch('get_order_details.php?id=' + orderId)
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        document.getElementById('orderDetailsContainer').innerHTML = 
                            `<div class="error-message">Error: ${data.error}</div>`;
                        return;
                    }
                    
                    // Format the order date
                    const orderDate = new Date(data.order.order_date);
                    const formattedDate = orderDate.toLocaleDateString('en-MY', {
                        year: 'numeric',
                        month: 'long',
                        day: 'numeric'
                    });
                    
                    // Build order details HTML
                    let html = `
                        <div class="order-header">
                            <div class="order-info">
                                <p><strong>Order ID:</strong> ${data.order.order_id}</p>
                                <p><strong>Type:</strong> ${data.order.order_type}</p>
                                <p><strong>Customer/Supplier:</strong> ${data.order.customer_name}</p>
                            </div>
                            <div class="order-info">
                                <p><strong>Date:</strong> ${formattedDate}</p>
                                <p><strong>Status:</strong> <span class="status ${data.order.status.toLowerCase()}">${data.order.status}</span></p>
                                <p><strong>Created By:</strong> ${data.order.created_by_name || data.order.created_by}</p>
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
                                <tbody>
                    `;
                    
                    // Add order items
                    let totalAmount = 0;
                    if (data.items && data.items.length > 0) {
                        data.items.forEach(item => {
                            const subtotal = item.quantity * item.unit_price;
                            totalAmount += subtotal;
                            
                            html += `
                                <tr>
                                    <td>${item.product_id}</td>
                                    <td>${item.product_name}</td>
                                    <td>${item.quantity}</td>
                                    <td>RM ${parseFloat(item.unit_price).toFixed(2)}</td>
                                    <td>RM ${subtotal.toFixed(2)}</td>
                                </tr>
                            `;
                        });
                    } else {
                        html += `<tr><td colspan="5" class="no-data">No items found for this order</td></tr>`;
                    }
                    
                    // Add total row
                    html += `
                                </tbody>
                                <tfoot>
                                    <tr>
                                        <td colspan="4" class="text-right"><strong>Total:</strong></td>
                                        <td><strong>RM ${totalAmount.toFixed(2)}</strong></td>
                                    </tr>
                                </tfoot>
                            </table>
                        </div>
                    `;
                    
                    // Add actions
                    html += `
                        <div class="modal-footer">
                            <a href="staff_manageinventory.php?tab=orders" class="action-btn">
                                <i class="fas fa-list"></i> View All Orders
                            </a>
                            <button type="button" class="close-btn" onclick="closeModal('viewOrderModal')">Close</button>
                        </div>
                    `;
                    
                    document.getElementById('orderDetailsContainer').innerHTML = html;
                })
                .catch(error => {
                    console.error('Error:', error);
                    document.getElementById('orderDetailsContainer').innerHTML = 
                        `<div class="error-message">Error loading order details. Please try again later.</div>`;
                });
        }
        
        // Mark notifications as read when clicked
        document.addEventListener('DOMContentLoaded', function() {
            document.querySelectorAll('.notification-item.unread').forEach(item => {
                item.addEventListener('click', function(e) {
                    // Don't mark as read if clicking on action links
                    if (!e.target.closest('.action-link')) {
                        const notificationId = this.dataset.id;
                        window.location.href = `staff_alerts.php?mark_read=${notificationId}`;
                    }
                });
            });
        });
    </script>
</body>
</html>