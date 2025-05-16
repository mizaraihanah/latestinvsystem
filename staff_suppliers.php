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

// Create suppliers table if it doesn't exist
$createTableSQL = "CREATE TABLE IF NOT EXISTS suppliers (
    supplier_id INT AUTO_INCREMENT PRIMARY KEY,
    supplier_name VARCHAR(100) NOT NULL,
    contact_person VARCHAR(100),
    email VARCHAR(100),
    phone VARCHAR(20),
    address TEXT,
    payment_terms VARCHAR(100),
    notes TEXT,
    created_by VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)";

$conn->query($createTableSQL);

// Handle Add Supplier
if (isset($_POST['add_supplier'])) {
    $supplierName = trim($_POST['supplier_name']);
    $contactPerson = trim($_POST['contact_person']);
    $email = trim($_POST['email']);
    $phone = trim($_POST['phone']);
    $address = trim($_POST['address']);
    $paymentTerms = trim($_POST['payment_terms']);
    $notes = trim($_POST['notes']);
    
    if (!empty($supplierName)) {
        $sql = "INSERT INTO suppliers (supplier_name, contact_person, email, phone, address, payment_terms, notes, created_by) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ssssssss", $supplierName, $contactPerson, $email, $phone, $address, $paymentTerms, $notes, $userID);
        
        if ($stmt->execute()) {
            $supplierId = $conn->insert_id;
            logInventoryActivity($conn, $userID, "add_supplier", $supplierId, "Added new supplier: $supplierName");
            header("Location: staff_suppliers.php?success=Supplier added successfully");
        } else {
            header("Location: staff_suppliers.php?error=Failed to add supplier: " . $conn->error);
        }
        $stmt->close();
        exit();
    }
}

// Handle Update Supplier
if (isset($_POST['update_supplier'])) {
    $supplierId = $_POST['supplier_id'];
    $supplierName = trim($_POST['supplier_name']);
    $contactPerson = trim($_POST['contact_person']);
    $email = trim($_POST['email']);
    $phone = trim($_POST['phone']);
    $address = trim($_POST['address']);
    $paymentTerms = trim($_POST['payment_terms']);
    $notes = trim($_POST['notes']);
    
    if (!empty($supplierId) && !empty($supplierName)) {
        $sql = "UPDATE suppliers 
                SET supplier_name = ?, contact_person = ?, email = ?, phone = ?, address = ?, payment_terms = ?, notes = ? 
                WHERE supplier_id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("sssssssi", $supplierName, $contactPerson, $email, $phone, $address, $paymentTerms, $notes, $supplierId);
        
        if ($stmt->execute()) {
            logInventoryActivity($conn, $userID, "update_supplier", $supplierId, "Updated supplier: $supplierName");
            header("Location: staff_suppliers.php?success=Supplier updated successfully");
        } else {
            header("Location: staff_suppliers.php?error=Failed to update supplier: " . $conn->error);
        }
        $stmt->close();
        exit();
    }
}

// Handle Delete Supplier
if (isset($_POST['delete_supplier'])) {
    $supplierId = $_POST['supplier_id'];
    
    // First check if this supplier has any orders
    $checkSql = "SELECT COUNT(*) AS order_count FROM orders WHERE customer_name IN 
                (SELECT supplier_name FROM suppliers WHERE supplier_id = ?)";
    $checkStmt = $conn->prepare($checkSql);
    $checkStmt->bind_param("i", $supplierId);
    $checkStmt->execute();
    $checkResult = $checkStmt->get_result();
    $row = $checkResult->fetch_assoc();
    $checkStmt->close();
    
    // If supplier has orders, don't delete
    if ($row['order_count'] > 0) {
        header("Location: staff_suppliers.php?error=Cannot delete supplier that has associated orders");
        exit();
    }
    
    // Get supplier name before deletion for logging
    $nameSql = "SELECT supplier_name FROM suppliers WHERE supplier_id = ?";
    $nameStmt = $conn->prepare($nameSql);
    $nameStmt->bind_param("i", $supplierId);
    $nameStmt->execute();
    $nameResult = $nameStmt->get_result();
    $supplierName = "";
    if ($nameRow = $nameResult->fetch_assoc()) {
        $supplierName = $nameRow['supplier_name'];
    }
    $nameStmt->close();
    
    // Delete the supplier
    $sql = "DELETE FROM suppliers WHERE supplier_id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("i", $supplierId);
    
    if ($stmt->execute()) {
        logInventoryActivity($conn, $userID, "delete_supplier", $supplierId, "Deleted supplier: $supplierName");
        header("Location: staff_suppliers.php?success=Supplier deleted successfully");
    } else {
        header("Location: staff_suppliers.php?error=Failed to delete supplier: " . $conn->error);
    }
    $stmt->close();
    exit();
}

// Set default search value
$searchTerm = isset($_GET['search']) ? $_GET['search'] : '';

// Build the query with potential search
$query = "SELECT * FROM suppliers WHERE 1=1";

$params = [];
$types = "";

if (!empty($searchTerm)) {
    $query .= " AND (supplier_name LIKE ? OR contact_person LIKE ? OR email LIKE ? OR phone LIKE ?)";
    $searchParam = "%$searchTerm%";
    array_push($params, $searchParam, $searchParam, $searchParam, $searchParam);
    $types .= "ssss";
}

$query .= " ORDER BY supplier_name";

// Prepare and execute the query
$stmt = $conn->prepare($query);
if (!empty($params)) {
    $stmt->bind_param($types, ...$params);
}
$stmt->execute();
$result_suppliers = $stmt->get_result();
$stmt->close();

// Count total suppliers
$countSql = "SELECT COUNT(*) as total FROM suppliers";
$countResult = $conn->query($countSql);
$totalSuppliers = $countResult->fetch_assoc()['total'];

// Get purchase orders from this supplier (for the dashboard stats)
$ordersSql = "SELECT COUNT(*) as order_count, SUM(total_amount) as total_spent 
             FROM orders 
             WHERE order_type = 'Purchase'";
$ordersResult = $conn->query($ordersSql);
$ordersData = $ordersResult->fetch_assoc();
$totalOrders = $ordersData['order_count'] ?? 0;
$totalSpent = $ordersData['total_spent'] ?? 0;

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Suppliers - Roti Seri Bakery</title>
    <link rel="stylesheet" href="staff_dashboard.css">
    <link rel="stylesheet" href="staff_suppliers.css">
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
            <a href="staff_suppliers.php" class="nav-item active">
                <i class="fas fa-truck"></i>
                <span>Manage Suppliers</span>
            </a>
            <a href="staff_alerts.php" class="nav-item">
                <i class="fas fa-bell"></i>
                <span>Alerts</span>
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
                <h1>Supplier Management</h1>
                <p>Welcome, <?php echo htmlspecialchars($fullName); ?>!</p>
            </div>
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

        <div class="dashboard-stats">
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-truck"></i>
                </div>
                <div class="stat-info">
                    <h3>Total Suppliers</h3>
                    <p><?php echo $totalSuppliers; ?></p>
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-shopping-cart"></i>
                </div>
                <div class="stat-info">
                    <h3>Purchase Orders</h3>
                    <p><?php echo $totalOrders; ?></p>
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-money-bill-wave"></i>
                </div>
                <div class="stat-info">
                    <h3>Total Spent</h3>
                    <p>RM <?php echo number_format($totalSpent, 2); ?></p>
                </div>
            </div>
        </div>

        <div class="supplier-actions">
            <div class="search-filters">
                <form method="GET" action="staff_suppliers.php">
                    <div class="search-bar">
                        <input type="text" name="search" placeholder="Search suppliers..." value="<?php echo htmlspecialchars($searchTerm); ?>">
                        <button type="submit"><i class="fas fa-search"></i></button>
                    </div>
                </form>
            </div>
            <button class="add-supplier-btn" onclick="showAddModal()">
                <i class="fas fa-plus"></i> Add New Supplier
            </button>
        </div>

        <div class="supplier-table-container">
            <table class="supplier-table">
                <thead>
                    <tr>
                        <th>Supplier Name</th>
                        <th>Contact Person</th>
                        <th>Email</th>
                        <th>Phone</th>
                        <th>Payment Terms</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if ($result_suppliers->num_rows > 0): ?>
                        <?php while ($supplier = $result_suppliers->fetch_assoc()): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($supplier['supplier_name']); ?></td>
                                <td><?php echo htmlspecialchars($supplier['contact_person']); ?></td>
                                <td><?php echo htmlspecialchars($supplier['email']); ?></td>
                                <td><?php echo htmlspecialchars($supplier['phone']); ?></td>
                                <td><?php echo htmlspecialchars($supplier['payment_terms']); ?></td>
                                <td>
                                    <div class="action-buttons">
                                        <button class="action-btn view-btn" title="View Details" 
                                                onclick="viewSupplierDetails(<?php echo htmlspecialchars(json_encode($supplier)); ?>)">
                                            <i class="fas fa-eye"></i>
                                        </button>
                                        <button class="action-btn edit-btn" title="Edit Supplier" 
                                                onclick="showEditModal(<?php echo htmlspecialchars(json_encode($supplier)); ?>)">
                                            <i class="fas fa-edit"></i>
                                        </button>
                                        <button class="action-btn delete-btn" title="Delete Supplier"
                                                onclick="confirmDelete(<?php echo $supplier['supplier_id']; ?>, '<?php echo addslashes($supplier['supplier_name']); ?>')">
                                            <i class="fas fa-trash"></i>
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        <?php endwhile; ?>
                    <?php else: ?>
                        <tr>
                            <td colspan="6" class="no-data">No suppliers found matching your criteria</td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- Add Supplier Modal -->
    <div id="addSupplierModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Add New Supplier</h2>
                <span class="close" onclick="closeModal('addSupplierModal')">&times;</span>
            </div>
            <div class="modal-body">
                <form id="addSupplierForm" action="staff_suppliers.php" method="POST">
                    <div class="form-group">
                        <label for="supplier_name">Supplier Name: <span class="required">*</span></label>
                        <div class="supplier-name-container">
                            <input type="text" id="supplier_name" name="supplier_name" list="existingSuppliers" autocomplete="off" required>
                            <i class="fas fa-magic autofill-indicator" title="Select an existing supplier to autofill details"></i>
                        </div>
                        <p class="existing-supplier-hint">Start typing to see existing suppliers or enter a new supplier name</p>
<datalist id="existingSuppliers">
<?php 
// Reset the suppliers result pointer and loop through suppliers
if ($result_suppliers && $result_suppliers->num_rows > 0) {
    $result_suppliers->data_seek(0);
    while ($supplier = $result_suppliers->fetch_assoc()) {
        echo '<option value="' . htmlspecialchars($supplier['supplier_name']) . '" 
            data-contact="' . htmlspecialchars($supplier['contact_person']) . '" 
            data-email="' . htmlspecialchars($supplier['email']) . '" 
            data-phone="' . htmlspecialchars($supplier['phone']) . '" 
            data-address="' . htmlspecialchars($supplier['address']) . '" 
            data-terms="' . htmlspecialchars($supplier['payment_terms']) . '"
            data-notes="' . htmlspecialchars($supplier['notes']) . '"></option>';
    }
}
?>
</datalist>
                    </div>
                    <div class="form-group">
                        <label for="contact_person">Contact Person:</label>
                        <input type="text" id="contact_person" name="contact_person">
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label for="email">Email:</label>
                            <input type="email" id="email" name="email">
                        </div>
                        <div class="form-group">
                            <label for="phone">Phone:</label>
                            <input type="text" id="phone" name="phone">
                        </div>
                    </div>
                    <div class="form-group">
                        <label for="address">Address:</label>
                        <textarea id="address" name="address" rows="3"></textarea>
                    </div>
                    <div class="form-group">
                        <label for="payment_terms">Payment Terms:</label>
                        <input type="text" id="payment_terms" name="payment_terms" placeholder="e.g., Net 30, COD">
                    </div>
                    <div class="form-group">
                        <label for="notes">Notes:</label>
                        <textarea id="notes" name="notes" rows="2"></textarea>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="cancel-btn" onclick="closeModal('addSupplierModal')">Cancel</button>
                        <button type="submit" name="add_supplier" class="save-btn">Add Supplier</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Edit Supplier Modal -->
    <div id="editSupplierModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Edit Supplier</h2>
                <span class="close" onclick="closeModal('editSupplierModal')">&times;</span>
            </div>
            <div class="modal-body">
                <form id="editSupplierForm" action="staff_suppliers.php" method="POST">
                    <input type="hidden" id="edit_supplier_id" name="supplier_id">
                    <div class="form-group">
                        <label for="edit_supplier_name">Supplier Name: <span class="required">*</span></label>
                        <input type="text" id="edit_supplier_name" name="supplier_name" required>
                    </div>
                    <div class="form-group">
                        <label for="edit_contact_person">Contact Person:</label>
                        <input type="text" id="edit_contact_person" name="contact_person">
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label for="edit_email">Email:</label>
                            <input type="email" id="edit_email" name="email">
                        </div>
                        <div class="form-group">
                            <label for="edit_phone">Phone:</label>
                            <input type="text" id="edit_phone" name="phone">
                        </div>
                    </div>
                    <div class="form-group">
                        <label for="edit_address">Address:</label>
                        <textarea id="edit_address" name="address" rows="3"></textarea>
                    </div>
                    <div class="form-group">
                        <label for="edit_payment_terms">Payment Terms:</label>
                        <input type="text" id="edit_payment_terms" name="payment_terms" placeholder="e.g., Net 30, COD">
                    </div>
                    <div class="form-group">
                        <label for="edit_notes">Notes:</label>
                        <textarea id="edit_notes" name="notes" rows="2"></textarea>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="cancel-btn" onclick="closeModal('editSupplierModal')">Cancel</button>
                        <button type="submit" name="update_supplier" class="save-btn">Update Supplier</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- View Supplier Details Modal -->
    <div id="viewSupplierModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>Supplier Details</h2>
                <span class="close" onclick="closeModal('viewSupplierModal')">&times;</span>
            </div>
            <div class="modal-body">
                <div class="supplier-details">
                    <div class="detail-row">
                        <div class="detail-label">Supplier Name:</div>
                        <div class="detail-value" id="view_supplier_name"></div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Contact Person:</div>
                        <div class="detail-value" id="view_contact_person"></div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Email:</div>
                        <div class="detail-value" id="view_email"></div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Phone:</div>
                        <div class="detail-value" id="view_phone"></div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Address:</div>
                        <div class="detail-value" id="view_address"></div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Payment Terms:</div>
                        <div class="detail-value" id="view_payment_terms"></div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Notes:</div>
                        <div class="detail-value" id="view_notes"></div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Created By:</div>
                        <div class="detail-value" id="view_created_by"></div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Last Updated:</div>
                        <div class="detail-value" id="view_updated_at"></div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="action-btn edit-btn" id="view_edit_btn">
                        <i class="fas fa-edit"></i> Edit Supplier
                    </button>
                    <button type="button" class="close-btn" onclick="closeModal('viewSupplierModal')">Close</button>
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
                <p>Are you sure you want to delete <span id="delete_supplier_name" class="highlighted-text"></span>?</p>
                <p class="warning-text">This action cannot be undone!</p>
                <form id="deleteSupplierForm" action="staff_suppliers.php" method="POST">
                    <input type="hidden" id="delete_supplier_id" name="supplier_id">
                    <div class="modal-footer">
                        <button type="button" class="cancel-btn" onclick="closeModal('deleteConfirmModal')">Cancel</button>
                        <button type="submit" name="delete_supplier" class="delete-btn">Delete Supplier</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script src="staff_suppliers.js"></script>
</body>
</html>