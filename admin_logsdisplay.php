<?php
session_start();

// Redirect to login page if user is not logged in or not an admin
if (!isset($_SESSION['userID']) || $_SESSION['role'] !== 'Administrator') {
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
    $fullName = "Admin";
}

$stmt->close();

// Set default filter values
$userFilter = isset($_GET['user']) ? $_GET['user'] : '';
$actionFilter = isset($_GET['action']) ? $_GET['action'] : '';
$dateFrom = isset($_GET['date_from']) ? $_GET['date_from'] : '';
$dateTo = isset($_GET['date_to']) ? $_GET['date_to'] : '';
$logTypeFilter = isset($_GET['log_type']) ? $_GET['log_type'] : 'all'; // Add log type filter

// Build the admin logs query
$admin_query = "SELECT l.*, 
                a.fullName AS admin_name, 
                u.fullName AS affected_user_name,
                'admin' AS log_type
              FROM admin_logs l
              LEFT JOIN users a ON l.admin_id = a.userID
              LEFT JOIN users u ON l.affected_user = u.userID
              WHERE 1=1";

// Build the inventory logs query
$inventory_query = "SELECT l.*,
                     u.fullName AS user_name,
                     'inventory' AS log_type
                   FROM inventory_logs l
                   LEFT JOIN users u ON l.user_id = u.userID
                   WHERE 1=1";

$admin_params = [];
$admin_types = "";
$inventory_params = [];
$inventory_types = "";

// Apply filters to admin query
if (!empty($userFilter)) {
    $admin_query .= " AND (l.admin_id = ? OR l.affected_user = ?)";
    $admin_params[] = $userFilter;
    $admin_params[] = $userFilter;
    $admin_types .= "ss";
}

if (!empty($actionFilter)) {
    $admin_query .= " AND l.action = ?";
    $admin_params[] = $actionFilter;
    $admin_types .= "s";
}

if (!empty($dateFrom)) {
    $admin_query .= " AND DATE(l.timestamp) >= ?";
    $admin_params[] = $dateFrom;
    $admin_types .= "s";
}

if (!empty($dateTo)) {
    $admin_query .= " AND DATE(l.timestamp) <= ?";
    $admin_params[] = $dateTo;
    $admin_types .= "s";
}

// Apply filters to inventory query
if (!empty($userFilter)) {
    $inventory_query .= " AND l.user_id = ?";
    $inventory_params[] = $userFilter;
    $inventory_types .= "s";
}

if (!empty($actionFilter)) {
    $inventory_query .= " AND l.action = ?";
    $inventory_params[] = $actionFilter;
    $inventory_types .= "s";
}

if (!empty($dateFrom)) {
    $inventory_query .= " AND DATE(l.timestamp) >= ?";
    $inventory_params[] = $dateFrom;
    $inventory_types .= "s";
}

if (!empty($dateTo)) {
    $inventory_query .= " AND DATE(l.timestamp) <= ?";
    $inventory_params[] = $dateTo;
    $inventory_types .= "s";
}

// Get admin logs if needed
$result_admin_logs = null;
if ($logTypeFilter == 'admin' || $logTypeFilter == 'all') {
    $stmt = $conn->prepare($admin_query . " ORDER BY l.timestamp DESC");
    if (!empty($admin_types)) {
        $stmt->bind_param($admin_types, ...$admin_params);
    }
    $stmt->execute();
    $result_admin_logs = $stmt->get_result();
    $stmt->close();
}

// Get inventory logs if needed
$result_inventory_logs = null;
if ($logTypeFilter == 'inventory' || $logTypeFilter == 'all') {
    $stmt = $conn->prepare($inventory_query . " ORDER BY l.timestamp DESC");
    if (!empty($inventory_types)) {
        $stmt->bind_param($inventory_types, ...$inventory_params);
    }
    $stmt->execute();
    $result_inventory_logs = $stmt->get_result();
    $stmt->close();
}

// Get distinct actions for the filter dropdown (combined from both tables)
$action_query = "SELECT DISTINCT action FROM admin_logs 
                UNION 
                SELECT DISTINCT action FROM inventory_logs 
                ORDER BY action";
$result_actions = $conn->query($action_query);

// Get users for the filter dropdown (all user roles)
$user_query = "SELECT DISTINCT u.userID, u.fullName, u.role 
               FROM users u
               ORDER BY u.role, u.fullName";
$result_users = $conn->query($user_query);

// Get summary statistics - FIXED VERSION
$stats_query = "SELECT 
                  (SELECT COUNT(*) FROM admin_logs) + (SELECT COUNT(*) FROM inventory_logs) as total_logs,
                  (SELECT COUNT(*) FROM users WHERE role = 'Administrator') as total_admins,
                  (SELECT COUNT(*) FROM users WHERE role = 'Inventory Manager') as total_managers,
                  (SELECT COUNT(*) FROM users WHERE role = 'Bakery Staff') as total_staff,
                  (SELECT COUNT(DISTINCT DATE(timestamp)) FROM (
                    SELECT timestamp FROM admin_logs UNION SELECT timestamp FROM inventory_logs
                  ) as combined_dates) as total_days";
$stats_result = $conn->query($stats_query);
$stats = $stats_result->fetch_assoc();

// Get top actions (combined from both tables)
$top_actions_query = "SELECT action, COUNT(*) as count FROM (
                        SELECT action FROM admin_logs
                        UNION ALL
                        SELECT action FROM inventory_logs
                     ) as combined_logs 
                     GROUP BY action 
                     ORDER BY count DESC 
                     LIMIT 5";
$top_actions_result = $conn->query($top_actions_query);

// Export logs functionality - modified to include both log types
if (isset($_GET['export']) && $_GET['export'] == 'csv') {
    // Create headers for CSV
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename=combined_logs_export.csv');
    
    // Create a file pointer connected to the output stream
    $output = fopen('php://output', 'w');
    
    // Output column headings
    fputcsv($output, [
        'Log ID', 
        'Log Type',
        'User ID', 
        'User Name', 
        'Action', 
        'Affected Entity',
        'Affected Entity Name',
        'Action Details',
        'IP Address',
        'Timestamp'
    ]);
    
    // For admin logs
    if ($logTypeFilter == 'admin' || $logTypeFilter == 'all') {
        // Recreate admin logs query for export
        $export_admin_query = "SELECT 
                           l.log_id, 
                           l.admin_id AS user_id, 
                           a.fullName AS user_name,
                           l.action, 
                           l.affected_user AS affected_entity,
                           u.fullName AS affected_entity_name,
                           l.action_details,
                           l.ip_address,
                           l.timestamp
                        FROM admin_logs l
                        LEFT JOIN users a ON l.admin_id = a.userID
                        LEFT JOIN users u ON l.affected_user = u.userID
                        WHERE 1=1";
        
        // Apply filters
        if (!empty($userFilter)) {
            $export_admin_query .= " AND (l.admin_id = '$userFilter' OR l.affected_user = '$userFilter')";
        }
        
        if (!empty($actionFilter)) {
            $export_admin_query .= " AND l.action = '$actionFilter'";
        }
        
        if (!empty($dateFrom)) {
            $export_admin_query .= " AND DATE(l.timestamp) >= '$dateFrom'";
        }
        
        if (!empty($dateTo)) {
            $export_admin_query .= " AND DATE(l.timestamp) <= '$dateTo'";
        }
        
        $export_admin_result = $conn->query($export_admin_query);
        
        // Output admin log data
        while ($row = $export_admin_result->fetch_assoc()) {
            fputcsv($output, [
                $row['log_id'],
                'Admin',
                $row['user_id'],
                $row['user_name'],
                $row['action'],
                $row['affected_entity'],
                $row['affected_entity_name'],
                $row['action_details'],
                $row['ip_address'],
                $row['timestamp']
            ]);
        }
    }
    
    // For inventory logs
    if ($logTypeFilter == 'inventory' || $logTypeFilter == 'all') {
        // Recreate inventory logs query for export
        $export_inventory_query = "SELECT 
                           l.log_id, 
                           l.user_id, 
                           u.fullName AS user_name,
                           l.action, 
                           l.item_id AS affected_entity,
                           '' AS affected_entity_name,
                           l.action_details,
                           l.ip_address,
                           l.timestamp
                        FROM inventory_logs l
                        LEFT JOIN users u ON l.user_id = u.userID
                        WHERE 1=1";
        
        // Apply filters
        if (!empty($userFilter)) {
            $export_inventory_query .= " AND l.user_id = '$userFilter'";
        }
        
        if (!empty($actionFilter)) {
            $export_inventory_query .= " AND l.action = '$actionFilter'";
        }
        
        if (!empty($dateFrom)) {
            $export_inventory_query .= " AND DATE(l.timestamp) >= '$dateFrom'";
        }
        
        if (!empty($dateTo)) {
            $export_inventory_query .= " AND DATE(l.timestamp) <= '$dateTo'";
        }
        
        $export_inventory_result = $conn->query($export_inventory_query);
        
        // Output inventory log data
        while ($row = $export_inventory_result->fetch_assoc()) {
            fputcsv($output, [
                $row['log_id'],
                'Inventory',
                $row['user_id'],
                $row['user_name'],
                $row['action'],
                $row['affected_entity'],
                $row['affected_entity_name'],
                $row['action_details'],
                $row['ip_address'],
                $row['timestamp']
            ]);
        }
    }
    
    // Close the connection and exit
    $conn->close();
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Activity Logs - Roti Seri Bakery</title>
    <link rel="stylesheet" href="admin_dashboard.css">
    <link rel="stylesheet" href="sidebar.css">
    <link rel="stylesheet" href="admin_logsdisplay.css">
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
                    <span class="company-name2">Admin</span>
                </div>
            </div>

            <nav class="nav-container" role="navigation">
                <a href="admin_dashboard.php" class="nav-item">
                    <i class="fas fa-home"></i>
                    <div class="nav-text">Home</div>
                </a>
                <a href="admin_usermanagement.php" class="nav-item">
                    <i class="fa fa-user nav-icon"></i>
                    <div class="nav-text">User Management</div>
                </a>
                <a href="admin_logsdisplay.php" class="nav-item active">
                    <i class="fas fa-file-alt"></i>
                    <div class="nav-text">Logs</div>
                </a>
                <a href="admin_passmanagement.php" class="nav-item">
                    <i class="fas fa-key"></i>
                    <div class="nav-text">Password Management</div>
                </a>
                <a href="admin_profile.php" class="nav-item">
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
            <h1>System Activity Logs</h1>
            <p>Welcome, <?php echo htmlspecialchars($fullName); ?>!</p>
        </div>

        <!-- Summary Statistics -->
        <div class="stats-container">
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-file-alt"></i>
                </div>
                <div class="stat-details">
                    <h3>Total Logs</h3>
                    <p><?php echo number_format($stats['total_logs']); ?></p>
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-users-cog"></i>
                </div>
                <div class="stat-details">
                    <h3>Admins</h3>
                    <p><?php echo number_format($stats['total_admins']); ?></p>
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-user-tie"></i>
                </div>
                <div class="stat-details">
                    <h3>Managers</h3>
                    <p><?php echo number_format($stats['total_managers']); ?></p>
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-user"></i>
                </div>
                <div class="stat-details">
                    <h3>Staff</h3>
                    <p><?php echo number_format($stats['total_staff']); ?></p>
                </div>
            </div>
        </div>

        <!-- Charts Section -->
        <div class="charts-section">
            <div class="chart-container">
                <h3><i class="fas fa-chart-pie"></i> Top Actions</h3>
                <canvas id="actionsChart"></canvas>
            </div>
        </div>

        <!-- Filter Section -->
        <div class="filter-section">
            <h3><i class="fas fa-filter"></i> Filter Logs</h3>
            <form method="GET" action="admin_logsdisplay.php" id="filterForm">
                <div class="filter-row">
                    <div class="filter-group">
                        <label for="log_type">Log Type:</label>
                        <select name="log_type" id="log_type">
                            <option value="all" <?php echo ($logTypeFilter == 'all') ? 'selected' : ''; ?>>All Logs</option>
                            <option value="admin" <?php echo ($logTypeFilter == 'admin') ? 'selected' : ''; ?>>Admin Logs</option>
                            <option value="inventory" <?php echo ($logTypeFilter == 'inventory') ? 'selected' : ''; ?>>Inventory Logs</option>
                        </select>
                    </div>
                
                    <div class="filter-group">
                        <label for="user">User:</label>
                        <select name="user" id="user">
                            <option value="">All Users</option>
                            <?php while ($user = $result_users->fetch_assoc()): ?>
                                <option value="<?php echo $user['userID']; ?>" 
                                    <?php echo ($userFilter == $user['userID']) ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($user['fullName']); ?> (<?php echo $user['role']; ?>)
                                </option>
                            <?php endwhile; ?>
                        </select>
                    </div>
                    
                    <div class="filter-group">
                        <label for="action">Action:</label>
                        <select name="action" id="action">
                            <option value="">All Actions</option>
                            <?php while ($action = $result_actions->fetch_assoc()): ?>
                                <option value="<?php echo $action['action']; ?>" 
                                    <?php echo ($actionFilter == $action['action']) ? 'selected' : ''; ?>>
                                    <?php echo ucwords(str_replace('_', ' ', $action['action'])); ?>
                                </option>
                            <?php endwhile; ?>
                        </select>
                    </div>
                </div>
                
                <div class="filter-row">
                    <div class="filter-group">
                        <label for="date_from">Date From:</label>
                        <input type="date" id="date_from" name="date_from" value="<?php echo $dateFrom; ?>">
                    </div>
                    
                    <div class="filter-group">
                        <label for="date_to">Date To:</label>
                        <input type="date" id="date_to" name="date_to" value="<?php echo $dateTo; ?>">
                    </div>
                </div>
                
                <div class="filter-buttons">
                    <button type="submit" class="filter-btn apply-btn"><i class="fas fa-search"></i> Apply Filters</button>
                    <button type="button" id="resetBtn" class="filter-btn reset-btn"><i class="fas fa-sync"></i> Reset Filters</button>
                    <a href="admin_logsdisplay.php?export=csv<?php 
                        echo '&log_type=' . urlencode($logTypeFilter);
                        echo (!empty($userFilter)) ? '&user=' . urlencode($userFilter) : '';
                        echo (!empty($actionFilter)) ? '&action=' . urlencode($actionFilter) : '';
                        echo (!empty($dateFrom)) ? '&date_from=' . urlencode($dateFrom) : '';
                        echo (!empty($dateTo)) ? '&date_to=' . urlencode($dateTo) : '';
                    ?>" class="filter-btn export-btn"><i class="fas fa-download"></i> Export to CSV</a>
                </div>
            </form>
        </div>

        <!-- Logs Table -->
        <div class="logs-table-container">
            <table class="logs-table">
                <thead>
                    <tr>
                        <th>Log Type</th>
                        <th>Date & Time</th>
                        <th>User</th>
                        <th>Action</th>
                        <th>Affected Entity</th>
                        <th>Details</th>
                        <th>IP Address</th>
                    </tr>
                </thead>
                <tbody>
                    <?php 
                    // Initialize a counter for displaying rows
                    $logCount = 0;
                    $maxLogs = 1000; // Limit to prevent performance issues
                    
                    // Create a combined result set by timestamp
                    $combined_logs = [];
                    
                    // Add admin logs if applicable
                    if (isset($result_admin_logs) && $result_admin_logs->num_rows > 0) {
                        while ($log = $result_admin_logs->fetch_assoc()) {
                            $log['log_source'] = 'admin';
                            $combined_logs[] = $log;
                        }
                    }
                    
                    // Add inventory logs if applicable
                    if (isset($result_inventory_logs) && $result_inventory_logs->num_rows > 0) {
                        while ($log = $result_inventory_logs->fetch_assoc()) {
                            $log['log_source'] = 'inventory';
                            $combined_logs[] = $log;
                        }
                    }
                    
                    // Sort combined logs by timestamp (newest first)
                    usort($combined_logs, function($a, $b) {
                        return strtotime($b['timestamp']) - strtotime($a['timestamp']);
                    });
                    
                    // Display logs
                    if (count($combined_logs) > 0) {
                        foreach ($combined_logs as $log) {
                            if ($logCount < $maxLogs) {
                                if ($log['log_source'] == 'admin') {
                                    echo "<tr class='admin-log-row'>";
                                    echo "<td><span class='log-type admin'>Admin</span></td>";
                                    echo "<td>" . htmlspecialchars($log['timestamp']) . "</td>";
                                    echo "<td>" . htmlspecialchars($log['admin_name'] ?? $log['admin_id']) . "</td>";
                                    echo "<td><span class='action-badge action-" . strtolower($log['action']) . "'>" . 
                                         ucwords(str_replace('_', ' ', $log['action'])) . "</span></td>";
                                    echo "<td>" . htmlspecialchars($log['affected_user_name'] ?? $log['affected_user'] ?? 'N/A') . "</td>";
                                    echo "<td>" . htmlspecialchars($log['action_details'] ?? 'No details') . "</td>";
                                    echo "<td>" . htmlspecialchars($log['ip_address']) . "</td>";
                                    echo "</tr>";
                                } else {
                                    echo "<tr class='inventory-log-row'>";
                                    echo "<td><span class='log-type inventory'>Inventory</span></td>";
                                    echo "<td>" . htmlspecialchars($log['timestamp']) . "</td>";
                                    echo "<td>" . htmlspecialchars($log['user_name'] ?? $log['user_id']) . "</td>";
                                    echo "<td><span class='action-badge action-inventory action-" . strtolower($log['action']) . "'>" . 
                                         ucwords(str_replace('_', ' ', $log['action'])) . "</span></td>";
                                    echo "<td>" . htmlspecialchars($log['item_id'] ?? 'N/A') . "</td>";
                                    echo "<td>" . htmlspecialchars($log['action_details'] ?? 'No details') . "</td>";
                                    echo "<td>" . htmlspecialchars($log['ip_address']) . "</td>";
                                    echo "</tr>";
                                }
                                $logCount++;
                            } else {
                                break;
                            }
                        }
                    } else {
                        echo "<tr><td colspan='7' class='no-data'>No logs found matching your filter criteria</td></tr>";
                    }
                    ?>
                </tbody>
            </table>
            <?php if ($logCount >= $maxLogs): ?>
                <div class="pagination-note">Showing <?php echo $maxLogs; ?> most recent logs. Use filters to narrow results.</div>
            <?php endif; ?>
        </div>
    </div>

    <script src="admin_logsdisplay.js"></script>
    <script>
        // Data for action distribution chart
        const actionLabels = [
            <?php 
            $top_actions_result->data_seek(0);
            $labels = [];
            while ($action = $top_actions_result->fetch_assoc()) {
                $labels[] = "'" . ucwords(str_replace('_', ' ', $action['action'])) . "'";
            }
            echo implode(", ", $labels);
            ?>
        ];
        
        const actionCounts = [
            <?php 
            $top_actions_result->data_seek(0);
            $counts = [];
            while ($action = $top_actions_result->fetch_assoc()) {
                $counts[] = $action['count'];
            }
            echo implode(", ", $counts);
            ?>
        ];
        
        // Chart colors
        const chartColors = [
            '#4e73df', '#1cc88a', '#36b9cc', '#f6c23e', '#e74a3b'
        ];
    </script>
</body>
</html>
