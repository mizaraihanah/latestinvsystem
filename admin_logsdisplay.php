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

// Build the query with potential filters
$query = "SELECT l.*, 
            a.fullName AS admin_name, 
            u.fullName AS affected_user_name
          FROM admin_logs l
          LEFT JOIN users a ON l.admin_id = a.userID
          LEFT JOIN users u ON l.affected_user = u.userID
          WHERE 1=1";

$params = [];
$types = "";

if (!empty($userFilter)) {
    $query .= " AND (l.admin_id = ? OR l.affected_user = ?)";
    $params[] = $userFilter;
    $params[] = $userFilter;
    $types .= "ss";
}

if (!empty($actionFilter)) {
    $query .= " AND l.action = ?";
    $params[] = $actionFilter;
    $types .= "s";
}

if (!empty($dateFrom)) {
    $query .= " AND DATE(l.timestamp) >= ?";
    $params[] = $dateFrom;
    $types .= "s";
}

if (!empty($dateTo)) {
    $query .= " AND DATE(l.timestamp) <= ?";
    $params[] = $dateTo;
    $types .= "s";
}

$query .= " ORDER BY l.timestamp DESC";

// Prepare and execute the query
$stmt = $conn->prepare($query);
if (!empty($params)) {
    $stmt->bind_param($types, ...$params);
}
$stmt->execute();
$result_logs = $stmt->get_result();
$stmt->close();

// Get distinct actions for the filter dropdown
$action_query = "SELECT DISTINCT action FROM admin_logs ORDER BY action";
$result_actions = $conn->query($action_query);

// Get users for the filter dropdown
$user_query = "SELECT DISTINCT u.userID, u.fullName, u.role 
               FROM users u
               WHERE u.userID IN (SELECT admin_id FROM admin_logs)
               OR u.userID IN (SELECT affected_user FROM admin_logs WHERE affected_user IS NOT NULL)
               ORDER BY u.role, u.fullName";
$result_users = $conn->query($user_query);

// Get summary statistics
$stats_query = "SELECT 
                  COUNT(*) as total_logs,
                  COUNT(DISTINCT admin_id) as total_admins,
                  COUNT(DISTINCT affected_user) as total_affected_users,
                  COUNT(DISTINCT DATE(timestamp)) as total_days
                FROM admin_logs";
$stats_result = $conn->query($stats_query);
$stats = $stats_result->fetch_assoc();

// Get top actions
$top_actions_query = "SELECT action, COUNT(*) as count 
                     FROM admin_logs 
                     GROUP BY action 
                     ORDER BY count DESC 
                     LIMIT 5";
$top_actions_result = $conn->query($top_actions_query);

// Export logs functionality
if (isset($_GET['export']) && $_GET['export'] == 'csv') {
    // Create a new query with the same filters for export
    $export_query = "SELECT 
                       l.log_id, 
                       l.admin_id, 
                       a.fullName AS admin_name,
                       l.action, 
                       l.affected_user,
                       u.fullName AS affected_user_name,
                       l.action_details,
                       l.ip_address,
                       l.timestamp
                    FROM admin_logs l
                    LEFT JOIN users a ON l.admin_id = a.userID
                    LEFT JOIN users u ON l.affected_user = u.userID
                    WHERE 1=1";
    
    if (!empty($userFilter)) {
        $export_query .= " AND (l.admin_id = '$userFilter' OR l.affected_user = '$userFilter')";
    }
    
    if (!empty($actionFilter)) {
        $export_query .= " AND l.action = '$actionFilter'";
    }
    
    if (!empty($dateFrom)) {
        $export_query .= " AND DATE(l.timestamp) >= '$dateFrom'";
    }
    
    if (!empty($dateTo)) {
        $export_query .= " AND DATE(l.timestamp) <= '$dateTo'";
    }
    
    $export_query .= " ORDER BY l.timestamp DESC";
    
    $export_result = $conn->query($export_query);
    
    // Set headers for CSV download
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename=admin_logs_export.csv');
    
    // Create a file pointer connected to the output stream
    $output = fopen('php://output', 'w');
    
    // Output the column headings
    fputcsv($output, [
        'Log ID', 
        'Admin ID', 
        'Admin Name', 
        'Action', 
        'Affected User ID',
        'Affected User Name',
        'Action Details',
        'IP Address',
        'Timestamp'
    ]);
    
    // Fetch and output each row
    while ($row = $export_result->fetch_assoc()) {
        fputcsv($output, [
            $row['log_id'],
            $row['admin_id'],
            $row['admin_name'],
            $row['action'],
            $row['affected_user'],
            $row['affected_user_name'],
            $row['action_details'],
            $row['ip_address'],
            $row['timestamp']
        ]);
    }
    
    // Close the connection and exit
    $conn->close();
    exit();
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Logs - Roti Seri Bakery</title>
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
            <h1>Admin Activity Logs</h1>
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
                    <h3>Active Admins</h3>
                    <p><?php echo number_format($stats['total_admins']); ?></p>
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-user-edit"></i>
                </div>
                <div class="stat-details">
                    <h3>Affected Users</h3>
                    <p><?php echo number_format($stats['total_affected_users']); ?></p>
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">
                    <i class="fas fa-calendar-alt"></i>
                </div>
                <div class="stat-details">
                    <h3>Activity Days</h3>
                    <p><?php echo number_format($stats['total_days']); ?></p>
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
                        <label for="user">Admin/User:</label>
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
                        <th>Date & Time</th>
                        <th>Admin</th>
                        <th>Action</th>
                        <th>Affected User</th>
                        <th>Details</th>
                        <th>IP Address</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if ($result_logs->num_rows > 0): ?>
                        <?php while ($log = $result_logs->fetch_assoc()): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($log['timestamp']); ?></td>
                                <td><?php echo htmlspecialchars($log['admin_name'] ?? $log['admin_id']); ?></td>
                                <td>
                                    <span class="action-badge action-<?php echo strtolower($log['action']); ?>">
                                        <?php echo ucwords(str_replace('_', ' ', $log['action'])); ?>
                                    </span>
                                </td>
                                <td><?php echo htmlspecialchars($log['affected_user_name'] ?? $log['affected_user'] ?? 'N/A'); ?></td>
                                <td><?php echo htmlspecialchars($log['action_details'] ?? 'No details'); ?></td>
                                <td><?php echo htmlspecialchars($log['ip_address']); ?></td>
                            </tr>
                        <?php endwhile; ?>
                    <?php else: ?>
                        <tr>
                            <td colspan="6" class="no-data">No logs found matching your filter criteria</td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
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
