-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: May 16, 2025 at 04:55 PM
-- Server version: 10.4.28-MariaDB
-- PHP Version: 8.0.28

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `roti_seri_bakery_inventory`
--

-- --------------------------------------------------------

--
-- Table structure for table `admin_logs`
--

CREATE TABLE `admin_logs` (
  `log_id` int(11) NOT NULL,
  `admin_id` varchar(50) NOT NULL,
  `action` varchar(50) NOT NULL,
  `affected_user` varchar(50) DEFAULT NULL,
  `action_details` text DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `timestamp` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

--
-- Dumping data for table `admin_logs`
--

INSERT INTO `admin_logs` (`log_id`, `admin_id`, `action`, `affected_user`, `action_details`, `ip_address`, `timestamp`) VALUES
(1, 'aadmin', 'password_change', 'adminex', 'Changed user password', '::1', '2025-04-18 15:31:46'),
(2, 'aadmin', 'email_fail', 'adminex', 'Failed to send password change notification', '::1', '2025-04-18 15:31:48'),
(3, 'aadmin', 'password_change', 'adminex', 'Changed user password', '::1', '2025-04-18 15:31:53'),
(4, 'aadmin', 'email_fail', 'adminex', 'Failed to send password change notification', '::1', '2025-04-18 15:31:55'),
(5, 'aadmin', 'password_change', 'adminex', 'Changed user password', '::1', '2025-04-18 15:32:04'),
(6, 'aadmin', 'email_fail', 'adminex', 'Failed to send password change notification', '::1', '2025-04-18 15:32:06'),
(7, 'aadmin', 'password_reset', 'adminex', 'Reset user password', '::1', '2025-04-18 16:00:22'),
(8, 'aadmin', 'email_fail', 'adminex', 'Failed to send password reset email', '::1', '2025-04-18 16:00:22'),
(9, 'aadmin', 'password_change', 'adminex', 'Changed user password', '::1', '2025-04-18 16:02:40'),
(10, 'aadmin', 'email_fail', 'adminex', 'Failed to send password change notification', '::1', '2025-04-18 16:02:40'),
(11, 'aadmin', 'password_change', 'adminex', 'Changed user password', '::1', '2025-04-18 18:19:27'),
(12, 'aadmin', 'email_fail', 'adminex', 'Failed to send password change notification', '::1', '2025-04-18 18:19:27'),
(15, 'aadmin', 'password_change', 'adminex', 'Changed user password', '::1', '2025-04-19 09:50:53'),
(16, 'aadmin', 'password_reset', 'yaemiko12', 'Reset user password', '::1', '2025-04-19 10:07:10'),
(17, 'aadmin', 'password_change', 'yaemiko12', 'Changed user password', '::1', '2025-04-20 06:27:03');

-- --------------------------------------------------------

--
-- Table structure for table `inventory_logs`
--

CREATE TABLE `inventory_logs` (
  `log_id` int(11) NOT NULL,
  `user_id` varchar(50) NOT NULL,
  `action` varchar(50) NOT NULL,
  `item_id` varchar(50) NOT NULL,
  `action_details` text DEFAULT NULL,
  `timestamp` datetime NOT NULL DEFAULT current_timestamp(),
  `ip_address` varchar(45) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

--
-- Dumping data for table `inventory_logs`
--

INSERT INTO `inventory_logs` (`log_id`, `user_id`, `action`, `item_id`, `action_details`, `timestamp`, `ip_address`) VALUES
(1, 'admin1', 'add_product', 'PROD0001', 'Added new product: White Bread', '2025-05-13 12:07:05', '127.0.0.1'),
(2, 'admin1', 'add_product', 'PROD0002', 'Added new product: Multigrain Bread', '2025-05-13 12:07:05', '127.0.0.1'),
(3, 'yaemiko12', 'add_product', 'PROD0006', 'Added new product: aaaaa', '2025-05-13 15:58:50', '::1'),
(4, 'yaemiko12', 'delete_product', 'PROD0004', 'Deleted product ID: PROD0004', '2025-05-13 16:05:39', '::1'),
(5, 'yaemiko12', 'delete_product', 'PROD0006', 'Deleted product ID: PROD0006', '2025-05-13 16:05:47', '::1'),
(6, 'yaemiko12', 'delete_product', 'PROD0003', 'Deleted product ID: PROD0003', '2025-05-16 00:12:13', '::1'),
(7, 'yaemiko12', 'delete_category', '2', 'Deleted category ID: 2', '2025-05-16 00:12:17', '::1'),
(8, 'yaemiko12', 'stock_update', 'PROD0001', 'Increased stock by 20 via purchase order PO000001', '2025-05-16 01:04:11', '::1'),
(9, 'yaemiko12', 'create_order', 'PO000001', 'Created new Purchase order: PO000001', '2025-05-16 01:04:11', '::1'),
(10, 'staff01', 'update_order', 'PO000001', 'Updated order status to: Completed', '2025-05-16 16:13:34', '::1'),
(11, 'staff01', 'delete_supplier', '4', 'Deleted supplier: Dairy King Enterprise', '2025-05-16 17:52:23', '::1'),
(12, 'staff01', 'update_product', 'PROD0005', 'Updated product: Chocolate Chip Cookie', '2025-05-16 19:16:15', '::1'),
(13, 'staff01', 'update_product', 'PROD0005', 'Updated product: Chocolate Chip Cookie', '2025-05-16 19:16:24', '::1'),
(14, 'staff01', 'update_product', 'PROD0002', 'Updated product: Multigrain Bread', '2025-05-16 19:25:14', '::1');

-- --------------------------------------------------------

--
-- Table structure for table `orders`
--

CREATE TABLE `orders` (
  `order_id` varchar(10) NOT NULL,
  `order_type` enum('Purchase','Sales') NOT NULL,
  `customer_name` varchar(100) DEFAULT NULL,
  `order_date` date NOT NULL,
  `status` enum('Pending','Processing','Completed','Cancelled') NOT NULL DEFAULT 'Pending',
  `total_amount` decimal(10,2) NOT NULL DEFAULT 0.00,
  `created_by` varchar(50) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `status_changed_at` datetime DEFAULT NULL COMMENT 'Timestamp when order status was last changed'
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

--
-- Dumping data for table `orders`
--

INSERT INTO `orders` (`order_id`, `order_type`, `customer_name`, `order_date`, `status`, `total_amount`, `created_by`, `created_at`, `status_changed_at`) VALUES
('PO000001', 'Purchase', 'KILANG GULA ALOR SETAR', '2025-05-15', 'Completed', 110.00, 'yaemiko12', '2025-05-16 01:04:11', NULL);

-- --------------------------------------------------------

--
-- Table structure for table `order_items`
--

CREATE TABLE `order_items` (
  `item_id` int(11) NOT NULL,
  `order_id` varchar(10) NOT NULL,
  `product_id` varchar(10) NOT NULL,
  `quantity` int(11) NOT NULL,
  `unit_price` decimal(10,2) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

--
-- Dumping data for table `order_items`
--

INSERT INTO `order_items` (`item_id`, `order_id`, `product_id`, `quantity`, `unit_price`) VALUES
(1, 'PO000001', 'PROD0001', 20, 5.50);

-- --------------------------------------------------------

--
-- Table structure for table `password_reset_requests`
--

CREATE TABLE `password_reset_requests` (
  `request_id` int(11) NOT NULL,
  `userID` varchar(50) NOT NULL,
  `request_date` datetime NOT NULL,
  `status` enum('pending','completed','rejected') NOT NULL DEFAULT 'pending',
  `completed_date` datetime DEFAULT NULL,
  `completed_by` varchar(50) DEFAULT NULL,
  `notes` text DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

--
-- Dumping data for table `password_reset_requests`
--

INSERT INTO `password_reset_requests` (`request_id`, `userID`, `request_date`, `status`, `completed_date`, `completed_by`, `notes`, `ip_address`) VALUES
(1, 'adminex', '2025-04-18 23:33:15', 'completed', '2025-04-19 00:00:22', 'aadmin', NULL, '::1'),
(2, 'adminex', '2025-04-19 00:01:26', 'pending', NULL, NULL, NULL, '::1'),
(3, 'yaemiko12', '2025-04-19 18:01:11', 'completed', '2025-04-19 18:07:10', 'aadmin', NULL, '::1');

-- --------------------------------------------------------

--
-- Table structure for table `products`
--

CREATE TABLE `products` (
  `product_id` varchar(10) NOT NULL,
  `product_name` varchar(100) NOT NULL,
  `description` text DEFAULT NULL,
  `category_id` int(11) DEFAULT NULL,
  `stock_quantity` int(11) NOT NULL DEFAULT 0,
  `reorder_threshold` int(11) NOT NULL DEFAULT 10,
  `unit_price` decimal(10,2) NOT NULL DEFAULT 0.00,
  `last_updated` datetime DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

--
-- Dumping data for table `products`
--

INSERT INTO `products` (`product_id`, `product_name`, `description`, `category_id`, `stock_quantity`, `reorder_threshold`, `unit_price`, `last_updated`) VALUES
('PROD0001', 'White Bread', 'Regular white bread loaf', 1, 70, 20, 5.50, '2025-05-16 01:04:11'),
('PROD0002', 'Multigrain Bread', 'Healthy multigrain bread', 1, 1, 15, 7.00, '2025-05-16 19:25:14'),
('PROD0005', 'Chocolate Chip Cookie', 'Classic chocolate chip cookies', 4, 20, 30, 2.50, '2025-05-16 19:16:24');

-- --------------------------------------------------------

--
-- Table structure for table `product_categories`
--

CREATE TABLE `product_categories` (
  `category_id` int(11) NOT NULL,
  `category_name` varchar(50) NOT NULL,
  `description` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

--
-- Dumping data for table `product_categories`
--

INSERT INTO `product_categories` (`category_id`, `category_name`, `description`) VALUES
(1, 'Bread', 'Various types of bread products'),
(3, 'Cake', 'Cakes for all occasions'),
(4, 'Cookie', 'Different varieties of cookies'),
(5, 'Confectionery', 'Sweets and confectionery items');

-- --------------------------------------------------------

--
-- Table structure for table `sales_data`
--

CREATE TABLE `sales_data` (
  `sale_id` int(11) NOT NULL,
  `sale_date` date NOT NULL,
  `product_id` varchar(10) NOT NULL,
  `category_id` int(11) NOT NULL,
  `quantity_sold` int(11) NOT NULL,
  `unit_price` decimal(10,2) NOT NULL,
  `total_amount` decimal(10,2) NOT NULL,
  `payment_method` enum('Cash','Card','Online') NOT NULL DEFAULT 'Cash',
  `recorded_by` varchar(50) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

--
-- Dumping data for table `sales_data`
--

INSERT INTO `sales_data` (`sale_id`, `sale_date`, `product_id`, `category_id`, `quantity_sold`, `unit_price`, `total_amount`, `payment_method`, `recorded_by`, `created_at`) VALUES
(1, '2025-05-01', 'PROD0001', 1, 12, 5.50, 66.00, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(2, '2025-05-01', 'PROD0002', 1, 8, 7.00, 56.00, 'Card', 'staff01', '2025-05-16 04:03:28'),
(3, '2025-05-01', 'PROD0005', 4, 15, 2.50, 37.50, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(4, '2025-05-02', 'PROD0001', 1, 15, 5.50, 82.50, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(5, '2025-05-02', 'PROD0002', 1, 5, 7.00, 35.00, 'Card', 'staff01', '2025-05-16 04:03:28'),
(6, '2025-05-02', 'PROD0005', 4, 10, 2.50, 25.00, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(7, '2025-05-03', 'PROD0001', 1, 20, 5.50, 110.00, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(8, '2025-05-03', 'PROD0002', 1, 12, 7.00, 84.00, 'Card', 'staff01', '2025-05-16 04:03:28'),
(9, '2025-05-03', 'PROD0005', 4, 22, 2.50, 55.00, 'Online', 'staff01', '2025-05-16 04:03:28'),
(10, '2025-05-04', 'PROD0001', 1, 18, 5.50, 99.00, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(11, '2025-05-04', 'PROD0002', 1, 9, 7.00, 63.00, 'Card', 'staff01', '2025-05-16 04:03:28'),
(12, '2025-05-04', 'PROD0005', 4, 25, 2.50, 62.50, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(13, '2025-05-05', 'PROD0001', 1, 22, 5.50, 121.00, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(14, '2025-05-05', 'PROD0002', 1, 14, 7.00, 98.00, 'Card', 'staff01', '2025-05-16 04:03:28'),
(15, '2025-05-05', 'PROD0005', 4, 18, 2.50, 45.00, 'Online', 'staff01', '2025-05-16 04:03:28'),
(16, '2025-05-06', 'PROD0001', 1, 16, 5.50, 88.00, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(17, '2025-05-06', 'PROD0002', 1, 10, 7.00, 70.00, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(18, '2025-05-06', 'PROD0005', 4, 20, 2.50, 50.00, 'Card', 'staff01', '2025-05-16 04:03:28'),
(19, '2025-05-07', 'PROD0001', 1, 25, 5.50, 137.50, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(20, '2025-05-07', 'PROD0002', 1, 15, 7.00, 105.00, 'Online', 'staff01', '2025-05-16 04:03:28'),
(21, '2025-05-07', 'PROD0005', 4, 30, 2.50, 75.00, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(22, '2025-05-08', 'PROD0001', 1, 20, 5.50, 110.00, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(23, '2025-05-08', 'PROD0002', 1, 12, 7.00, 84.00, 'Card', 'staff01', '2025-05-16 04:03:28'),
(24, '2025-05-08', 'PROD0005', 4, 25, 2.50, 62.50, 'Online', 'staff01', '2025-05-16 04:03:28'),
(25, '2025-05-09', 'PROD0001', 1, 22, 5.50, 121.00, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(26, '2025-05-09', 'PROD0002', 1, 18, 7.00, 126.00, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(27, '2025-05-09', 'PROD0005', 4, 15, 2.50, 37.50, 'Card', 'staff01', '2025-05-16 04:03:28'),
(28, '2025-05-10', 'PROD0001', 1, 28, 5.50, 154.00, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(29, '2025-05-10', 'PROD0002', 1, 20, 7.00, 140.00, 'Online', 'staff01', '2025-05-16 04:03:28'),
(30, '2025-05-10', 'PROD0005', 4, 35, 2.50, 87.50, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(31, '2025-05-11', 'PROD0001', 1, 14, 5.50, 77.00, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(32, '2025-05-11', 'PROD0002', 1, 11, 7.00, 77.00, 'Card', 'staff01', '2025-05-16 04:03:28'),
(33, '2025-05-11', 'PROD0005', 4, 17, 2.50, 42.50, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(34, '2025-05-12', 'PROD0001', 1, 16, 5.50, 88.00, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(35, '2025-05-12', 'PROD0002', 1, 9, 7.00, 63.00, 'Online', 'staff01', '2025-05-16 04:03:28'),
(36, '2025-05-12', 'PROD0005', 4, 20, 2.50, 50.00, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(37, '2025-05-13', 'PROD0001', 1, 18, 5.50, 99.00, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(38, '2025-05-13', 'PROD0002', 1, 15, 7.00, 105.00, 'Card', 'staff01', '2025-05-16 04:03:28'),
(39, '2025-05-13', 'PROD0005', 4, 25, 2.50, 62.50, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(40, '2025-05-14', 'PROD0001', 1, 24, 5.50, 132.00, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(41, '2025-05-14', 'PROD0002', 1, 13, 7.00, 91.00, 'Online', 'staff01', '2025-05-16 04:03:28'),
(42, '2025-05-14', 'PROD0005', 4, 28, 2.50, 70.00, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(43, '2025-05-15', 'PROD0001', 1, 21, 5.50, 115.50, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(44, '2025-05-15', 'PROD0002', 1, 19, 7.00, 133.00, 'Card', 'staff01', '2025-05-16 04:03:28'),
(45, '2025-05-15', 'PROD0005', 4, 32, 2.50, 80.00, 'Online', 'staff01', '2025-05-16 04:03:28'),
(46, '2025-05-16', 'PROD0001', 1, 26, 5.50, 143.00, 'Cash', 'staff01', '2025-05-16 04:03:28'),
(47, '2025-05-16', 'PROD0002', 1, 17, 7.00, 119.00, 'Card', 'staff01', '2025-05-16 04:03:28'),
(48, '2025-05-16', 'PROD0005', 4, 22, 2.50, 55.00, 'Cash', 'staff01', '2025-05-16 04:03:28');

-- --------------------------------------------------------

--
-- Stand-in structure for view `sales_report_view`
-- (See below for the actual view)
--
CREATE TABLE `sales_report_view` (
`sale_id` int(11)
,`sale_date` date
,`product_id` varchar(10)
,`product_name` varchar(100)
,`category_id` int(11)
,`category_name` varchar(50)
,`quantity_sold` int(11)
,`unit_price` decimal(10,2)
,`total_amount` decimal(10,2)
,`payment_method` enum('Cash','Card','Online')
,`recorded_by` varchar(50)
,`recorded_by_name` varchar(255)
,`created_at` timestamp
);

-- --------------------------------------------------------

--
-- Table structure for table `staff_notifications`
--

CREATE TABLE `staff_notifications` (
  `notification_id` int(11) NOT NULL,
  `user_id` varchar(50) NOT NULL,
  `type` enum('low_stock','out_of_stock','order_status') NOT NULL,
  `message` text NOT NULL,
  `item_id` varchar(50) NOT NULL,
  `is_read` tinyint(1) NOT NULL DEFAULT 0,
  `created_at` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- --------------------------------------------------------

--
-- Table structure for table `suppliers`
--

CREATE TABLE `suppliers` (
  `supplier_id` int(11) NOT NULL,
  `supplier_name` varchar(100) NOT NULL,
  `contact_person` varchar(100) DEFAULT NULL,
  `email` varchar(100) DEFAULT NULL,
  `phone` varchar(20) DEFAULT NULL,
  `address` text DEFAULT NULL,
  `payment_terms` varchar(100) DEFAULT NULL,
  `notes` text DEFAULT NULL,
  `created_by` varchar(50) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

--
-- Dumping data for table `suppliers`
--

INSERT INTO `suppliers` (`supplier_id`, `supplier_name`, `contact_person`, `email`, `phone`, `address`, `payment_terms`, `notes`, `created_by`, `created_at`, `updated_at`) VALUES
(1, 'Flour Mills Sdn Bhd', 'Ahmad Karim', 'ahmad@flourmills.com', '0123456789', '123 Jalan Industri, Kuala Lumpur', 'Net 30', 'Primary supplier for all flour products', 'staff01', '2025-05-16 09:48:41', '2025-05-16 09:48:41'),
(2, 'Sugar Express', 'Lisa Wong', 'orders@sugarexpress.my', '0198765432', '45 Jalan Sultan, Petaling Jaya', 'COD', 'Delivers every Monday and Thursday', 'staff01', '2025-05-16 09:48:41', '2025-05-16 09:48:41'),
(3, 'FreshEgg Farm', 'John Tan', 'sales@freshegg.com', '0134567890', '78 Jalan Kebun, Shah Alam', 'Net 15', 'Organic eggs supplier', 'staff01', '2025-05-16 09:48:41', '2025-05-16 09:48:41');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `userID` varchar(50) NOT NULL,
  `username` varchar(100) NOT NULL,
  `fullName` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `phoneNumber` varchar(20) NOT NULL,
  `address` text NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` enum('Administrator','Inventory Manager','Bakery Staff') NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`userID`, `username`, `fullName`, `email`, `phoneNumber`, `address`, `password`, `role`, `created_at`) VALUES
('aadmin', 'aadmin', 'aria', 'aria@gmail.com', '0123456781', 'awan', '$2y$10$pABhRo0syw61ssRtejS8Ae1aCBHwQSOgQ5UZEIYqZIdsP3wRPuw0q', 'Administrator', '2025-04-12 18:14:17'),
('admin1', 'admin1', 'Hana', 'hana@gmail.com', '01976545678', 'Tawau, Sabah', '$2y$10$Rna7JJL8E94J/Yv6n4JCaORFTk4IufUVCL0U3XAjJ.tRp8H2ZurLa', 'Inventory Manager', '2025-03-24 18:26:42'),
('adminex', 'adminex', 'ADMINEX', 'chimhoneybee@gmail.com', '0135685063', 'TAWAU', '$2y$10$VdUD2sodC35vAN4VCwm.2.Ok98MU714.r6WP5zgRak0Dl0bfeD7OK', 'Administrator', '2025-04-18 15:30:20'),
('adminTest', 'adminTest', 'Admin Test', 'admin@test.com', '0123456789', 'Test Address', '$2y$10$txGCdV4DtFaAH2MO4upBb.t7GfILBn0ctjVWJvmDakONoP/uKCaa2', 'Administrator', '2025-03-25 06:22:04'),
('manager01', 'manager01', 'MANAGER', 'manager@gmail.com', '0156789234', 'Perak', '$2y$10$oAnTLr7.au7bBu4F8eujtuZH3BNl9KTyzyNJnhw63YS/x9sCYKHdW', 'Inventory Manager', '2025-04-13 17:36:10'),
('staff001', 'staff1', 'twinklebaee', 'hafi@gmail.com', '1234567890', 'dd', '$2y$10$9uuJ3NvCp0blEgaEVRMXNuylGP60gaHPADvZTzOUNylJCttfEgfRq', 'Inventory Manager', '2025-04-12 18:32:19'),
('staff01', 'staff01', 'staff', 'mizfansyafie@gmail.com', '0198048301', 'KUBANG PASU', '$2y$10$gga7OddidAqo6of0NkYC5.hKij/r6h5KffKWTvvCT9UWHqInNnJJW', 'Bakery Staff', '2025-04-22 05:23:37'),
('yaemiko12', 'yaemiko12', 'yae miko', 'mikomae82@gmail.com', '0198011207', 'tawau', '$2y$10$M86bWJJwiRyumKf4.H.L7.eiUL/6qz0wkxpTXtCVsR5DKyR3mMWRS', 'Inventory Manager', '2025-04-19 09:58:32');

-- --------------------------------------------------------

--
-- Structure for view `sales_report_view`
--
DROP TABLE IF EXISTS `sales_report_view`;

CREATE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `sales_report_view`  AS SELECT `s`.`sale_id` AS `sale_id`, `s`.`sale_date` AS `sale_date`, `s`.`product_id` AS `product_id`, `p`.`product_name` AS `product_name`, `c`.`category_id` AS `category_id`, `c`.`category_name` AS `category_name`, `s`.`quantity_sold` AS `quantity_sold`, `s`.`unit_price` AS `unit_price`, `s`.`total_amount` AS `total_amount`, `s`.`payment_method` AS `payment_method`, `s`.`recorded_by` AS `recorded_by`, `u`.`fullName` AS `recorded_by_name`, `s`.`created_at` AS `created_at` FROM (((`sales_data` `s` join `products` `p` on(`s`.`product_id` = `p`.`product_id`)) join `product_categories` `c` on(`s`.`category_id` = `c`.`category_id`)) left join `users` `u` on(`s`.`recorded_by` = `u`.`userID`)) ORDER BY `s`.`sale_date` DESC, `s`.`sale_id` DESC ;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `admin_logs`
--
ALTER TABLE `admin_logs`
  ADD PRIMARY KEY (`log_id`),
  ADD KEY `admin_id` (`admin_id`),
  ADD KEY `affected_user` (`affected_user`);

--
-- Indexes for table `inventory_logs`
--
ALTER TABLE `inventory_logs`
  ADD PRIMARY KEY (`log_id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `orders`
--
ALTER TABLE `orders`
  ADD PRIMARY KEY (`order_id`),
  ADD KEY `created_by` (`created_by`);

--
-- Indexes for table `order_items`
--
ALTER TABLE `order_items`
  ADD PRIMARY KEY (`item_id`),
  ADD KEY `order_id` (`order_id`),
  ADD KEY `product_id` (`product_id`);

--
-- Indexes for table `password_reset_requests`
--
ALTER TABLE `password_reset_requests`
  ADD PRIMARY KEY (`request_id`),
  ADD KEY `userID` (`userID`);

--
-- Indexes for table `products`
--
ALTER TABLE `products`
  ADD PRIMARY KEY (`product_id`),
  ADD KEY `category_id` (`category_id`);

--
-- Indexes for table `product_categories`
--
ALTER TABLE `product_categories`
  ADD PRIMARY KEY (`category_id`),
  ADD UNIQUE KEY `category_name` (`category_name`);

--
-- Indexes for table `sales_data`
--
ALTER TABLE `sales_data`
  ADD PRIMARY KEY (`sale_id`),
  ADD KEY `product_id` (`product_id`),
  ADD KEY `category_id` (`category_id`),
  ADD KEY `recorded_by` (`recorded_by`),
  ADD KEY `sale_date` (`sale_date`);

--
-- Indexes for table `staff_notifications`
--
ALTER TABLE `staff_notifications`
  ADD PRIMARY KEY (`notification_id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `suppliers`
--
ALTER TABLE `suppliers`
  ADD PRIMARY KEY (`supplier_id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`userID`),
  ADD UNIQUE KEY `email` (`email`),
  ADD UNIQUE KEY `phoneNumber` (`phoneNumber`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `admin_logs`
--
ALTER TABLE `admin_logs`
  MODIFY `log_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=18;

--
-- AUTO_INCREMENT for table `inventory_logs`
--
ALTER TABLE `inventory_logs`
  MODIFY `log_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=15;

--
-- AUTO_INCREMENT for table `order_items`
--
ALTER TABLE `order_items`
  MODIFY `item_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `password_reset_requests`
--
ALTER TABLE `password_reset_requests`
  MODIFY `request_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `product_categories`
--
ALTER TABLE `product_categories`
  MODIFY `category_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT for table `sales_data`
--
ALTER TABLE `sales_data`
  MODIFY `sale_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=49;

--
-- AUTO_INCREMENT for table `staff_notifications`
--
ALTER TABLE `staff_notifications`
  MODIFY `notification_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `suppliers`
--
ALTER TABLE `suppliers`
  MODIFY `supplier_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `admin_logs`
--
ALTER TABLE `admin_logs`
  ADD CONSTRAINT `admin_logs_ibfk_1` FOREIGN KEY (`admin_id`) REFERENCES `users` (`userID`) ON DELETE CASCADE,
  ADD CONSTRAINT `admin_logs_ibfk_2` FOREIGN KEY (`affected_user`) REFERENCES `users` (`userID`) ON DELETE SET NULL;

--
-- Constraints for table `inventory_logs`
--
ALTER TABLE `inventory_logs`
  ADD CONSTRAINT `inventory_logs_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`userID`) ON DELETE CASCADE;

--
-- Constraints for table `orders`
--
ALTER TABLE `orders`
  ADD CONSTRAINT `orders_ibfk_1` FOREIGN KEY (`created_by`) REFERENCES `users` (`userID`) ON DELETE SET NULL;

--
-- Constraints for table `order_items`
--
ALTER TABLE `order_items`
  ADD CONSTRAINT `order_items_ibfk_1` FOREIGN KEY (`order_id`) REFERENCES `orders` (`order_id`) ON DELETE CASCADE,
  ADD CONSTRAINT `order_items_ibfk_2` FOREIGN KEY (`product_id`) REFERENCES `products` (`product_id`) ON DELETE CASCADE;

--
-- Constraints for table `password_reset_requests`
--
ALTER TABLE `password_reset_requests`
  ADD CONSTRAINT `password_reset_requests_ibfk_1` FOREIGN KEY (`userID`) REFERENCES `users` (`userID`) ON DELETE CASCADE;

--
-- Constraints for table `products`
--
ALTER TABLE `products`
  ADD CONSTRAINT `products_ibfk_1` FOREIGN KEY (`category_id`) REFERENCES `product_categories` (`category_id`) ON DELETE SET NULL ON UPDATE CASCADE;

--
-- Constraints for table `sales_data`
--
ALTER TABLE `sales_data`
  ADD CONSTRAINT `sales_data_ibfk_1` FOREIGN KEY (`product_id`) REFERENCES `products` (`product_id`) ON DELETE CASCADE,
  ADD CONSTRAINT `sales_data_ibfk_2` FOREIGN KEY (`category_id`) REFERENCES `product_categories` (`category_id`) ON DELETE CASCADE,
  ADD CONSTRAINT `sales_data_ibfk_3` FOREIGN KEY (`recorded_by`) REFERENCES `users` (`userID`) ON DELETE SET NULL;

--
-- Constraints for table `staff_notifications`
--
ALTER TABLE `staff_notifications`
  ADD CONSTRAINT `staff_notifications_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`userID`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
