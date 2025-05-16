/**
 * Staff Manage Inventory JavaScript
 * Handles functionality for the inventory management interface
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize notification dropdown
    initNotifications();
    
    // Close modals when clicking outside content
    window.addEventListener('click', function(event) {
        if (event.target.classList.contains('modal')) {
            closeAllModals();
        }
    });
    
    // Close modals with Escape key
    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape') {
            closeAllModals();
        }
    });
    
    // Add event listener to edit button in view details modal
    const viewEditBtn = document.getElementById('view_edit_btn');
    if (viewEditBtn) {
        viewEditBtn.addEventListener('click', function() {
            const productId = document.getElementById('view_product_id').textContent;
            // Find the product data from the page
            const productRows = document.querySelectorAll('.inventory-table tbody tr');
            
            productRows.forEach(row => {
                const rowProductId = row.querySelector('td:first-child').textContent;
                if (rowProductId === productId) {
                    // Trigger the edit button click for this row
                    row.querySelector('.edit-btn').click();
                }
            });
            
            closeModal('viewItemModal');
        });
    }
    
    // Add event listener to status update button in view order modal
    const updateStatusBtn = document.getElementById('updateStatusBtn');
    if (updateStatusBtn) {
        updateStatusBtn.addEventListener('click', function() {
            const orderId = document.getElementById('view_order_id').textContent;
            const currentStatus = document.getElementById('view_order_status').textContent;
            
            showUpdateStatusModal(orderId, currentStatus);
            closeModal('viewOrderModal');
        });
    }
});

/**
 * Initialize notification dropdown functionality
 */
function initNotifications() {
    const bell = document.querySelector('.notification-bell');
    if (bell) {
        bell.addEventListener('click', function(e) {
            e.stopPropagation();
            const dropdown = document.getElementById('notificationDropdown');
            dropdown.classList.toggle('show');
        });
        
        // Close dropdown when clicking outside
        document.addEventListener('click', function() {
            const dropdown = document.getElementById('notificationDropdown');
            if (dropdown && dropdown.classList.contains('show')) {
                dropdown.classList.remove('show');
            }
        });
        
        // Prevent clicks inside dropdown from closing it
        const dropdown = document.getElementById('notificationDropdown');
        if (dropdown) {
            dropdown.addEventListener('click', function(e) {
                e.stopPropagation();
            });
        }
    }
}

/**
 * Toggle the notification dropdown
 */
function toggleNotifications() {
    const dropdown = document.getElementById('notificationDropdown');
    dropdown.classList.toggle('show');
}

/**
 * Close a specific modal by ID
 * @param {string} modalId - The ID of the modal to close
 */
function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.style.display = 'none';
    }
}

/**
 * Close all open modals
 */
function closeAllModals() {
    const modals = document.querySelectorAll('.modal');
    modals.forEach(modal => {
        modal.style.display = 'none';
    });
}

/**
 * Show the Add Item modal
 */
function showAddModal() {
    document.getElementById('addItemForm').reset();
    document.getElementById('addItemModal').style.display = 'block';
}

/**
 * Show the Edit Item modal with pre-filled data
 * @param {Object} product - The product data to pre-fill
 */
function showEditModal(product) {
    // Fill form fields with product data
    document.getElementById('edit_product_id').value = product.product_id;
    document.getElementById('edit_product_name').value = product.product_name;
    document.getElementById('edit_product_description').value = product.description || '';
    document.getElementById('edit_category_id').value = product.category_id;
    document.getElementById('edit_stock_quantity').value = product.stock_quantity;
    document.getElementById('edit_reorder_threshold').value = product.reorder_threshold;
    document.getElementById('edit_unit_price').value = parseFloat(product.unit_price).toFixed(2);
    
    // Show the modal
    document.getElementById('editItemModal').style.display = 'block';
}

/**
 * Show the Delete Confirmation modal
 * @param {string} productId - The ID of the product to delete
 * @param {string} productName - The name of the product to delete
 */
function confirmDelete(productId, productName) {
    document.getElementById('delete_product_id').value = productId;
    document.getElementById('delete_item_name').textContent = productName;
    document.getElementById('deleteConfirmModal').style.display = 'block';
}

/**
 * View detailed information about an inventory item
 * @param {string} productJson - JSON string of product data
 */
function viewItemDetails(productJson) {
    const product = JSON.parse(productJson);
    
    // Fill the details
    document.getElementById('view_product_id').textContent = product.product_id;
    document.getElementById('view_product_name').textContent = product.product_name;
    document.getElementById('view_product_description').textContent = product.description || 'No description available';
    document.getElementById('view_category_name').textContent = product.category_name;
    document.getElementById('view_stock_quantity').textContent = product.stock_quantity;
    document.getElementById('view_reorder_threshold').textContent = product.reorder_threshold;
    document.getElementById('view_unit_price').textContent = `RM ${parseFloat(product.unit_price).toFixed(2)}`;
    document.getElementById('view_last_updated').textContent = product.last_updated;
    
    // Set status
    let statusText = 'Normal';
    let statusClass = 'normal';
    if (product.stock_quantity === 0) {
        statusText = 'Out of Stock';
        statusClass = 'out';
    } else if (product.stock_quantity <= product.reorder_threshold) {
        statusText = 'Low Stock';
        statusClass = 'low';
    }
    
    const statusElement = document.getElementById('view_status');
    statusElement.textContent = statusText;
    statusElement.className = `detail-value status ${statusClass}`;
    
    // Show the modal
    document.getElementById('viewItemModal').style.display = 'block';
    
    // If this is a low stock or out of stock item, show a notification
    if (statusClass !== 'normal') {
        const message = statusClass === 'out' ? 
            `This item is out of stock. Consider placing a purchase order soon.` : 
            `This item has low stock (${product.stock_quantity}/${product.reorder_threshold}). Consider restocking.`;
        
        showToast(message, 'warning');
    }
}

/**
 * Show the Update Order Status modal
 * @param {string} orderId - The ID of the order
 * @param {string} currentStatus - The current status of the order
 */
function showUpdateStatusModal(orderId, currentStatus) {
    document.getElementById('update_order_id').value = orderId;
    document.getElementById('order_status').value = currentStatus;
    document.getElementById('updateOrderStatusModal').style.display = 'block';
}

/**
 * View order details in the modal
 * @param {string} orderId - The ID of the order to view
 */
function viewOrderDetails(orderId) {
    // Show loading state
    const orderDetailsContainer = document.getElementById('orderDetailsContainer');
    orderDetailsContainer.innerHTML = '<div class="loading-spinner"><div class="spinner"></div></div>';
    
    // Show the modal first
    document.getElementById('viewOrderModal').style.display = 'block';
    
    // Fetch order details using AJAX
    fetch(`get_order_details.php?id=${orderId}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            // Format the order date
            const orderDate = new Date(data.order.order_date);
            const formattedDate = orderDate.toLocaleDateString('en-MY', {
                year: 'numeric',
                month: 'long',
                day: 'numeric'
            });
            
            // Fill order header details
            document.getElementById('view_order_id').textContent = data.order.order_id;
            document.getElementById('view_order_type').textContent = data.order.order_type;
            document.getElementById('view_customer_name').textContent = data.order.customer_name;
            document.getElementById('view_order_date').textContent = formattedDate;
            document.getElementById('view_order_status').textContent = data.order.status;
            document.getElementById('view_created_by').textContent = data.order.created_by_name || data.order.created_by;
            document.getElementById('view_total_amount').textContent = parseFloat(data.order.total_amount).toFixed(2);
            
            // Build order items table
            const tableBody = document.getElementById('orderItemsTable');
            tableBody.innerHTML = '';
            
            if (data.items && data.items.length > 0) {
                data.items.forEach(item => {
                    const subtotal = item.quantity * item.unit_price;
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${item.product_id}</td>
                        <td>${item.product_name}</td>
                        <td>${item.quantity}</td>
                        <td>RM ${parseFloat(item.unit_price).toFixed(2)}</td>
                        <td>RM ${subtotal.toFixed(2)}</td>
                    `;
                    tableBody.appendChild(row);
                });
            } else {
                tableBody.innerHTML = '<tr><td colspan="5" class="no-data">No items found for this order</td></tr>';
            }
            
            // Style the status
            const statusElement = document.getElementById('view_order_status');
            statusElement.className = `status ${data.order.status.toLowerCase()}`;
        })
        .catch(error => {
            console.error('Error fetching order details:', error);
            orderDetailsContainer.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-circle"></i>
                    Error loading order details. Please try again later.
                </div>
                <div class="modal-footer">
                    <button type="button" class="close-btn" onclick="closeModal('viewOrderModal')">Close</button>
                </div>
            `;
        });
}

/**
 * Show a toast notification
 * @param {string} message - Message to display
 * @param {string} type - Type of notification (success or error)
 */
function showToast(message, type = 'success') {
    // Check if a toast already exists and remove it
    const existingToast = document.querySelector('.toast-notification');
    if (existingToast) {
        existingToast.remove();
    }
    
    // Create the toast element
    const toast = document.createElement('div');
    toast.className = `toast-notification ${type}`;
    
    const icon = type === 'success' ? 'check-circle' : 'exclamation-circle';
    toast.innerHTML = `
        <i class="fas fa-${icon}"></i>
        <span>${message}</span>
        <button class="toast-close" onclick="this.parentElement.remove();">&times;</button>
    `;
    
    // Add to the document
    document.body.appendChild(toast);
    
    // Show toast
    setTimeout(() => {
        toast.classList.add('show');
    }, 10);
    
    // Hide toast after 5 seconds
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => {
            toast.remove();
        }, 300);
    }, 5000);
}