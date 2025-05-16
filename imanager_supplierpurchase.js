/**
 * imanager_supplierpurchase.js
 * JavaScript functionality for the supplier purchases view
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize event listeners
    initEventListeners();
});

/**
 * Initialize all event listeners for the page
 */
function initEventListeners() {
    // Reset filters button
    const resetFiltersBtn = document.getElementById('resetFilters');
    if (resetFiltersBtn) {
        resetFiltersBtn.addEventListener('click', resetFilters);
    }

    // Export buttons
    const exportPDFBtn = document.getElementById('exportPDF');
    if (exportPDFBtn) {
        exportPDFBtn.addEventListener('click', exportPDF);
    }

    const exportExcelBtn = document.getElementById('exportExcel');
    if (exportExcelBtn) {
        exportExcelBtn.addEventListener('click', exportExcel);
    }

    // Modal close button
    const closeModalBtn = document.querySelector('.close-modal');
    if (closeModalBtn) {
        closeModalBtn.addEventListener('click', closeModal);
    }

    // Close modal when clicking outside of it
    window.addEventListener('click', function(event) {
        const modal = document.getElementById('purchaseDetailsModal');
        if (event.target === modal) {
            closeModal();
        }
    });

    // Close modal with Escape key
    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape') {
            closeModal();
        }
    });
}

/**
 * Reset all filter fields and submit the form
 */
function resetFilters() {
    document.getElementById('supplier').value = '';
    document.getElementById('date_from').value = '';
    document.getElementById('date_to').value = '';
    document.getElementById('status').value = '';
    
    // Submit the form to refresh with default values
    document.getElementById('filterForm').submit();
}

/**
 * Export purchases data as PDF
 */
function exportPDF() {
    // Get current filter values
    const supplier = document.getElementById('supplier').value;
    const dateFrom = document.getElementById('date_from').value;
    const dateTo = document.getElementById('date_to').value;
    const status = document.getElementById('status').value;
    
    // Build query string for filters
    let queryString = '?format=pdf';
    if (supplier) queryString += `&supplier=${encodeURIComponent(supplier)}`;
    if (dateFrom) queryString += `&date_from=${encodeURIComponent(dateFrom)}`;
    if (dateTo) queryString += `&date_to=${encodeURIComponent(dateTo)}`;
    if (status) queryString += `&status=${encodeURIComponent(status)}`;
    
    // Open in new window
    window.open(`export_purchases.php${queryString}`, '_blank');
    
    // Show success toast
    showToast('PDF export started. Your download will begin shortly.', 'success');
}

/**
 * Export purchases data as Excel
 */
function exportExcel() {
    // Get current filter values
    const supplier = document.getElementById('supplier').value;
    const dateFrom = document.getElementById('date_from').value;
    const dateTo = document.getElementById('date_to').value;
    const status = document.getElementById('status').value;
    
    // Build query string for filters
    let queryString = '?format=excel';
    if (supplier) queryString += `&supplier=${encodeURIComponent(supplier)}`;
    if (dateFrom) queryString += `&date_from=${encodeURIComponent(dateFrom)}`;
    if (dateTo) queryString += `&date_to=${encodeURIComponent(dateTo)}`;
    if (status) queryString += `&status=${encodeURIComponent(status)}`;
    
    // Open in new window
    window.open(`export_purchases.php${queryString}`, '_blank');
    
    // Show success toast
    showToast('Excel export started. Your download will begin shortly.', 'success');
}

/**
 * View purchase order details in modal
 * @param {string} orderId - The ID of the order to view
 */
function viewPurchaseDetails(orderId) {
    // Show loading state
    const contentContainer = document.getElementById('purchaseDetailsContent');
    contentContainer.innerHTML = '<div style="text-align: center; padding: 20px;"><i class="fas fa-spinner fa-spin" style="font-size: 24px;"></i><p>Loading order details...</p></div>';
    
    // Show the modal
    document.getElementById('purchaseDetailsModal').style.display = 'block';
    
    // Fetch order details
    fetch(`get_purchase_details.php?id=${encodeURIComponent(orderId)}`)
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
            
            // Calculate total
            let total = 0;
            data.items.forEach(item => {
                total += (item.quantity * item.unit_price);
            });
            
            // Build HTML for the modal content
            let html = `
                <div class="purchase-details-header">
                    <div class="details-column">
                        <div class="detail-item">
                            <span class="detail-label">Order ID</span>
                            <span class="detail-value">${data.order.order_id}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Supplier</span>
                            <span class="detail-value">${data.order.customer_name}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Order Date</span>
                            <span class="detail-value">${formattedDate}</span>
                        </div>
                    </div>
                    <div class="details-column">
                        <div class="detail-item">
                            <span class="detail-label">Status</span>
                            <span class="detail-value">
                                <span class="status-badge status-${data.order.status.toLowerCase()}">${data.order.status}</span>
                            </span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Created By</span>
                            <span class="detail-value">${data.order.created_by_name || data.order.created_by}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Created On</span>
                            <span class="detail-value">${new Date(data.order.created_at).toLocaleString()}</span>
                        </div>
                    </div>
                </div>
                
                <h3>Order Items</h3>
                <div class="table-responsive">
                    <table class="purchase-items-table">
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
            if (data.items.length > 0) {
                data.items.forEach(item => {
                    const subtotal = item.quantity * item.unit_price;
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
                html += '<tr><td colspan="5" class="no-records">No items found for this order</td></tr>';
            }
            
            html += `
                        </tbody>
                    </table>
                </div>
                
                <div class="purchase-total">
                    Total: RM ${total.toFixed(2)}
                </div>
                
                <div class="purchase-actions">
                    <button class="print-action-btn" onclick="printPurchaseOrder('${data.order.order_id}')">
                        <i class="fas fa-print"></i> Print Order
                    </button>
                    <button class="close-btn" onclick="closeModal()">
                        <i class="fas fa-times"></i> Close
                    </button>
                </div>
            `;
            
            contentContainer.innerHTML = html;
        })
        .catch(error => {
            console.error('Error fetching order details:', error);
            contentContainer.innerHTML = `
                <div style="text-align: center; padding: 20px; color: #f44336;">
                    <i class="fas fa-exclamation-circle" style="font-size: 24px;"></i>
                    <p>Error loading order details. Please try again later.</p>
                </div>
                <div class="purchase-actions">
                    <button class="close-btn" onclick="closeModal()">
                        <i class="fas fa-times"></i> Close
                    </button>
                </div>
            `;
            showToast('Failed to load order details.', 'error');
        });
}

/**
 * Close the purchase details modal
 */
function closeModal() {
    document.getElementById('purchaseDetailsModal').style.display = 'none';
}

/**
 * Print purchase order
 * @param {string} orderId - The ID of the order to print
 */
function printPurchaseOrder(orderId) {
    window.open(`print_purchase.php?id=${encodeURIComponent(orderId)}`, '_blank');
}

/**
 * Show a toast notification
 * @param {string} message - Message to display
 * @param {string} type - 'success' or 'error'
 */
function showToast(message, type = 'success') {
    // Remove existing toast if any
    const existingToast = document.querySelector('.toast');
    if (existingToast) {
        existingToast.remove();
    }
    
    // Create new toast
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icon = type === 'success' ? 'check-circle' : 'exclamation-circle';
    toast.innerHTML = `<i class="fas fa-${icon}"></i> ${message}`;
    
    // Add to body
    document.body.appendChild(toast);
    
    // Show toast
    setTimeout(() => {
        toast.classList.add('show');
    }, 10);
    
    // Hide toast after 3 seconds
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => {
            toast.remove();
        }, 300);
    }, 3000);
}