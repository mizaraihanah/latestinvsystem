/**
 * Handle supplier autofill functionality
 * Autofills supplier details when selecting an existing supplier
 */
// In staff_suppliers.js, modify the handleSupplierAutofill() function to add a console log
function handleSupplierAutofill() {
    const supplierNameInput = document.getElementById('supplier_name');
    const datalist = document.getElementById('existingSuppliers');
    const value = supplierNameInput.value.trim();
    
    // Check if the entered value matches any option in the datalist
    let matchFound = false;
    let matchedOption = null;
    
    // Find the matching option
    for (let i = 0; i < datalist.options.length; i++) {
        if (datalist.options[i].value === value) {
            matchFound = true;
            matchedOption = datalist.options[i];
            console.log("Found matching option:", matchedOption);
            console.log("Address attribute:", matchedOption.getAttribute('data-address'));
            break;
        }
    }
    
    if (matchFound && matchedOption) {
        // Autofill the form fields with the data attributes
        document.getElementById('contact_person').value = matchedOption.getAttribute('data-contact') || '';
        document.getElementById('email').value = matchedOption.getAttribute('data-email') || '';
        document.getElementById('phone').value = matchedOption.getAttribute('data-phone') || '';
        document.getElementById('address').value = matchedOption.getAttribute('data-address') || '';
        document.getElementById('payment_terms').value = matchedOption.getAttribute('data-terms') || '';
        document.getElementById('notes').value = matchedOption.getAttribute('data-notes') || '';
        
        // Show a toast notification
        showToast('Supplier details auto-filled. You can modify them if needed.', 'success');
        
        // Highlight the autofill indicator
        const indicator = document.querySelector('.autofill-indicator');
        if (indicator) {
            indicator.style.opacity = '1';
            indicator.style.color = '#4CAF50';
            
            // Reset after 3 seconds
            setTimeout(() => {
                indicator.style.opacity = '0.7';
                indicator.style.color = '#0561FC';
            }, 3000);
        }
    }
}

/**
 * Staff Suppliers Management JavaScript
 * Handles functionality for the supplier management interface
 */

document.addEventListener('DOMContentLoaded', function() {
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
            // Get the supplier details from the view modal
            const supplierName = document.getElementById('view_supplier_name').textContent;
            
            // Find the supplier in the table and trigger the edit button
            const supplierRows = document.querySelectorAll('.supplier-table tbody tr');
            
            supplierRows.forEach(row => {
                const rowSupplierName = row.querySelector('td:first-child').textContent;
                if (rowSupplierName === supplierName) {
                    row.querySelector('.edit-btn').click();
                }
            });
            
            closeModal('viewSupplierModal');
        });
    }
    
    // Add event listener for supplier name autofill functionality
    const supplierNameInput = document.getElementById('supplier_name');
    if (supplierNameInput) {
        supplierNameInput.addEventListener('input', handleSupplierAutofill);
    }
});

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
 * Show the Add Supplier modal
 */
function showAddModal() {
    document.getElementById('addSupplierForm').reset();
    document.getElementById('addSupplierModal').style.display = 'block';
    
    // Load existing suppliers into the datalist
    loadExistingSuppliers();
}

/**
 * Load existing suppliers into the datalist
 */
function loadExistingSuppliers() {
    const datalist = document.getElementById('existingSuppliers');
    
    // Clear existing options
    datalist.innerHTML = '';
    
    // Get suppliers from the table
    const supplierRows = document.querySelectorAll('.supplier-table tbody tr');
    
    supplierRows.forEach(row => {
        if (!row.classList.contains('no-data')) {
            const cells = row.querySelectorAll('td');
            
            // Create option element
            const option = document.createElement('option');
            option.value = cells[0].textContent; // Supplier name
            
            // Set data attributes for autofill
            option.setAttribute('data-contact', cells[1].textContent); // Contact person
            option.setAttribute('data-email', cells[2].textContent); // Email
            option.setAttribute('data-phone', cells[3].textContent); // Phone
            option.setAttribute('data-terms', cells[4].textContent); // Payment terms
            
            // Get address from the view modal when clicking the view button (simulate a click to get data)
            // This is needed because address isn't displayed in the table
            
            datalist.appendChild(option);
        }
    });
}

/**
 * Show the Edit Supplier modal with pre-filled data
 * @param {Object} supplier - The supplier data to pre-fill
 */
function showEditModal(supplier) {
    // Fill form fields with supplier data
    document.getElementById('edit_supplier_id').value = supplier.supplier_id;
    document.getElementById('edit_supplier_name').value = supplier.supplier_name;
    document.getElementById('edit_contact_person').value = supplier.contact_person || '';
    document.getElementById('edit_email').value = supplier.email || '';
    document.getElementById('edit_phone').value = supplier.phone || '';
    document.getElementById('edit_address').value = supplier.address || '';
    document.getElementById('edit_payment_terms').value = supplier.payment_terms || '';
    document.getElementById('edit_notes').value = supplier.notes || '';
    
    // Show the modal
    document.getElementById('editSupplierModal').style.display = 'block';
}

/**
 * Show the Delete Confirmation modal
 * @param {number} supplierId - The ID of the supplier to delete
 * @param {string} supplierName - The name of the supplier to delete
 */
function confirmDelete(supplierId, supplierName) {
    document.getElementById('delete_supplier_id').value = supplierId;
    document.getElementById('delete_supplier_name').textContent = supplierName;
    document.getElementById('deleteConfirmModal').style.display = 'block';
}

/**
 * View detailed information about a supplier
 * @param {Object} supplier - The supplier data to display
 */
function viewSupplierDetails(supplier) {
    // Fill the details
    document.getElementById('view_supplier_name').textContent = supplier.supplier_name;
    document.getElementById('view_contact_person').textContent = supplier.contact_person || 'Not specified';
    document.getElementById('view_email').textContent = supplier.email || 'Not specified';
    document.getElementById('view_phone').textContent = supplier.phone || 'Not specified';
    document.getElementById('view_address').textContent = supplier.address || 'Not specified';
    document.getElementById('view_payment_terms').textContent = supplier.payment_terms || 'Not specified';
    document.getElementById('view_notes').textContent = supplier.notes || 'No notes';
    document.getElementById('view_created_by').textContent = supplier.created_by || 'N/A';
    document.getElementById('view_updated_at').textContent = supplier.updated_at || 'N/A';
    
    // Show the modal
    document.getElementById('viewSupplierModal').style.display = 'block';
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

/**
 * Validate supplier form before submission
 * @param {HTMLFormElement} form - The form to validate
 * @returns {boolean} - Returns true if the form is valid
 */
function validateSupplierForm(form) {
    const supplierName = form.querySelector('[name="supplier_name"]').value.trim();
    
    if (!supplierName) {
        showToast('Supplier name is required', 'error');
        return false;
    }
    
    return true;
}

// Add form validation to the add and edit forms
document.addEventListener('DOMContentLoaded', function() {
    const addForm = document.getElementById('addSupplierForm');
    if (addForm) {
        addForm.addEventListener('submit', function(event) {
            if (!validateSupplierForm(this)) {
                event.preventDefault();
            }
        });
    }
    
    const editForm = document.getElementById('editSupplierForm');
    if (editForm) {
        editForm.addEventListener('submit', function(event) {
            if (!validateSupplierForm(this)) {
                event.preventDefault();
            }
        });
    }
});