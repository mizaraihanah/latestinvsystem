/* Create staff_alerts.js */

document.addEventListener('DOMContentLoaded', function() {
    // Mark individual notifications as read when clicked
    document.querySelectorAll('.notification-item').forEach(item => {
        if (item.classList.contains('unread')) {
            item.addEventListener('click', function() {
                markNotificationRead(this);
            });
        }
    });
    
    // Function to mark a notification as read
    function markNotificationRead(notificationElement) {
        if (notificationElement.classList.contains('unread')) {
            notificationElement.classList.remove('unread');
            
            // Get notification ID from data attribute
            const notificationId = notificationElement.dataset.id;
            
            // Send AJAX request to mark as read
            if (notificationId) {
                fetch('mark_notification_read.php?id=' + notificationId)
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            updateNotificationCounter();
                        }
                    })
                    .catch(error => {
                        console.error('Error marking notification as read:', error);
                    });
            }
        }
    }
    
    // Function to update the notification counter in the sidebar
    function updateNotificationCounter() {
        const badge = document.querySelector('.sidebar-nav .badge');
        if (badge) {
            let count = parseInt(badge.textContent) - 1;
            if (count <= 0) {
                badge.style.display = 'none';
            } else {
                badge.textContent = count;
            }
        }
    }
    
    // Show toast for unread notifications
    function showToast(message, type = 'info') {
        // Check if a toast already exists and remove it
        const existingToast = document.querySelector('.toast-notification');
        if (existingToast) {
            existingToast.remove();
        }
        
        // Create the toast element
        const toast = document.createElement('div');
        toast.className = `toast-notification ${type}`;
        
        // Set icon based on notification type
        let icon = 'info-circle';
        if (type === 'warning') {
            icon = 'exclamation-triangle';
        } else if (type === 'danger') {
            icon = 'exclamation-circle';
        } else if (type === 'success') {
            icon = 'check-circle';
        }
        
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
    
    // Show toast for unread notifications count
    const unreadCount = document.querySelector('.sidebar-nav .badge');
    if (unreadCount && parseInt(unreadCount.textContent) > 0) {
        showToast(`You have ${unreadCount.textContent} unread notifications`, 'info');
    }
});

