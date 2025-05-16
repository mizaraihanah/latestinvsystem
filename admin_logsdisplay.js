document.addEventListener('DOMContentLoaded', function() {
    // Initialize the actions chart
    initCharts();
    
    // Add reset button functionality
    document.getElementById('resetBtn').addEventListener('click', function() {
        document.getElementById('user').value = '';
        document.getElementById('action').value = '';
        document.getElementById('date_from').value = '';
        document.getElementById('date_to').value = '';
        document.getElementById('filterForm').submit();
    });
    
    // Add date validation
    const dateFrom = document.getElementById('date_from');
    const dateTo = document.getElementById('date_to');
    
    // Ensure date_to is not before date_from
    dateTo.addEventListener('change', function() {
        if (dateFrom.value && this.value && this.value < dateFrom.value) {
            alert('End date cannot be earlier than start date');
            this.value = dateFrom.value;
        }
    });
    
    // Ensure date_from is not after date_to
    dateFrom.addEventListener('change', function() {
        if (dateTo.value && this.value && this.value > dateTo.value) {
            dateTo.value = this.value;
        }
    });
});

/**
 * Initialize chart visualizations
 */
function initCharts() {
    // Actions Distribution Chart
    const actionsCtx = document.getElementById('actionsChart').getContext('2d');
    
    new Chart(actionsCtx, {
        type: 'doughnut',
        data: {
            labels: actionLabels,
            datasets: [{
                data: actionCounts,
                backgroundColor: chartColors,
                hoverBackgroundColor: chartColors.map(color => color.replace('rgb', 'rgba').replace(')', ', 0.8)')),
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        boxWidth: 12,
                        font: {
                            size: 12
                        }
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.raw;
                            const total = context.dataset.data.reduce((acc, data) => acc + data, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            },
            cutout: '60%'
        }
    });
}

/**
 * Format a date string in a more readable format
 * @param {string} dateString - The date string to format
 * @returns {string} - Formatted date string
 */
function formatDate(dateString) {
    const options = { 
        year: 'numeric', 
        month: 'short', 
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    };
    return new Date(dateString).toLocaleDateString('en-US', options);
}

/**
 * Export logs to CSV
 */
function exportLogsToCSV() {
    // Get current filter values
    const userFilter = document.getElementById('user').value;
    const actionFilter = document.getElementById('action').value;
    const dateFrom = document.getElementById('date_from').value;
    const dateTo = document.getElementById('date_to').value;
    
    // Build export URL with current filters
    let exportUrl = 'admin_logsdisplay.php?export=csv';
    
    if (userFilter) {
        exportUrl += `&user=${encodeURIComponent(userFilter)}`;
    }
    
    if (actionFilter) {
        exportUrl += `&action=${encodeURIComponent(actionFilter)}`;
    }
    
    if (dateFrom) {
        exportUrl += `&date_from=${encodeURIComponent(dateFrom)}`;
    }
    
    if (dateTo) {
        exportUrl += `&date_to=${encodeURIComponent(dateTo)}`;
    }
    
    // Redirect to export URL
    window.location.href = exportUrl;
}