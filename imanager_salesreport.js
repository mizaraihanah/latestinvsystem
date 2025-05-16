function initializeCharts() {
    // Daily Sales Trend Chart
    if (dailySalesData.length > 0) {
        createDailySalesChart();
    }
    
    // Category Sales Chart
    if (categoryLabels.length > 0) {
        createCategorySalesChart();
    }
    
    // Payment Methods Chart
    if (paymentLabels.length > 0) {
        createPaymentMethodsChart();
    }
    
    // Top Products Chart
    if (productLabels.length > 0) {
        createTopProductsChart();
    }
}

function createDailySalesChart() {
    const ctx = document.getElementById('dailySalesChart').getContext('2d');
    
    // Format dates and extract values
    const dates = dailySalesData.map(item => new Date(item.date).toLocaleDateString('en-MY', {day: '2-digit', month: 'short'}));
    const sales = dailySalesData.map(item => item.sales);
    const items = dailySalesData.map(item => item.items);
    
    // Create the daily sales chart
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: dates,
            datasets: [
                {
                    label: 'Sales (RM)',
                    data: sales,
                    borderColor: '#0561FC',
                    backgroundColor: 'rgba(5, 97, 252, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    yAxisID: 'y'
                },
                {
                    label: 'Items Sold',
                    data: items,
                    borderColor: '#FFC107',
                    backgroundColor: 'transparent',
                    borderWidth: 2,
                    borderDash: [5, 5],
                    tension: 0.4,
                    yAxisID: 'y1'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    callbacks: {
                        label: function(context) {
                            let label = context.dataset.label || '';
                            if (label) {
                                label += ': ';
                            }
                            if (context.datasetIndex === 0) {
                                label += 'RM ' + context.parsed.y.toFixed(2);
                            } else {
                                label += context.parsed.y.toFixed(0);
                            }
                            return label;
                        }
                    }
                },
                legend: {
                    position: 'top',
                }
            },
            scales: {
                x: {
                    grid: {
                        display: false
                    }
                },
                y: {
                    type: 'linear',
                    display: true,
                    position: 'left',
                    title: {
                        display: true,
                        text: 'Sales (RM)'
                    },
                    beginAtZero: true
                },
                y1: {
                    type: 'linear',
                    display: true,
                    position: 'right',
                    title: {
                        display: true,
                        text: 'Items Sold'
                    },
                    beginAtZero: true,
                    grid: {
                        drawOnChartArea: false
                    }
                }
            }
        }
    });
}

function createCategorySalesChart() {
    const ctx = document.getElementById('categorySalesChart').getContext('2d');
    
    // Generate colors for each category
    const colors = generateColors(categoryLabels.length);
    
    // Create the category sales chart
    new Chart(ctx, {
        type: 'pie',
        data: {
            labels: categoryLabels,
            datasets: [{
                data: categorySales,
                backgroundColor: colors,
                hoverBackgroundColor: colors.map(color => {
                    // Slightly darker on hover
                    return color.replace('0.7', '0.9');
                }),
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = 'RM ' + context.parsed.toFixed(2);
                            const total = context.dataset.data.reduce((acc, val) => acc + val, 0);
                            const percentage = ((context.parsed / total) * 100).toFixed(1) + '%';
                            return `${label}: ${value} (${percentage})`;
                        }
                    }
                },
                legend: {
                    position: 'right',
                    labels: {
                        boxWidth: 12
                    }
                }
            }
        }
    });
}

function createPaymentMethodsChart() {
    const ctx = document.getElementById('paymentMethodsChart').getContext('2d');
    
    // Set colors for payment methods
    const colors = {
        'Cash': 'rgba(76, 175, 80, 0.7)',  // Green
        'Card': 'rgba(33, 150, 243, 0.7)', // Blue
        'Online': 'rgba(156, 39, 176, 0.7)' // Purple
    };
    
    // Get colors based on labels
    const backgroundColors = paymentLabels.map(label => colors[label] || 'rgba(150, 150, 150, 0.7)');
    
    // Create the payment methods chart
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: paymentLabels,
            datasets: [{
                data: paymentAmounts,
                backgroundColor: backgroundColors,
                hoverBackgroundColor: backgroundColors.map(color => {
                    return color.replace('0.7', '0.9');
                }),
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = 'RM ' + context.parsed.toFixed(2);
                            const total = context.dataset.data.reduce((acc, val) => acc + val, 0);
                            const percentage = ((context.parsed / total) * 100).toFixed(1) + '%';
                            return `${label}: ${value} (${percentage})`;
                        }
                    }
                },
                legend: {
                    position: 'bottom'
                }
            },
            cutout: '60%'
        }
    });
}

function createTopProductsChart() {
    const ctx = document.getElementById('topProductsChart').getContext('2d');
    
    // Generate colors for products
    const colors = generateColors(productLabels.length);
    
    // Create the top products chart
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: productLabels,
            datasets: [{
                label: 'Sales (RM)',
                data: productAmounts,
                backgroundColor: colors,
                borderColor: colors.map(color => color.replace('0.7', '1')),
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            plugins: {
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return 'RM ' + context.parsed.x.toFixed(2);
                        }
                    }
                },
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Sales (RM)'
                    }
                },
                y: {
                    grid: {
                        display: false
                    }
                }
            }
        }
    });
}

// Helper function to generate colors
function generateColors(count) {
    const baseColors = [
        'rgba(75, 192, 192, 0.7)',   // Teal
        'rgba(54, 162, 235, 0.7)',   // Blue
        'rgba(153, 102, 255, 0.7)',  // Purple
        'rgba(255, 159, 64, 0.7)',   // Orange
        'rgba(255, 99, 132, 0.7)',   // Red
        'rgba(255, 205, 86, 0.7)',   // Yellow
        'rgba(201, 203, 207, 0.7)',  // Grey
        'rgba(0, 150, 136, 0.7)',    // Teal green
        'rgba(103, 58, 183, 0.7)',   // Deep purple
        'rgba(233, 30, 99, 0.7)'     // Pink
    ];
    
    // If we need more colors than in our base set, generate them
    if (count <= baseColors.length) {
        return baseColors.slice(0, count);
    } else {
        let colors = [...baseColors];
        // Add more colors as needed
        for (let i = baseColors.length; i < count; i++) {
            const r = Math.floor(Math.random() * 255);
            const g = Math.floor(Math.random() * 255);
            const b = Math.floor(Math.random() * 255);
            colors.push(`rgba(${r}, ${g}, ${b}, 0.7)`);
        }
        return colors;
    }
}

// Function to show toast notification
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

// Initialize event listeners
function initEventListeners() {
    // Reset filters button
    const resetFiltersBtn = document.getElementById('resetFilters');
    if (resetFiltersBtn) {
        resetFiltersBtn.addEventListener('click', function() {
            document.getElementById('date_from').value = '';
            document.getElementById('date_to').value = '';
            document.getElementById('category').value = '';
            document.getElementById('product').value = '';
            document.getElementById('payment_method').value = '';
            document.getElementById('filterForm').submit();
        });
    }
}