/**
 * Admin Dashboard JavaScript
 * For administrators (role = 3)
 */

console.log('DITAdminDashboard: Script loaded');

const DITAdminDashboard = {
    /**
     * Initialize admin dashboard
     */
    init: function () {
        console.log('DITAdminDashboard: Initializing...');
        console.log('DITAdminDashboard: dit_ajax available:', typeof dit_ajax !== 'undefined');
        if (typeof dit_ajax !== 'undefined') {
            console.log('DITAdminDashboard: dit_ajax.ajax_url:', dit_ajax.ajax_url);
        }

        this.bindEvents();
        this.loadCustomers();
        this.loadUsers();
        this.loadSystemStats();
    },

    /**
     * Bind event listeners
     */
    bindEvents: function () {
        // Navigation
        $('.nav-item').on('click', function (e) {
            e.preventDefault();
            const section = $(this).data('section');
            DITAdminDashboard.switchSection(section);
        });

        // Logout
        $('.logout-btn').on('click', function (e) {
            e.preventDefault();
            DITAdminDashboard.handleLogout();
        });
    },

    /**
     * Switch between dashboard sections
     */
    switchSection: function (section) {
        // Update navigation
        $('.nav-item').removeClass('active');
        $(`.nav-item[data-section="${ section }"]`).addClass('active');

        // Update content
        $('.content-section').removeClass('active');
        $(`#${ section }-section`).addClass('active');

        // Load section-specific data
        switch (section) {
            case 'customers':
                this.loadCustomers();
                break;
            case 'users':
                this.loadUsers();
                break;
            case 'tools':
                this.loadSystemStats();
                break;
        }
    },

    /**
     * Load customers list
     */
    loadCustomers: function () {
        console.log('DITAdminDashboard: Loading customers...');
        $('#customers-loading').show();
        $('#customers-container').hide();

        if (typeof dit_ajax === 'undefined') {
            console.error('DITAdminDashboard: dit_ajax is not defined!');
            $('#customers-loading').hide();
            $('#customers-container').html('<div class="error-message">Configuration error: dit_ajax not available</div>').show();
            return;
        }

        $.ajax({
            url: dit_ajax.ajax_url,
            type: 'POST',
            timeout: 10000, // 10 seconds timeout
            data: {
                action: 'dit_get_all_customers'
            },
            success: function (response) {
                console.log('DITAdminDashboard: Customers response:', response);
                $('#customers-loading').hide();
                if (response.success) {
                    DITAdminDashboard.renderCustomers(response.data);
                } else {
                    $('#customers-container').html('<div class="error-message">' + response.data + '</div>').show();
                }
            },
            error: function (xhr, status, error) {
                console.error('DITAdminDashboard: Customers AJAX error:', { xhr, status, error });
                $('#customers-loading').hide();
                if (status === 'timeout') {
                    $('#customers-container').html('<div class="error-message">Request timeout. Please try again.</div>').show();
                } else {
                    $('#customers-container').html('<div class="error-message">Failed to load customers. Error: ' + error + '</div>').show();
                }
            }
        });
    },

    /**
     * Render customers list (actually renders users like customer role)
     */
    renderCustomers: function (users) {
        if (!users || users.length === 0) {
            $('#customers-container').html('<div class="no-data">No users found</div>').show();
            return;
        }

        let html = '<div class="customers-grid">';
        users.forEach(function (user) {
            // Format tools array
            const toolsList = user.tools && user.tools.length > 0 ? user.tools.join(', ') : 'No tools assigned';

            html += `
                <div class="customer-item" data-id="${ user.id }">
                    <div class="customer-info">
                        <h4>${ user.name }</h4>
                        <p><strong>Email:</strong> ${ user.email }</p>
                        <p><strong>Tools:</strong> ${ toolsList }</p>
                        <p><strong>Status:</strong> <span class="status-badge ${ user.active ? 'active' : 'inactive' }">${ user.active ? 'Active' : 'Inactive' }</span></p>
                    </div>
                    <div class="customer-actions">
                        <button class="btn-secondary" onclick="DITAdminDashboard.editCustomer(${ user.id })">
                            <i class="dashicons dashicons-edit"></i> Edit
                        </button>
                        <button class="btn-danger" onclick="DITAdminDashboard.deleteCustomer(${ user.id }, '${ user.name }')">
                            <i class="dashicons dashicons-trash"></i> Delete
                        </button>
                    </div>
                </div>
            `;
        });
        html += '</div>';

        $('#customers-container').html(html).show();
    },

    /**
     * Load users list
     */
    loadUsers: function () {
        console.log('DITAdminDashboard: Loading users...');
        $('#users-loading').show();
        $('#users-container').hide();

        if (typeof dit_ajax === 'undefined') {
            console.error('DITAdminDashboard: dit_ajax is not defined!');
            $('#users-loading').hide();
            $('#users-container').html('<div class="error-message">Configuration error: dit_ajax not available</div>').show();
            return;
        }

        $.ajax({
            url: dit_ajax.ajax_url,
            type: 'POST',
            timeout: 10000, // 10 seconds timeout
            data: {
                action: 'dit_get_all_users'
            },
            success: function (response) {
                console.log('DITAdminDashboard: Users response:', response);
                $('#users-loading').hide();
                if (response.success) {
                    DITAdminDashboard.renderUsers(response.data);
                } else {
                    $('#users-container').html('<div class="error-message">' + response.data + '</div>').show();
                }
            },
            error: function (xhr, status, error) {
                console.error('DITAdminDashboard: Users AJAX error:', { xhr, status, error });
                $('#users-loading').hide();
                if (status === 'timeout') {
                    $('#users-container').html('<div class="error-message">Request timeout. Please try again.</div>').show();
                } else {
                    $('#users-container').html('<div class="error-message">Failed to load users. Error: ' + error + '</div>').show();
                }
            }
        });
    },

    /**
     * Render users list
     */
    renderUsers: function (users) {
        if (!users || users.length === 0) {
            $('#users-container').html('<div class="no-data">No users found</div>').show();
            return;
        }

        let html = '<div class="users-grid">';
        users.forEach(function (user) {
            html += `
                <div class="user-item" data-id="${ user.id }">
                    <div class="user-info">
                        <h4>${ user.first_name } ${ user.last_name }</h4>
                        <p><strong>Email:</strong> ${ user.email }</p>
                        <p><strong>Customer ID:</strong> ${ user.customer_id }</p>
                        <p><strong>Status:</strong> <span class="status-badge ${ user.status }">${ user.status }</span></p>
                    </div>
                    <div class="user-actions">
                        <button class="btn-secondary" onclick="DITAdminDashboard.editUser(${ user.id })">
                            <i class="dashicons dashicons-edit"></i> Edit
                        </button>
                        <button class="btn-danger" onclick="DITAdminDashboard.deleteUser(${ user.id }, '${ user.first_name } ${ user.last_name }')">
                            <i class="dashicons dashicons-trash"></i> Delete
                        </button>
                    </div>
                </div>
            `;
        });
        html += '</div>';

        $('#users-container').html(html).show();
    },

    /**
     * Load system statistics
     */
    loadSystemStats: function () {
        // For now, use mock data
        $('#total-customers').text('2');
        $('#total-users').text('2');
        $('#active-sessions').text('1');
        $('#system-uptime').text('99.9%');
    },

    /**
     * Show add customer modal
     */
    showAddCustomerModal: function () {
        $('#add-customer-form')[0].reset();
        $('#edit_customer_id').val('');
        $('#add-customer-modal').show();
    },

    /**
     * Show add user modal
     */
    showAddUserModal: function () {
        $('#add-user-form')[0].reset();
        $('#edit_user_id').val('');
        $('#add-user-modal').show();
    },

    /**
     * Add customer
     */
    addCustomer: function () {
        const formData = {
            action: 'dit_add_customer',
            email: $('#customer_email').val(),
            password: $('#customer_password').val(),
            first_name: $('#customer_first_name').val(),
            last_name: $('#customer_last_name').val(),
            company: $('#customer_company').val()
        };

        $.ajax({
            url: dit_ajax.ajax_url,
            type: 'POST',
            data: formData,
            success: function (response) {
                if (response.success) {
                    DITAdminDashboard.closeModal('add-customer-modal');
                    DITAdminDashboard.loadCustomers();
                    alert('Customer added successfully!');
                } else {
                    alert('Error: ' + response.data);
                }
            },
            error: function () {
                alert('Failed to add customer');
            }
        });
    },

    /**
     * Add user
     */
    addUser: function () {
        const formData = {
            action: 'dit_add_user',
            email: $('#user_email').val(),
            password: $('#user_password').val(),
            first_name: $('#user_first_name').val(),
            last_name: $('#user_last_name').val(),
            customer_id: $('#user_customer_id').val()
        };

        $.ajax({
            url: dit_ajax.ajax_url,
            type: 'POST',
            data: formData,
            success: function (response) {
                if (response.success) {
                    DITAdminDashboard.closeModal('add-user-modal');
                    DITAdminDashboard.loadUsers();
                    alert('User added successfully!');
                } else {
                    alert('Error: ' + response.data);
                }
            },
            error: function () {
                alert('Failed to add user');
            }
        });
    },

    /**
     * Edit customer
     */
    editCustomer: function (customerId) {
        // For now, just show the modal with customer ID
        $('#edit_customer_id').val(customerId);
        $('#add-customer-modal').show();
        // TODO: Load customer data and populate form
    },

    /**
     * Edit user
     */
    editUser: function (userId) {
        // For now, just show the modal with user ID
        $('#edit_user_id').val(userId);
        $('#add-user-modal').show();
        // TODO: Load user data and populate form
    },

    /**
     * Delete customer
     */
    deleteCustomer: function (customerId, customerName) {
        if (confirm(`Are you sure you want to delete customer "${ customerName }"? This action cannot be undone.`)) {
            $.ajax({
                url: dit_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'dit_delete_customer',
                    customer_id: customerId
                },
                success: function (response) {
                    if (response.success) {
                        DITAdminDashboard.loadCustomers();
                        alert('Customer deleted successfully!');
                    } else {
                        alert('Error: ' + response.data);
                    }
                },
                error: function () {
                    alert('Failed to delete customer');
                }
            });
        }
    },

    /**
     * Delete user
     */
    deleteUser: function (userId, userName) {
        if (confirm(`Are you sure you want to delete user "${ userName }"? This action cannot be undone.`)) {
            $.ajax({
                url: dit_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'dit_delete_user',
                    user_id: userId
                },
                success: function (response) {
                    if (response.success) {
                        DITAdminDashboard.loadUsers();
                        alert('User deleted successfully!');
                    } else {
                        alert('Error: ' + response.data);
                    }
                },
                error: function () {
                    alert('Failed to delete user');
                }
            });
        }
    },

    /**
     * Close modal
     */
    closeModal: function (modalId) {
        $('#' + modalId).hide();
    },

    /**
     * Launch tool
     */
    launchTool: function (toolName) {
        const toolTitles = {
            'system-health': 'System Health Monitor',
            'audit-logs': 'Audit Logs',
            'user-management': 'User Management',
            'system-reports': 'System Reports'
        };

        $('#tool-modal-title').text(toolTitles[toolName] || 'Tool');
        $('#tool-loading').show();
        $('#tool-content').hide();
        $('#tool-launch-modal').show();

        // Simulate tool loading
        setTimeout(function () {
            $('#tool-loading').hide();
            $('#tool-content').html('<p>Tool "' + toolName + '" is loading...</p>').show();
        }, 2000);
    },

    /**
     * Update account
     */
    updateAccount: function () {
        const formData = {
            action: 'dit_update_account',
            first_name: $('#first_name').val(),
            last_name: $('#last_name').val(),
            new_password: $('#new_password').val(),
            confirm_password: $('#confirm_password').val()
        };

        $.ajax({
            url: dit_ajax.ajax_url,
            type: 'POST',
            data: formData,
            success: function (response) {
                if (response.success) {
                    alert('Account updated successfully!');
                    $('#new_password').val('');
                    $('#confirm_password').val('');
                } else {
                    alert('Error: ' + response.data);
                }
            },
            error: function () {
                alert('Failed to update account');
            }
        });
    },

    /**
     * Handle logout
     */
    handleLogout: function () {
        if (confirm('Are you sure you want to logout?')) {
            $.ajax({
                url: dit_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'dit_logout'
                },
                success: function (response) {
                    if (response.success) {
                        window.location.href = response.data.redirect_url || '/';
                    } else {
                        alert('Logout failed: ' + response.data);
                    }
                },
                error: function () {
                    alert('Logout failed');
                }
            });
        }
    }
};

// Initialize when document is ready
$(document).ready(function () {
    console.log('DITAdminDashboard: Document ready, initializing...');
    console.log('DITAdminDashboard: jQuery available:', typeof $ !== 'undefined');
    console.log('DITAdminDashboard: DITAdminDashboard object available:', typeof DITAdminDashboard !== 'undefined');

    if (typeof DITAdminDashboard !== 'undefined') {
        DITAdminDashboard.init();
    } else {
        console.error('DITAdminDashboard: DITAdminDashboard object is not defined!');
    }
}); 