<?php

/**
 * Admin Dashboard Template
 * For users with role = 3 (Administrator)
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Get session data
$session_data = $this->session_manager->get_session_data();
$user_id = $session_data['user_id'] ?? null;
$email = $session_data['email'] ?? '';
$first_name = $session_data['first_name'] ?? '';
$last_name = $session_data['last_name'] ?? '';

// Check if this is being loaded as a shortcode
$is_shortcode = !defined('DIT_IS_FULL_PAGE');

// If not shortcode, output full HTML structure
if (!$is_shortcode):
?>
    <!DOCTYPE html>
    <html lang="uk">

    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>DIT Dashboard - Administrator</title>
        <link rel="stylesheet" href="<?php echo DIT_PLUGIN_URL; ?>assets/css/dashboard.css">
        <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    </head>

    <body>
    <?php endif; ?>
    <div class="dit-dashboard">
        <!-- Header -->
        <div class="dashboard-header">
            <h2>Administrator Dashboard</h2>
            <p>Welcome, <?php echo esc_html($first_name ? $first_name . ' ' . $last_name : $email); ?> | Admin ID: <?php echo esc_html($user_id); ?></p>
        </div>

        <!-- Navigation -->
        <div class="dashboard-nav">
            <a href="#customers" class="nav-item active" data-section="customers">
                <i class="dashicons dashicons-groups"></i>
                <span>Manage Users</span>
            </a>
            <a href="#users" class="nav-item" data-section="users">
                <i class="dashicons dashicons-admin-users"></i>
                <span>System Users</span>
            </a>
            <a href="#tools" class="nav-item" data-section="tools">
                <i class="dashicons dashicons-admin-tools"></i>
                <span>System Tools</span>
            </a>
            <a href="#account" class="nav-item" data-section="account">
                <i class="dashicons dashicons-admin-users"></i>
                <span>Account Settings</span>
            </a>
            <button class="logout-btn"
                onclick="if(typeof DITAdminDashboard !== 'undefined') { DITAdminDashboard.handleLogout(event); } else { console.error('DITAdminDashboard not available'); }">
                <i class="dashicons dashicons-exit"></i>
                <span>Logout</span>
            </button>
        </div>

        <!-- Content -->
        <div class="dashboard-content">
            <!-- Customers Section -->
            <div id="customers-section" class="content-section active">
                <div class="section-header">
                    <h3>Manage Users</h3>
                    <button class="btn-primary" onclick="DITAdminDashboard.showAddCustomerModal()">
                        <i class="dashicons dashicons-plus"></i>
                        Add New User
                    </button>
                </div>

                <div class="customers-list">
                    <div class="loading-spinner" id="customers-loading">
                        <div class="spinner"></div>
                        <p>Loading customers...</p>
                    </div>
                    <div id="customers-container" style="display: none;">
                        <!-- Customers will be loaded here -->
                    </div>
                </div>
            </div>

            <!-- Users Section -->
            <div id="users-section" class="content-section">
                <div class="section-header">
                    <h3>System Users</h3>
                    <button class="btn-primary" onclick="DITAdminDashboard.showAddUserModal()">
                        <i class="dashicons dashicons-plus"></i>
                        Add New System User
                    </button>
                </div>

                <div class="users-list">
                    <div class="loading-spinner" id="users-loading">
                        <div class="spinner"></div>
                        <p>Loading users...</p>
                    </div>
                    <div id="users-container" style="display: none;">
                        <!-- Users will be loaded here -->
                    </div>
                </div>
            </div>

            <!-- System Tools Section -->
            <div id="tools-section" class="content-section">
                <div class="section-header">
                    <h3>System Tools</h3>
                    <p>Administrative tools and system management</p>
                </div>

                <div class="tools-grid">
                    <div class="tool-item">
                        <div class="tool-icon">
                            <i class="dashicons dashicons-shield"></i>
                        </div>
                        <div class="tool-info">
                            <h4>System Health</h4>
                            <p>Monitor system performance and health status</p>
                            <div class="tool-status active">Active</div>
                            <button class="btn-primary tool-launch-btn"
                                onclick="DITAdminDashboard.launchTool('system-health')">
                                Launch Tool
                            </button>
                        </div>
                    </div>

                    <div class="tool-item">
                        <div class="tool-icon">
                            <i class="dashicons dashicons-list-view"></i>
                        </div>
                        <div class="tool-info">
                            <h4>Audit Logs</h4>
                            <p>View system audit logs and activity history</p>
                            <div class="tool-status active">Active</div>
                            <button class="btn-primary tool-launch-btn"
                                onclick="DITAdminDashboard.launchTool('audit-logs')">
                                Launch Tool
                            </button>
                        </div>
                    </div>

                    <div class="tool-item">
                        <div class="tool-icon">
                            <i class="dashicons dashicons-yes-alt"></i>
                        </div>
                        <div class="tool-info">
                            <h4>User Management</h4>
                            <p>Manage user accounts and permissions</p>
                            <div class="tool-status active">Active</div>
                            <button class="btn-primary tool-launch-btn"
                                onclick="DITAdminDashboard.launchTool('user-management')">
                                Launch Tool
                            </button>
                        </div>
                    </div>

                    <div class="tool-item">
                        <div class="tool-icon">
                            <i class="dashicons dashicons-chart-bar"></i>
                        </div>
                        <div class="tool-info">
                            <h4>System Reports</h4>
                            <p>Generate comprehensive system reports</p>
                            <div class="tool-status active">Active</div>
                            <button class="btn-primary tool-launch-btn"
                                onclick="DITAdminDashboard.launchTool('system-reports')">
                                Launch Tool
                            </button>
                        </div>
                    </div>
                </div>

                <!-- System Statistics -->
                <div class="system-stats">
                    <h4>System Statistics</h4>
                    <div class="stats-grid">
                        <div class="stat-item">
                            <div class="stat-number" id="total-customers">0</div>
                            <div class="stat-label">Total Customers</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-number" id="total-users">0</div>
                            <div class="stat-label">Total Users</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-number" id="active-sessions">0</div>
                            <div class="stat-label">Active Sessions</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-number" id="system-uptime">99.9%</div>
                            <div class="stat-label">System Uptime</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Account Settings Section -->
            <div id="account-section" class="content-section">
                <div class="section-header">
                    <h3>Account Settings</h3>
                    <p>Manage your administrator account</p>
                </div>

                <div class="account-form">
                    <div class="form-group">
                        <label for="current_email">Email Address</label>
                        <input type="email" id="current_email" value="<?php echo esc_attr($email); ?>" readonly>
                        <small>Email address cannot be changed.</small>
                    </div>

                    <div class="form-group">
                        <label for="first_name">First Name</label>
                        <input type="text" id="first_name" value="<?php echo esc_attr($first_name ?? ''); ?>" placeholder="Enter your first name">
                    </div>

                    <div class="form-group">
                        <label for="last_name">Last Name</label>
                        <input type="text" id="last_name" value="<?php echo esc_attr($last_name ?? ''); ?>" placeholder="Enter your last name">
                    </div>

                    <div class="form-group">
                        <label for="new_password">New Password</label>
                        <input type="password" id="new_password" placeholder="Enter new password">
                        <small>Password must be at least 8 characters long</small>
                    </div>

                    <div class="form-group">
                        <label for="confirm_password">Confirm Password</label>
                        <input type="password" id="confirm_password" placeholder="Confirm new password">
                    </div>

                    <button type="button" class="btn-primary" onclick="DITAdminDashboard.updateAccount()">
                        Update Account
                    </button>
                </div>

                <!-- Account Information -->
                <div class="account-info">
                    <h4>Account Information</h4>
                    <div class="info-grid">
                        <div class="info-item">
                            <label>Admin ID:</label>
                            <span><?php echo esc_html($user_id); ?></span>
                        </div>
                        <div class="info-item">
                            <label>Account Type:</label>
                            <span>Administrator</span>
                        </div>
                        <div class="info-item">
                            <label>Member Since:</label>
                            <span><?php echo date('Y-m-d'); ?></span>
                        </div>
                        <div class="info-item">
                            <label>Last Login:</label>
                            <span><?php echo date('Y-m-d H:i:s'); ?></span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Add Customer Modal -->
    <div id="add-customer-modal" class="modal" style="display: none;">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Add New Customer</h3>
                <span class="close" onclick="DITAdminDashboard.closeModal('add-customer-modal')">&times;</span>
            </div>
            <div class="modal-body">
                <form id="add-customer-form">
                    <input type="hidden" id="edit_customer_id" value="">
                    <div class="form-group">
                        <label for="customer_email">Email Address</label>
                        <input type="email" id="customer_email" required>
                    </div>

                    <div class="form-group">
                        <label for="customer_password">Password</label>
                        <input type="password" id="customer_password" required>
                    </div>

                    <div class="form-group">
                        <label for="customer_first_name">First Name</label>
                        <input type="text" id="customer_first_name" required>
                    </div>

                    <div class="form-group">
                        <label for="customer_last_name">Last Name</label>
                        <input type="text" id="customer_last_name" required>
                    </div>

                    <div class="form-group">
                        <label for="customer_company">Company</label>
                        <input type="text" id="customer_company" required>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-secondary"
                    onclick="DITAdminDashboard.closeModal('add-customer-modal')">Cancel</button>
                <button type="button" class="btn-primary" onclick="DITAdminDashboard.addCustomer()">Add Customer</button>
            </div>
        </div>
    </div>

    <!-- Add User Modal -->
    <div id="add-user-modal" class="modal" style="display: none;">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Add New User</h3>
                <span class="close" onclick="DITAdminDashboard.closeModal('add-user-modal')">&times;</span>
            </div>
            <div class="modal-body">
                <form id="add-user-form">
                    <input type="hidden" id="edit_user_id" value="">
                    <div class="form-group">
                        <label for="user_email">Email Address</label>
                        <input type="email" id="user_email" required>
                    </div>

                    <div class="form-group">
                        <label for="user_password">Password</label>
                        <input type="password" id="user_password" required>
                    </div>

                    <div class="form-group">
                        <label for="user_first_name">First Name</label>
                        <input type="text" id="user_first_name" required>
                    </div>

                    <div class="form-group">
                        <label for="user_last_name">Last Name</label>
                        <input type="text" id="user_last_name" required>
                    </div>

                    <div class="form-group">
                        <label for="user_customer_id">Customer ID</label>
                        <input type="number" id="user_customer_id" required>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-secondary"
                    onclick="DITAdminDashboard.closeModal('add-user-modal')">Cancel</button>
                <button type="button" class="btn-primary" onclick="DITAdminDashboard.addUser()">Add User</button>
            </div>
        </div>
    </div>

    <!-- Delete Confirmation Modals -->
    <div id="delete-customer-modal" class="modal" style="display: none;">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Delete Customer</h3>
                <span class="close" onclick="DITAdminDashboard.closeModal('delete-customer-modal')">&times;</span>
            </div>
            <div class="modal-body">
                <p>Are you sure you want to delete customer <strong id="delete-customer-name"></strong>?</p>
                <p>This action will also delete all associated users and cannot be undone.</p>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-secondary"
                    onclick="DITAdminDashboard.closeModal('delete-customer-modal')">Cancel</button>
                <button type="button" class="btn-danger" onclick="DITAdminDashboard.deleteCustomer()">Delete Customer</button>
            </div>
        </div>
    </div>

    <div id="delete-user-modal" class="modal" style="display: none;">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Delete User</h3>
                <span class="close" onclick="DITAdminDashboard.closeModal('delete-user-modal')">&times;</span>
            </div>
            <div class="modal-body">
                <p>Are you sure you want to delete user <strong id="delete-user-name"></strong>?</p>
                <p>This action cannot be undone.</p>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-secondary"
                    onclick="DITAdminDashboard.closeModal('delete-user-modal')">Cancel</button>
                <button type="button" class="btn-danger" onclick="DITAdminDashboard.deleteUser()">Delete User</button>
            </div>
        </div>
    </div>

    <!-- Tool Launch Modal -->
    <div id="tool-launch-modal" class="modal" style="display: none;">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="tool-modal-title">Launch Tool</h3>
                <span class="close" onclick="DITAdminDashboard.closeModal('tool-launch-modal')">&times;</span>
            </div>
            <div class="modal-body">
                <div id="tool-loading" class="loading-spinner">
                    <div class="spinner"></div>
                    <p>Initializing tool...</p>
                </div>
                <div id="tool-content" style="display: none;">
                    <!-- Tool content will be loaded here -->
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-secondary"
                    onclick="DITAdminDashboard.closeModal('tool-launch-modal')">Close</button>
            </div>
        </div>
    </div>

    <?php if (!$is_shortcode): ?>
    </body>

    </html>
<?php endif; ?>