<?php

/**
 * Customer Dashboard Template
 * For users with role = 2 (Customer)
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Get session data
$session_data = $this->session_manager->get_session_data();
$customer_id = $session_data['customer_id'] ?? null;
$email = $session_data['email'] ?? '';

// Get user data from session with fallback to local data
$first_name = $session_data['first_name'] ?? '';
$last_name = $session_data['last_name'] ?? '';
$company = $session_data['company'] ?? '';

// If session data is missing, try to get from local storage
if (empty($first_name) || empty($last_name)) {
    $local_first_name = \DIT\get_user_first_name($customer_id);
    $local_last_name = \DIT\get_user_last_name($customer_id);
    $local_company = \DIT\get_user_company($customer_id);

    $first_name = $first_name ?: $local_first_name ?: '';
    $last_name = $last_name ?: $local_last_name ?: '';
    $company = $company ?: $local_company ?: '';

    // Log fallback data retrieval
    error_log('DIT Dashboard: Using fallback data for customer ' . $customer_id .
        ' - First Name: ' . ($first_name ?: 'NOT FOUND') .
        ', Last Name: ' . ($last_name ?: 'NOT FOUND') .
        ', Company: ' . ($company ?: 'NOT FOUND'));
}

// Check if this is being loaded as a shortcode
$is_shortcode = !defined('DIT_IS_FULL_PAGE');

echo '<pre>';
var_dump($session_data);
echo '</pre>';

// If not shortcode, output full HTML structure
if (!$is_shortcode):
?>
    <!DOCTYPE html>
    <html lang="uk">

    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>DIT Dashboard - Customer</title>
        <link rel="stylesheet" href="<?php echo DIT_PLUGIN_URL; ?>assets/css/dashboard.css">
        <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    </head>

    <body>
    <?php endif; ?>
    <div class="dit-dashboard">
        <!-- Header -->
        <div class="dashboard-header">
            <h2>Customer Dashboard</h2>
            <p>Welcome, <?php echo esc_html($first_name ? $first_name . ' ' . $last_name : $email); ?> | Customer ID:
                <?php echo esc_html($customer_id); ?></p>
        </div>

        <!-- Navigation -->
        <div class="dashboard-nav">
            <a href="#users" class="nav-item active" data-section="users">
                <i class="dashicons dashicons-groups"></i>
                <span>Manage Users</span>
            </a>
            <a href="#tools" class="nav-item" data-section="tools">
                <i class="dashicons dashicons-admin-tools"></i>
                <span>Tools</span>
            </a>
            <a href="#account" class="nav-item" data-section="account">
                <i class="dashicons dashicons-admin-users"></i>
                <span>Account Settings</span>
            </a>
            <button class="logout-btn"
                onclick="if(typeof DITDashboard !== 'undefined') { DITDashboard.handleLogout(event); } else { console.error('DITDashboard not available'); }">
                <i class="dashicons dashicons-exit"></i>
                <span>Logout</span>
            </button>
        </div>

        <!-- Content -->
        <div class="dashboard-content">
            <!-- Users Section -->
            <div id="users-section" class="content-section active">
                <div class="section-header">
                    <h3>Manage Users</h3>
                    <button class="btn-primary" onclick="DITDashboard.showAddUserModal()">
                        <i class="dashicons dashicons-plus"></i>
                        Add New User
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

            <!-- Tools Section -->
            <div id="tools-section" class="content-section">
                <div class="section-header">
                    <h3>Available Tools</h3>
                </div>

                <div class="tools-grid">
                    <div class="tool-item">
                        <div class="tool-icon">
                            <i class="dashicons dashicons-shield"></i>
                        </div>
                        <div class="tool-info">
                            <h4>Data Integrity Tool</h4>
                            <p>Comprehensive data validation and integrity checking</p>
                            <div class="tool-status active">Active</div>
                        </div>
                    </div>

                    <div class="tool-item">
                        <div class="tool-icon">
                            <i class="dashicons dashicons-list-view"></i>
                        </div>
                        <div class="tool-info">
                            <h4>Audit Trail</h4>
                            <p>Track and monitor all data changes and activities</p>
                            <div class="tool-status active">Active</div>
                        </div>
                    </div>

                    <div class="tool-item">
                        <div class="tool-icon">
                            <i class="dashicons dashicons-yes-alt"></i>
                        </div>
                        <div class="tool-info">
                            <h4>Compliance Checker</h4>
                            <p>Ensure compliance with industry standards and regulations</p>
                            <div class="tool-status active">Active</div>
                        </div>
                    </div>

                    <div class="tool-item">
                        <div class="tool-icon">
                            <i class="dashicons dashicons-chart-bar"></i>
                        </div>
                        <div class="tool-info">
                            <h4>Report Generator</h4>
                            <p>Generate comprehensive reports and analytics</p>
                            <div class="tool-status active">Active</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Account Settings Section -->
            <div id="account-section" class="content-section">
                <div class="section-header">
                    <h3>Account Settings</h3>
                </div>

                <div class="account-form">
                    <div class="form-group">
                        <label for="current_email">Email Address</label>
                        <input type="email" id="current_email" value="<?php echo esc_attr($email); ?>" readonly>
                    </div>

                    <div class="form-group">
                        <label for="first_name">First Name</label>
                        <input type="text" id="first_name" value="<?php echo esc_attr($first_name); ?>"
                            placeholder="Enter your first name">
                    </div>

                    <div class="form-group">
                        <label for="last_name">Last Name</label>
                        <input type="text" id="last_name" value="<?php echo esc_attr($last_name); ?>"
                            placeholder="Enter your last name">
                    </div>

                    <div class="form-group">
                        <label for="company">Company</label>
                        <input type="text" id="company" value="<?php echo esc_attr($company); ?>"
                            placeholder="Enter your company name">
                    </div>

                    <div class="form-group">
                        <label for="new_password">New Password</label>
                        <input type="password" id="new_password" placeholder="Enter new password">
                    </div>

                    <div class="form-group">
                        <label for="confirm_password">Confirm Password</label>
                        <input type="password" id="confirm_password" placeholder="Confirm new password">
                    </div>

                    <button type="button" class="btn-primary" onclick="DITDashboard.updateAccount()">
                        Update Account
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Add User Modal -->
    <div id="add-user-modal" class="modal" style="display: none;">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Add New User</h3>
                <span class="close" onclick="DITDashboard.closeModal('add-user-modal')">&times;</span>
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
                        <label>Tools Access</label>
                        <div class="checkbox-group">
                            <label class="checkbox-item">
                                <input type="checkbox" value="0" checked> Data Integrity Tool
                            </label>
                            <label class="checkbox-item">
                                <input type="checkbox" value="1" checked> Audit Trail
                            </label>
                            <label class="checkbox-item">
                                <input type="checkbox" value="2" checked> Compliance Checker
                            </label>
                            <label class="checkbox-item">
                                <input type="checkbox" value="3" checked> Report Generator
                            </label>
                        </div>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-secondary"
                    onclick="DITDashboard.closeModal('add-user-modal')">Cancel</button>
                <button type="button" class="btn-primary" onclick="DITDashboard.addUser()">Add User</button>
            </div>
        </div>
    </div>

    <!-- Delete User Confirmation Modal -->
    <div id="delete-user-modal" class="modal" style="display: none;">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Delete User</h3>
                <span class="close" onclick="DITDashboard.closeModal('delete-user-modal')">&times;</span>
            </div>
            <div class="modal-body">
                <p>Are you sure you want to delete user <strong id="delete-user-name"></strong>?</p>
                <p>This action cannot be undone.</p>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-secondary"
                    onclick="DITDashboard.closeModal('delete-user-modal')">Cancel</button>
                <button type="button" class="btn-danger" onclick="DITDashboard.deleteUser()">Delete User</button>
            </div>
        </div>
    </div>


    <?php if (!$is_shortcode): ?>
    </body>

    </html>
<?php endif; ?>