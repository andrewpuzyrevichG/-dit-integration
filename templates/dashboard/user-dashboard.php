<?php

/**
 * User Dashboard Template
 * For users with role = 1 (User)
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
echo '<pre>';
print_r($session_data);
echo '</pre>';

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
        <title>DIT Dashboard - User</title>
        <link rel="stylesheet" href="<?php echo DIT_PLUGIN_URL; ?>assets/css/dashboard.css">
        <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    </head>

    <body>
    <?php endif; ?>
    <div class="dit-dashboard">
        <!-- Header -->
        <div class="dashboard-header">
            <h2>User Dashboard</h2>
            <p>Welcome, <?php echo esc_html($first_name ? $first_name . ' ' . $last_name : $email); ?> | User ID: <?php echo esc_html($user_id); ?></p>
        </div>

        <!-- Navigation -->
        <div class="dashboard-nav">
            <a href="#tools" class="nav-item active" data-section="tools">
                <i class="dashicons dashicons-admin-tools"></i>
                <span>Available Tools</span>
            </a>
            <a href="#account" class="nav-item" data-section="account">
                <i class="dashicons dashicons-admin-users"></i>
                <span>Account Settings</span>
            </a>
            <button class="logout-btn">
                <i class="dashicons dashicons-exit"></i>
                <span>Logout</span>
            </button>
        </div>

        <!-- Content -->
        <div class="dashboard-content">
            <!-- Tools Section -->
            <div id="tools-section" class="content-section active">
                <div class="section-header">
                    <h3>Available Tools</h3>
                    <p>You have access to the following tools:</p>
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
                            <button class="btn-primary tool-launch-btn"
                                onclick="DITDashboard.launchTool('data-integrity')">
                                Launch Tool
                            </button>
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
                            <button class="btn-primary tool-launch-btn"
                                onclick="DITDashboard.launchTool('audit-trail')">
                                Launch Tool
                            </button>
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
                            <button class="btn-primary tool-launch-btn"
                                onclick="DITDashboard.launchTool('compliance-checker')">
                                Launch Tool
                            </button>
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
                            <button class="btn-primary tool-launch-btn"
                                onclick="DITDashboard.launchTool('report-generator')">
                                Launch Tool
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Recent Activity -->
                <div class="recent-activity">
                    <h4>Recent Activity</h4>
                    <div class="activity-list">
                        <div class="activity-item">
                            <div class="activity-icon">
                                <i class="dashicons dashicons-clock"></i>
                            </div>
                            <div class="activity-content">
                                <p>Last login: <?php echo date('Y-m-d H:i:s'); ?></p>
                                <span class="activity-time">Just now</span>
                            </div>
                        </div>
                        <div class="activity-item">
                            <div class="activity-icon">
                                <i class="dashicons dashicons-shield"></i>
                            </div>
                            <div class="activity-content">
                                <p>Data Integrity Tool accessed</p>
                                <span class="activity-time">2 hours ago</span>
                            </div>
                        </div>
                        <div class="activity-item">
                            <div class="activity-icon">
                                <i class="dashicons dashicons-chart-bar"></i>
                            </div>
                            <div class="activity-content">
                                <p>Report generated successfully</p>
                                <span class="activity-time">1 day ago</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Account Settings Section -->
            <div id="account-section" class="content-section">
                <div class="section-header">
                    <h3>Account Settings</h3>
                    <p>Manage your account information and security settings</p>
                </div>

                <div class="account-form">
                    <div class="form-group">
                        <label for="current_email">Email Address</label>
                        <input type="email" id="current_email" value="<?php echo esc_attr($email); ?>" readonly>
                        <small>Email address cannot be changed. Contact your administrator if needed.</small>
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
                        <small>Password must be at least 6 characters long</small>
                    </div>

                    <div class="form-group">
                        <label for="confirm_password">Confirm Password</label>
                        <input type="password" id="confirm_password" placeholder="Confirm new password">
                    </div>

                    <button type="button" class="btn-primary" onclick="DITDashboard.updateAccount()">
                        Update Account
                    </button>
                </div>

                <!-- Account Information -->
                <div class="account-info">
                    <h4>Account Information</h4>
                    <div class="info-grid">
                        <div class="info-item">
                            <label>User ID:</label>
                            <span><?php echo esc_html($user_id); ?></span>
                        </div>
                        <div class="info-item">
                            <label>Account Type:</label>
                            <span>User</span>
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

    <!-- Tool Launch Modal -->
    <div id="tool-launch-modal" class="modal" style="display: none;">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="tool-modal-title">Launch Tool</h3>
                <span class="close" onclick="DITDashboard.closeModal('tool-launch-modal')">&times;</span>
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
                    onclick="DITDashboard.closeModal('tool-launch-modal')">Close</button>
            </div>
        </div>
    </div>


    <?php if (!$is_shortcode): ?>
    </body>

    </html>
<?php endif; ?>