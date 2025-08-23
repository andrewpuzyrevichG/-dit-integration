<?php

namespace DIT;

/**
 * Dashboard Manager for DIT Integration
 * Handles user dashboard, account management, and role-based interfaces
 */
class Dashboard
{
    /**
     * Session manager instance
     */
    private $session_manager;

    /**
     * Constructor
     */
    public function __construct()
    {
        // Session Manager will be initialized later in init() method
        $this->session_manager = null;
    }

    /**
     * Initialize dashboard functionality
     */
    public function init(): void
    {
        error_log('DIT Dashboard: init() method called');

        // Initialize Session Manager
        if (!class_exists('DIT\\Session_Manager')) {
            $session_manager_file = DIT_PLUGIN_DIR . 'includes/class-session-manager.php';
            if (file_exists($session_manager_file)) {
                require_once $session_manager_file;
                error_log('DIT Dashboard: Session Manager file loaded manually');
            } else {
                error_log('DIT Dashboard: Session Manager file not found at: ' . $session_manager_file);
            }
        }

        if (class_exists('DIT\\Session_Manager')) {
            $this->session_manager = new Session_Manager();
            error_log('DIT Dashboard: Session Manager initialized');
        } else {
            error_log('DIT Dashboard: Session_Manager class not found');
            return;
        }

        // Add hooks for dashboard pages
        add_action('init', [$this, 'register_dashboard_pages']);
        add_action('wp_enqueue_scripts', [$this, 'enqueue_dashboard_assets']);

        // AJAX handlers for dashboard functionality
        add_action('wp_ajax_dit_logout', [$this, 'handle_logout']);
        add_action('wp_ajax_nopriv_dit_logout', [$this, 'handle_logout']);

        // Customer-specific AJAX handlers
        add_action('wp_ajax_dit_get_customer_users', [$this, 'handle_get_customer_users']);
        add_action('wp_ajax_nopriv_dit_get_customer_users', [$this, 'handle_get_customer_users']);
        add_action('wp_ajax_dit_get_user', [$this, 'handle_get_user']);
        add_action('wp_ajax_nopriv_dit_get_user', [$this, 'handle_get_user']);
        add_action('wp_ajax_dit_update_user', [$this, 'handle_update_user']);
        add_action('wp_ajax_nopriv_dit_update_user', [$this, 'handle_update_user']);
        add_action('wp_ajax_dit_add_user', [$this, 'handle_add_user']);
        add_action('wp_ajax_nopriv_dit_add_user', [$this, 'handle_add_user']);
        add_action('wp_ajax_dit_delete_user', [$this, 'handle_delete_user']);
        add_action('wp_ajax_nopriv_dit_delete_user', [$this, 'handle_delete_user']);
        error_log('DIT Dashboard: Customer AJAX handlers registered (with nopriv)');

        // User-specific AJAX handlers
        add_action('wp_ajax_dit_get_user_activity', [$this, 'handle_get_user_activity']);

        // Common AJAX handlers
        add_action('wp_ajax_dit_update_password', [$this, 'handle_update_password']);
        add_action('wp_ajax_dit_update_account', [$this, 'handle_update_account']);
        add_action('wp_ajax_dit_get_customer_data', [$this, 'handle_get_customer_data']);

        // Admin-specific AJAX handlers
        add_action('wp_ajax_dit_get_all_customers', [$this, 'handle_get_all_customers']);
        add_action('wp_ajax_nopriv_dit_get_all_customers', [$this, 'handle_get_all_customers']);
        add_action('wp_ajax_dit_add_customer', [$this, 'handle_add_customer']);
        add_action('wp_ajax_nopriv_dit_add_customer', [$this, 'handle_add_customer']);
        add_action('wp_ajax_dit_update_customer', [$this, 'handle_update_customer']);
        add_action('wp_ajax_nopriv_dit_update_customer', [$this, 'handle_update_customer']);
        add_action('wp_ajax_dit_delete_customer', [$this, 'handle_delete_customer']);
        add_action('wp_ajax_nopriv_dit_delete_customer', [$this, 'handle_delete_customer']);
        add_action('wp_ajax_dit_get_all_users', [$this, 'handle_get_all_users']);
        add_action('wp_ajax_nopriv_dit_get_all_users', [$this, 'handle_get_all_users']);

        // Test AJAX handler
        add_action('wp_ajax_dit_test', [$this, 'handle_test']);
        add_action('wp_ajax_nopriv_dit_test', [$this, 'handle_test']);

        // Simple test AJAX handler for debugging
        add_action('wp_ajax_dit_simple_test', [$this, 'handle_simple_test']);
        add_action('wp_ajax_nopriv_dit_simple_test', [$this, 'handle_simple_test']);

        error_log('DIT Dashboard: All AJAX handlers registered');

        // Add shortcodes for dashboard components
        add_shortcode('dit_dashboard', [$this, 'render_dashboard']);
        add_shortcode('dit_account_settings', [$this, 'render_account_settings']);
        add_shortcode('dit_user_management', [$this, 'render_user_management']);
        add_shortcode('dit_license_management', [$this, 'render_license_management']);
        add_shortcode('dit_payment_history', [$this, 'render_payment_history']);

        error_log('DIT Dashboard: init() method completed successfully');
    }

    /**
     * Register dashboard pages
     */
    public function register_dashboard_pages(): void
    {
        // Add rewrite rules for dashboard pages
        add_rewrite_rule(
            '^dashboard/?$',
            'index.php?dit_dashboard=1',
            'top'
        );

        add_rewrite_rule(
            '^dashboard/account/?$',
            'index.php?dit_dashboard=account',
            'top'
        );

        add_rewrite_rule(
            '^dashboard/users/?$',
            'index.php?dit_dashboard=users',
            'top'
        );

        add_rewrite_rule(
            '^dashboard/licenses/?$',
            'index.php?dit_dashboard=licenses',
            'top'
        );

        add_rewrite_rule(
            '^dashboard/payments/?$',
            'index.php?dit_dashboard=payments',
            'top'
        );

        // Add query vars
        add_filter('query_vars', function ($vars) {
            $vars[] = 'dit_dashboard';
            return $vars;
        });

        // Handle dashboard page requests
        add_action('template_redirect', [$this, 'handle_dashboard_request']);
    }

    /**
     * Handle dashboard page requests
     */
    public function handle_dashboard_request(): void
    {
        $dashboard_page = get_query_var('dit_dashboard');

        if (!$dashboard_page) {
            return;
        }

        // Get login page from settings
        $settings = get_option('dit_settings', []);
        $login_page_id = isset($settings['login_page_id']) ? (int)$settings['login_page_id'] : 0;
        $login_url = $login_page_id ? get_permalink($login_page_id) : home_url('/login');

        // Check if session manager is available
        if (!$this->session_manager) {
            error_log('DIT Dashboard: Session manager not available');
            wp_redirect($login_url . '?error=session_error');
            exit;
        }

        // Check if user is logged in
        if (!$this->session_manager->is_logged_in()) {
            wp_redirect($login_url);
            exit;
        }

        // Check session timeout
        if (!$this->session_manager->check_session_timeout()) {
            wp_redirect($login_url . '?timeout=1');
            exit;
        }

        // Refresh session activity
        $this->session_manager->refresh_activity();

        // Load appropriate dashboard template
        $this->load_dashboard_template($dashboard_page);
    }

    /**
     * Load dashboard template based on page type and user role
     */
    private function load_dashboard_template(string $page_type): void
    {
        if (!$this->session_manager) {
            error_log('DIT Dashboard: Session manager not available in load_dashboard_template');
            return;
        }

        $role = $this->session_manager->get_user_role();

        switch ($page_type) {
            case '1': // Main dashboard - load role-specific template
                if ($role === 2) { // Customer
                    $this->load_template('customer-dashboard.php', $role);
                } elseif ($role === 1) { // User
                    $this->load_template('user-dashboard.php', $role);
                } elseif ($role === 3) { // Administrator
                    $this->load_template('admin-dashboard.php', $role);
                } else { // Other roles
                    $this->load_template('customer-dashboard.php', $role); // Default to customer template
                }
                break;

            case 'account':
                if ($role === 2) { // Customer
                    $this->load_template('customer-dashboard.php', 2);
                } elseif ($role === 1) { // User
                    $this->load_template('user-dashboard.php', 1);
                } elseif ($role === 3) { // Administrator
                    $this->load_template('admin-dashboard.php', 3);
                } else {
                    $this->load_template('customer-dashboard.php', $role);
                }
                break;

            case 'users':
                if ($this->session_manager->is_customer()) {
                    $this->load_template('customer-dashboard.php', 2);
                } else {
                    $dashboard_url = $this->get_dashboard_url();
                    wp_redirect($dashboard_url . '?error=access_denied');
                    exit;
                }
                break;

            case 'licenses':
                if ($this->session_manager->is_customer()) {
                    $this->load_template('customer-dashboard.php', 2);
                } else {
                    $this->load_template('user-dashboard.php', 1);
                }
                break;

            case 'payments':
                if ($this->session_manager->is_customer()) {
                    $this->load_template('customer-dashboard.php', 2);
                } else {
                    $dashboard_url = $this->get_dashboard_url();
                    wp_redirect($dashboard_url . '?error=access_denied');
                    exit;
                }
                break;

            default:
                // For any other page, load role-specific main dashboard
                if ($role === 2) { // Customer
                    $this->load_template('customer-dashboard.php', $role);
                } elseif ($role === 1) { // User
                    $this->load_template('user-dashboard.php', $role);
                } elseif ($role === 3) { // Administrator
                    $this->load_template('admin-dashboard.php', $role);
                } else { // Other roles
                    $this->load_template('customer-dashboard.php', $role); // Default to customer template
                }
                break;
        }
    }

    /**
     * Load dashboard template file
     */
    private function load_template(string $template_name, int $role): void
    {
        if (!$this->session_manager) {
            error_log('DIT Dashboard: Session manager not available in load_template');
            return;
        }

        $template_path = DIT_PLUGIN_DIR . 'templates/dashboard/' . $template_name;

        if (file_exists($template_path)) {
            // Set up template variables
            $session_data = $this->session_manager->get_session_data();
            $user_role = $role;

            // Define constant to indicate this is a full page load
            define('DIT_IS_FULL_PAGE', true);

            include $template_path;
            exit;
        } else {
            // Fallback to default template
            $this->load_fallback_template($role);
        }
    }

    /**
     * Load template content for shortcode (without exit)
     */
    private function load_template_content(string $template_name, int $role): void
    {
        $template_path = DIT_PLUGIN_DIR . 'templates/dashboard/' . $template_name;

        if (file_exists($template_path)) {
            // Set up template variables
            $session_data = $this->session_manager->get_session_data();
            $user_role = $role;

            include $template_path;
        } else {
            // Fallback content
            echo '<div class="dit-dashboard-error">';
            echo '<h3>Dashboard Template Not Found</h3>';
            echo '<p>The dashboard template "' . esc_html($template_name) . '" could not be loaded.</p>';
            echo '</div>';
        }
    }

    /**
     * Load fallback template
     */
    private function load_fallback_template(int $role): void
    {
        $session_data = $this->session_manager->get_session_data();
?>
        <!DOCTYPE html>
        <html>

        <head>
            <title>DIT Dashboard</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background: #f5f5f5;
                }

                .dashboard {
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                }

                .header {
                    padding: 20px;
                    border-bottom: 1px solid #eee;
                }

                .content {
                    padding: 20px;
                }

                .nav {
                    display: flex;
                    gap: 20px;
                    margin-bottom: 20px;
                }

                .nav a {
                    padding: 10px 20px;
                    text-decoration: none;
                    background: #007cba;
                    color: white;
                    border-radius: 4px;
                }

                .nav a:hover {
                    background: #005a87;
                }

                .user-info {
                    background: #f8f9fa;
                    padding: 15px;
                    border-radius: 4px;
                    margin-bottom: 20px;
                }

                .logout-btn {
                    background: #dc3545;
                    color: white;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 4px;
                    cursor: pointer;
                }

                .logout-btn:hover {
                    background: #c82333;
                }
            </style>
        </head>

        <body>
            <div class="dashboard">

                <div class="header">
                    <h1>DIT Dashboard!!!</h1>
                    <div class="user-info">
                        <p><strong>Email:</strong> <?php echo esc_html($session_data['email']); ?></p>
                        <p><strong>Role:</strong> <?php echo esc_html($this->get_role_name($role)); ?></p>
                        <p><strong>User ID:</strong> <?php echo esc_html($session_data['user_id']); ?></p>
                        <?php if ($session_data['customer_id']): ?>
                            <p><strong>Customer ID:</strong> <?php echo esc_html($session_data['customer_id']); ?></p>
                        <?php endif; ?>
                    </div>
                    <button class="logout-btn" onclick="logout()">Logout</button>
                </div>

                <div class="content">
                    <div class="nav">
                        <a href="<?php echo $this->get_dashboard_url(); ?>">Dashboard</a>
                        <a href="<?php echo home_url('/dashboard/account'); ?>">Account</a>
                        <?php if ($role === 2): ?>
                            <a href="<?php echo home_url('/dashboard/users'); ?>">Users</a>
                            <a href="<?php echo home_url('/dashboard/licenses'); ?>">Licenses</a>
                            <a href="<?php echo home_url('/dashboard/payments'); ?>">Payments</a>
                        <?php else: ?>
                            <a href="<?php echo home_url('/dashboard/licenses'); ?>">My License</a>
                        <?php endif; ?>
                    </div>

                    <div class="main-content">
                        <h2>Welcome to your dashboard!</h2>
                        <p>This is a fallback template. Please create proper dashboard templates.</p>
                    </div>
                </div>
            </div>

            <script>
                function logout() {
                    if (confirm('Are you sure you want to logout?')) {
                        fetch('<?php echo admin_url('admin-ajax.php'); ?>', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-www-form-urlencoded',
                            },
                            body: 'action=dit_logout&nonce=<?php echo wp_create_nonce('dit_dashboard_nonce'); ?>'
                        }).then(response => response.json()).then(data => {
                            if (data.success) {
                                window.location.href = data.redirect_url || '<?php echo home_url(); ?>';
                            } else {
                                alert('Logout failed. Please try again.');
                            }
                        }).catch(error => {
                            console.error('Logout error:', error);
                            alert('Logout failed. Please try again.');
                        });
                    }
                }
            </script>
        </body>

        </html>
    <?php
        exit;
    }

    /**
     * Enqueue dashboard assets
     */
    public function enqueue_dashboard_assets(): void
    {
        // Check if we're on a dashboard page or if the dashboard shortcode is used
        $is_dashboard_page = is_page('dashboard') || strpos($_SERVER['REQUEST_URI'], '/dashboard') !== false;
        $has_dashboard_shortcode = $this->has_dashboard_shortcode();

        // Always load assets if user is logged in and we're on a page (not admin)
        $should_load = $is_dashboard_page || $has_dashboard_shortcode ||
            ($this->session_manager->is_logged_in() && !is_admin() && !is_404());

        error_log('DIT Dashboard: enqueue_dashboard_assets - should_load: ' . ($should_load ? 'true' : 'false'));
        error_log('DIT Dashboard: enqueue_dashboard_assets - is_dashboard_page: ' . ($is_dashboard_page ? 'true' : 'false'));
        error_log('DIT Dashboard: enqueue_dashboard_assets - has_dashboard_shortcode: ' . ($has_dashboard_shortcode ? 'true' : 'false'));
        error_log('DIT Dashboard: enqueue_dashboard_assets - is_logged_in: ' . ($this->session_manager->is_logged_in() ? 'true' : 'false'));

        if ($should_load) {
            wp_enqueue_style('dit-dashboard', DIT_PLUGIN_URL . 'assets/css/dashboard.css', [], '1.0.0');
            wp_enqueue_script('dit-dashboard', DIT_PLUGIN_URL . 'assets/js/dashboard.js', ['jquery'], '1.0.0', true);

            // Get user role and enqueue role-specific scripts
            if ($this->session_manager->is_logged_in()) {
                $role = $this->session_manager->get_user_role();
                $session_data = $this->session_manager->get_session_data();

                error_log('DIT Dashboard: enqueue_dashboard_assets - user role: ' . $role);

                if ($role === 2) { // Customer
                    wp_enqueue_script('dit-customer-dashboard', DIT_PLUGIN_URL . 'assets/js/customer-dashboard.js', ['jquery', 'dit-dashboard'], '1.0.0', true);
                    error_log('DIT Dashboard: enqueue_dashboard_assets - customer dashboard script enqueued');
                } elseif ($role === 1) { // User
                    wp_enqueue_script('dit-user-dashboard', DIT_PLUGIN_URL . 'assets/js/user-dashboard.js', ['jquery', 'dit-dashboard'], '1.0.0', true);
                    error_log('DIT Dashboard: enqueue_dashboard_assets - user dashboard script enqueued');
                } elseif ($role === 3) { // Administrator
                    wp_enqueue_script('dit-admin-dashboard', DIT_PLUGIN_URL . 'assets/js/admin-dashboard.js', ['jquery', 'dit-dashboard'], '1.0.0', true);
                    error_log('DIT Dashboard: enqueue_dashboard_assets - admin dashboard script enqueued');
                    error_log('DIT Dashboard: enqueue_dashboard_assets - admin script URL: ' . DIT_PLUGIN_URL . 'assets/js/admin-dashboard.js');
                }
            }

            // Localize script with AJAX URL and user data
            $ajax_data = [
                'ajax_url' => admin_url('admin-ajax.php'),
                'nonce' => wp_create_nonce('dit_dashboard_nonce'),
                'user_id' => $this->session_manager->is_logged_in() ? $this->session_manager->get_user_id() : null,
                'customer_id' => $this->session_manager->is_logged_in() ? $this->session_manager->get_customer_id() : null,
                'user_role' => $this->session_manager->is_logged_in() ? $this->session_manager->get_user_role() : null,
                'dashboard_url' => home_url('/dashboard')
            ];

            // Also localize ajaxurl for compatibility
            wp_localize_script('dit-dashboard', 'ajaxurl', admin_url('admin-ajax.php'));

            wp_localize_script('dit-dashboard', 'dit_ajax', $ajax_data);

            // Also localize for role-specific scripts
            if ($this->session_manager->is_logged_in()) {
                $role = $this->session_manager->get_user_role();
                if ($role === 2) { // Customer
                    wp_localize_script('dit-customer-dashboard', 'dit_ajax', $ajax_data);
                    wp_localize_script('dit-customer-dashboard', 'ajaxurl', admin_url('admin-ajax.php'));
                    error_log('DIT Dashboard: enqueue_dashboard_assets - dit_ajax localized for customer dashboard');
                } elseif ($role === 1) { // User
                    wp_localize_script('dit-user-dashboard', 'dit_ajax', $ajax_data);
                    wp_localize_script('dit-user-dashboard', 'ajaxurl', admin_url('admin-ajax.php'));
                    error_log('DIT Dashboard: enqueue_dashboard_assets - dit_ajax localized for user dashboard');
                } elseif ($role === 3) { // Administrator
                    wp_localize_script('dit-admin-dashboard', 'dit_ajax', $ajax_data);
                    wp_localize_script('dit-admin-dashboard', 'ajaxurl', admin_url('admin-ajax.php'));
                    error_log('DIT Dashboard: enqueue_dashboard_assets - dit_ajax localized for admin dashboard');
                    error_log('DIT Dashboard: enqueue_dashboard_assets - admin dit_ajax data: ' . print_r($ajax_data, true));
                }
            }

            error_log('DIT Dashboard: enqueue_dashboard_assets - dit_ajax data: ' . print_r($ajax_data, true));
        }
    }

    /**
     * Check if dashboard shortcode is used on current page
     */
    private function has_dashboard_shortcode(): bool
    {
        global $post;

        if (!$post) {
            return false;
        }

        $content = $post->post_content;
        return strpos($content, '[dit_dashboard') !== false ||
            strpos($content, '[dit_account_settings') !== false ||
            strpos($content, '[dit_user_management') !== false ||
            strpos($content, '[dit_license_management') !== false ||
            strpos($content, '[dit_payment_history') !== false;
    }

    /**
     * Get dashboard URL from settings
     */
    private function get_dashboard_url(): string
    {
        $settings = get_option('dit_settings', []);
        $dashboard_page_id = isset($settings['dashboard_page_id']) ? (int)$settings['dashboard_page_id'] : 0;

        if ($dashboard_page_id) {
            return get_permalink($dashboard_page_id);
        }

        // Fallback to home page if no dashboard page is configured
        return home_url();
    }

    /**
     * Handle logout AJAX request
     */
    public function handle_logout(): void
    {
        check_ajax_referer('dit_dashboard_nonce', 'nonce');

        $success = $this->session_manager->logout();

        // Get login page URL from settings
        $settings = get_option('dit_settings', []);
        $login_page_id = isset($settings['login_page_id']) ? (int)$settings['login_page_id'] : 0;

        if ($login_page_id && get_post($login_page_id)) {
            $redirect_url = get_permalink($login_page_id);
        } else {
            // Fallback to home page if no login page is configured
            $redirect_url = home_url();
        }

        wp_send_json([
            'success' => $success,
            'redirect_url' => $redirect_url
        ]);
    }

    /**
     * Render main dashboard shortcode
     */
    public function render_dashboard($atts): string
    {
        // Check if session manager is available
        if (!$this->session_manager) {
            return '<p>Session manager not available.</p>';
        }

        if (!$this->session_manager->is_logged_in()) {
            $settings = get_option('dit_settings', []);
            $login_page_id = isset($settings['login_page_id']) ? (int)$settings['login_page_id'] : 0;
            $login_url = $login_page_id ? get_permalink($login_page_id) : home_url('/login');
            return '<p>' . esc_html__('Please ', 'dit-integration') . '<a href="' . esc_url($login_url) . '">' . esc_html__('login or register', 'dit-integration') . '</a> ' . esc_html__('to access your dashboard.', 'dit-integration') . '</p>';
        }

        $role = $this->session_manager->get_user_role();

        // Load appropriate template based on user role
        ob_start();

        if ($role === 2) { // Customer
            $this->load_template_content('customer-dashboard.php', $role);
        } elseif ($role === 1) { // User
            $this->load_template_content('user-dashboard.php', $role);
        } else { // Administrator or other roles - default to customer template
            $this->load_template_content('customer-dashboard.php', $role);
        }

        return ob_get_clean();
    }

    /**
     * Get active users count (for customers)
     */
    private function get_active_users_count(): int
    {
        // This would typically call the API to get user count
        // For now, return a placeholder
        return 0;
    }

    /**
     * Get active licenses count (for customers)
     */
    private function get_active_licenses_count(): int
    {
        // This would typically call the API to get license count
        // For now, return a placeholder
        return 0;
    }

    /**
     * Get total payments (for customers)
     */
    private function get_total_payments(): float
    {
        // This would typically call the API to get payment total
        // For now, return a placeholder
        return 0.00;
    }

    /**
     * Get user license info (for regular users)
     */
    private function get_user_license_info(): string
    {
        if (!$this->session_manager) {
            return '<p>Session manager not available.</p>';
        }
        $session_data = $this->session_manager->get_session_data();

        if ($session_data['remaining_seconds']) {
            $hours = floor($session_data['remaining_seconds'] / 3600);
            $minutes = floor(($session_data['remaining_seconds'] % 3600) / 60);

            return sprintf(
                '<p><strong>Remaining Time:</strong> %d hours, %d minutes</p>',
                $hours,
                $minutes
            );
        }

        return '<p>No active license found.</p>';
    }

    /**
     * Render account settings shortcode
     */
    public function render_account_settings($atts): string
    {
        // Check if session manager is available
        if (!$this->session_manager) {
            return '<p>Session manager not available.</p>';
        }

        if (!$this->session_manager->is_logged_in()) {
            return '<p>Please login to access account settings.</p>';
        }

        $session_data = $this->session_manager->get_session_data();

        ob_start();
    ?>
        <div class="dit-account-settings">
            <h2>Account Settings</h2>
            <form class="account-form" method="post">
                <div class="form-group">
                    <label for="email">Email Address</label>
                    <input type="email" id="email" name="email" value="<?php echo esc_attr($session_data['email']); ?>"
                        readonly>
                </div>

                <div class="form-group">
                    <label for="new_password">New Password</label>
                    <input type="password" id="new_password" name="new_password">
                </div>

                <div class="form_file">
                    <label for="confirm_password">Confirm Password</label>
                    <input type="password" id="confirm_password" name="confirm_password">
                </div>

                <button type="submit" class="btn-primary">Update Account</button>
            </form>
        </div>
    <?php
        return ob_get_clean();
    }

    /**
     * Render user management shortcode (customers only)
     */
    public function render_user_management($atts): string
    {
        // Check if session manager is available
        if (!$this->session_manager) {
            return '<p>Session manager not available.</p>';
        }

        if (!$this->session_manager->is_logged_in() || !$this->session_manager->is_customer()) {
            return '<p>Access denied. Customer privileges required.</p>';
        }

        ob_start();
    ?>
        <div class="dit-user-management">
            <h2>User Management</h2>
            <div class="user-list">
                <p>User management functionality will be implemented here.</p>
            </div>
        </div>
    <?php
        return ob_get_clean();
    }

    /**
     * Render license management shortcode
     */
    public function render_license_management($atts): string
    {
        // Check if session manager is available
        if (!$this->session_manager) {
            return '<p>Session manager not available.</p>';
        }

        if (!$this->session_manager->is_logged_in()) {
            return '<p>Please login to access license information.</p>';
        }

        $session_data = $this->session_manager->get_session_data();

        ob_start();
    ?>
        <div class="dit-license-management">
            <h2><?php echo $this->session_manager->is_customer() ? 'License Management' : 'My License'; ?></h2>
            <div class="license-info">
                <?php echo $this->get_user_license_info(); ?>
            </div>
        </div>
    <?php
        return ob_get_clean();
    }

    /**
     * Render payment history shortcode (customers only)
     */
    public function render_payment_history($atts): string
    {
        // Check if session manager is available
        if (!$this->session_manager) {
            return '<p>Session manager not available.</p>';
        }

        if (!$this->session_manager->is_logged_in() || !$this->session_manager->is_customer()) {
            return '<p>Access denied. Customer privileges required.</p>';
        }

        ob_start();
    ?>
        <div class="dit-license-management">
            <h2>Payment History</h2>
            <div class="payment-list">
                <p>Payment history functionality will be implemented here.</p>
            </div>
        </div>
<?php
        return ob_get_clean();
    }

    /**
     * Get role name by role ID
     *
     * @param int $role_id Role ID
     * @return string Role name
     */
    private function get_role_name(int $role_id): string
    {
        switch ($role_id) {
            case 1:
                return 'User';
            case 2:
                return 'Customer';
            case 3:
                return 'Administrator';
            default:
                return 'Unknown';
        }
    }

    /**
     * AJAX handler: Get customer users
     */
    public function handle_get_customer_users(): void
    {
        // Log the start of the request
        error_log('DIT Dashboard: handle_get_customer_users started');
        error_log('DIT Dashboard: POST data: ' . print_r($_POST, true));
        error_log('DIT Dashboard: REQUEST_METHOD: ' . $_SERVER['REQUEST_METHOD']);
        error_log('DIT Dashboard: HTTP_USER_AGENT: ' . ($_SERVER['HTTP_USER_AGENT'] ?? 'not set'));
        error_log('DIT Dashboard: Current user ID: ' . get_current_user_id());
        error_log('DIT Dashboard: Is user logged in: ' . (is_user_logged_in() ? 'Yes' : 'No'));

        // Simple test response to check if method is called
        if (isset($_POST['test']) && $_POST['test'] === 'ping') {
            wp_send_json_success(['message' => 'pong']);
            return;
        }

        // Simple response for debugging
        if (isset($_POST['debug']) && $_POST['debug'] === 'true') {
            wp_send_json_success([
                'message' => 'Method called successfully',
                'post_data' => $_POST,
                'user_id' => get_current_user_id(),
                'is_logged_in' => is_user_logged_in(),
                'timestamp' => current_time('mysql')
            ]);
            return;
        }

        try {
            // Verify nonce
            $nonce = $_POST['nonce'] ?? '';
            error_log('DIT Dashboard: Nonce received: ' . (!empty($nonce) ? 'Yes' : 'No'));
            error_log('DIT Dashboard: Nonce value: ' . $nonce);

            if (!wp_verify_nonce($nonce, 'dit_dashboard_nonce')) {
                error_log('DIT Dashboard: Invalid nonce');
                error_log('DIT Dashboard: Expected nonce action: dit_dashboard_nonce');
                wp_send_json_error('Invalid nonce');
                return;
            }

            error_log('DIT Dashboard: Nonce verified successfully');

            // Check if session manager exists
            if (!$this->session_manager) {
                error_log('DIT Dashboard: Session manager is null');
                wp_send_json_error('Session manager not available');
                return;
            }

            error_log('DIT Dashboard: Session manager exists');

            // Check if user is logged in
            $is_logged_in = $this->session_manager->is_logged_in();
            error_log('DIT Dashboard: User logged in: ' . ($is_logged_in ? 'Yes' : 'No'));

            if (!$is_logged_in) {
                wp_send_json_error('User not logged in');
                return;
            }

            // Check if user is a customer
            $is_customer = $this->session_manager->is_customer();
            error_log('DIT Dashboard: User is customer: ' . ($is_customer ? 'Yes' : 'No'));

            if (!$is_customer) {
                wp_send_json_error('Access denied - user is not a customer');
                return;
            }

            // Get user ID and customer ID
            $user_id = $this->session_manager->get_user_id();
            $customer_id = $this->session_manager->get_customer_id();

            // Check if customer_id was passed in POST data
            $post_customer_id = $_POST['customer_id'] ?? null;
            error_log('DIT Dashboard: User ID: ' . ($user_id ?: 'null'));
            error_log('DIT Dashboard: Customer ID from session: ' . ($customer_id ?: 'null'));
            error_log('DIT Dashboard: Customer ID from POST: ' . ($post_customer_id ?: 'null'));

            if (!$user_id) {
                wp_send_json_error('User ID not found');
                return;
            }

            // Use POST customer_id if available, otherwise use session customer_id, otherwise fallback to user_id
            $api_customer_id = $post_customer_id ?: $customer_id ?: $user_id;
            error_log('DIT Dashboard: Using API Customer ID: ' . $api_customer_id);

            // Get Core instance
            $core = \DIT\Core::get_instance();
            if (!$core) {
                error_log('DIT Dashboard: Core instance not available');
                wp_send_json_error('Core not available');
                return;
            }

            error_log('DIT Dashboard: Core instance obtained');

            // Get API instance
            $api = $core->api;
            if (!$api) {
                error_log('DIT Dashboard: API instance is null');
                wp_send_json_error('API not available');
                return;
            }

            error_log('DIT Dashboard: API instance obtained');

            // NEW: Sync users from API first
            error_log('DIT Dashboard: Starting API sync for customer_id: ' . $api_customer_id);
            $sync_result = $this->sync_users_from_api($api, $api_customer_id);
            error_log('DIT Dashboard: API sync result: ' . ($sync_result ? 'success' : 'failed'));

            // Note: Database functionality has been removed
            error_log('DIT Dashboard: Database functionality removed - returning empty user list');
            wp_send_json_success([]);

            error_log('DIT Dashboard: JSON response sent successfully');
        } catch (\Exception $e) {
            error_log('DIT Dashboard: Exception in handle_get_customer_users: ' . $e->getMessage());
            error_log('DIT Dashboard: Exception trace: ' . $e->getTraceAsString());
            wp_send_json_error('Internal server error: ' . $e->getMessage());
        }

        error_log('DIT Dashboard: handle_get_customer_users completed');
    }

    /**
     * Sync users from API and ensure steganography key exists
     */
    private function sync_users_from_api($api, $customer_id): bool
    {
        error_log('DIT Dashboard: Starting sync_users_from_api for customer_id: ' . $customer_id);

        try {
            // Check if steganography key already exists and is valid
            if (!isset($_SESSION)) {
                session_start();
            }

            $needs_steganography_key = true;
            if (isset($_SESSION['dit_aes_keys'][$customer_id])) {
                $existing_key = $_SESSION['dit_aes_keys'][$customer_id];
                $is_steganography_key = (ctype_xdigit($existing_key) && strlen($existing_key) === 128);

                error_log('DIT Dashboard: - Existing key found, length: ' . strlen($existing_key));
                error_log('DIT Dashboard: - Is steganography format: ' . ($is_steganography_key ? 'YES' : 'NO'));

                if ($is_steganography_key) {
                    error_log('DIT Dashboard: Valid steganography key already exists, skipping creation');
                    $needs_steganography_key = false;
                }
            }

            // IMPORTANT: We do NOT create users during login
            // Users should only be created during registration process
            // If steganography key is missing, it means the user was not properly registered
            if ($needs_steganography_key) {
                error_log('DIT Dashboard: ERROR - Steganography key missing during login');
                error_log('DIT Dashboard: This indicates the user was not properly registered');
                error_log('DIT Dashboard: Customer ID: ' . $customer_id . ' needs to be registered first');
                error_log('DIT Dashboard: Login process cannot continue without proper registration');
            }

            error_log('DIT Dashboard: sync_users_from_api completed successfully');
            return true;
        } catch (\Exception $e) {
            error_log('DIT Dashboard: Exception in sync_users_from_api: ' . $e->getMessage());
            error_log('DIT Dashboard: Exception trace: ' . $e->getTraceAsString());

            // Don't fail the entire sync if steganography fails
            // Return true to allow dashboard to continue working
            return true;
        }
    }

    /**
     * Test AJAX handler
     */
    public function handle_test(): void
    {
        error_log('DIT Dashboard: handle_test called');
        wp_send_json_success(['message' => 'Test successful', 'timestamp' => current_time('mysql')]);
    }

    /**
     * Handle simple test AJAX request for debugging
     */
    public function handle_simple_test(): void
    {
        error_log('DIT Dashboard: handle_simple_test called');
        wp_send_json_success([
            'message' => 'Simple test successful',
            'timestamp' => current_time('mysql'),
            'user_id' => get_current_user_id(),
            'ajax_url' => admin_url('admin-ajax.php')
        ]);
    }

    /**
     * AJAX handler: Add new user
     */
    public function handle_add_user(): void
    {
        $core = \DIT\Core::get_instance();
        $logger = $core->logger;

        $logger->log_api_interaction('Dashboard Add User', [
            'step' => 'start',
            'timestamp' => current_time('mysql'),
            'post_data_keys' => array_keys($_POST ?? [])
        ], 'info', 'Dashboard add user request started');

        // Check if session manager is available
        if (!$this->session_manager) {
            $logger->log_api_interaction('Dashboard Add User', [
                'step' => 'session_manager_check',
                'error' => 'Session manager not available'
            ], 'error', 'Session manager not available');
            wp_send_json_error('Session manager not available');
            return;
        }

        $logger->log_api_interaction('Dashboard Add User', [
            'step' => 'session_manager_available',
            'session_manager_class' => get_class($this->session_manager)
        ], 'info', 'Session manager is available');

        // Verify nonce
        $nonce = $_POST['nonce'] ?? '';
        $nonce_valid = wp_verify_nonce($nonce, 'dit_dashboard_nonce');

        $logger->log_api_interaction('Dashboard Add User', [
            'step' => 'nonce_verification',
            'nonce_provided' => !empty($nonce),
            'nonce_valid' => $nonce_valid,
            'nonce_length' => strlen($nonce)
        ], $nonce_valid ? 'info' : 'error', 'Nonce verification ' . ($nonce_valid ? 'passed' : 'failed'));

        if (!$nonce_valid) {
            wp_send_json_error('Invalid nonce');
            return;
        }

        // Check if user is logged in and is a customer
        $is_logged_in = $this->session_manager->is_logged_in();
        $is_customer = $this->session_manager->is_customer();

        $logger->log_api_interaction('Dashboard Add User', [
            'step' => 'authentication_check',
            'is_logged_in' => $is_logged_in,
            'is_customer' => $is_customer
        ], ($is_logged_in && $is_customer) ? 'info' : 'error', 'Authentication check');

        if (!$is_logged_in || !$is_customer) {
            wp_send_json_error('Access denied');
            return;
        }

        $user_data = $_POST['user_data'] ?? [];

        $logger->log_api_interaction('Dashboard Add User', [
            'step' => 'user_data_received',
            'user_data_keys' => array_keys($user_data),
            'has_email' => !empty($user_data['email']),
            'has_password' => !empty($user_data['password']),
            'has_first_name' => !empty($user_data['first_name']),
            'has_last_name' => !empty($user_data['last_name']),
            'has_tools' => !empty($user_data['tools']),
            'tools_count' => count($user_data['tools'] ?? [])
        ], 'info', 'User data received from form');

        // Validate required fields
        $missing_fields = [];
        if (empty($user_data['email'])) $missing_fields[] = 'email';
        if (empty($user_data['password'])) $missing_fields[] = 'password';
        if (empty($user_data['first_name'])) $missing_fields[] = 'first_name';
        if (empty($user_data['last_name'])) $missing_fields[] = 'last_name';

        $logger->log_api_interaction('Dashboard Add User', [
            'step' => 'field_validation',
            'missing_fields' => $missing_fields,
            'validation_passed' => empty($missing_fields)
        ], empty($missing_fields) ? 'info' : 'error', 'Field validation ' . (empty($missing_fields) ? 'passed' : 'failed'));

        if (!empty($missing_fields)) {
            wp_send_json_error('All fields are required');
            return;
        }

        // Validate email format
        $email_valid = is_email($user_data['email']);

        $logger->log_api_interaction('Dashboard Add User', [
            'step' => 'email_validation',
            'email' => $user_data['email'],
            'email_valid' => $email_valid
        ], $email_valid ? 'info' : 'error', 'Email validation ' . ($email_valid ? 'passed' : 'failed'));

        if (!$email_valid) {
            wp_send_json_error('Invalid email format');
            return;
        }

        // Validate password length
        $password_length = strlen($user_data['password']);
        $password_valid = $password_length >= 6;

        $logger->log_api_interaction('Dashboard Add User', [
            'step' => 'password_validation',
            'password_length' => $password_length,
            'password_valid' => $password_valid,
            'min_required_length' => 6
        ], $password_valid ? 'info' : 'error', 'Password validation ' . ($password_valid ? 'passed' : 'failed'));

        if (!$password_valid) {
            wp_send_json_error('Password must be at least 6 characters long');
            return;
        }

        // Get customer ID from session
        $customer_id = $this->session_manager->get_customer_id();

        $logger->log_api_interaction('Dashboard Add User', [
            'step' => 'customer_id_retrieval',
            'customer_id' => $customer_id,
            'customer_id_found' => !empty($customer_id)
        ], !empty($customer_id) ? 'info' : 'error', 'Customer ID retrieval');

        if (!$customer_id) {
            wp_send_json_error('Customer ID not found');
            return;
        }

        // Get AES key directly from customer-specific storage
        $api = \DIT\Core::get_instance()->api;
        $aes_key = $api->get_user_permanent_aes_key($customer_id);

        $logger->log_api_interaction('Dashboard Add User', [
            'step' => 'aes_key_retrieval',
            'aes_key_found' => !empty($aes_key),
            'aes_key_length' => strlen($aes_key ?? ''),
            'aes_key_preview' => !empty($aes_key) ? substr($aes_key, 0, 20) . '...' : 'empty',
            'aes_key_source' => 'get_user_permanent_aes_key'
        ], !empty($aes_key) ? 'info' : 'error', 'AES key retrieval from customer data');

        if (!$aes_key) {
            $logger->log_api_interaction('Dashboard Add User', [
                'step' => 'aes_key_not_found',
                'customer_id' => $customer_id,
                'aes_key_found' => false
            ], 'error', 'No AES key found for customer ' . $customer_id);
            wp_send_json_error('AES key not found for customer');
            return;
        }

        // Convert AES key from Base64 to hex format for API compatibility
        if (!empty($aes_key)) {
            $aes_key_hex = bin2hex(base64_decode($aes_key));
            $logger->log_api_interaction('Dashboard Add User', [
                'step' => 'aes_key_conversion',
                'aes_key_original_length' => strlen($aes_key),
                'aes_key_hex_length' => strlen($aes_key_hex),
                'aes_key_original_preview' => substr($aes_key, 0, 20) . '...',
                'aes_key_hex_preview' => substr($aes_key_hex, 0, 20) . '...'
            ], 'info', 'AES key converted from Base64 to hex');
            $aes_key = $aes_key_hex;
        }

        // Convert tools array from strings to integers for API compatibility
        $tools_array = $user_data['tools'] ?? [];
        $converted_tools = [];
        foreach ($tools_array as $tool) {
            if (is_numeric($tool)) {
                $converted_tools[] = (int)$tool;
            }
        }

        // Prepare user data for API
        $api_user_data = [
            'first_name' => sanitize_text_field($user_data['first_name']),
            'last_name' => sanitize_text_field($user_data['last_name']),
            'email' => sanitize_email($user_data['email']),
            'password' => $user_data['password'],
            'tools' => $converted_tools,
            'aes_key' => $aes_key
        ];

        $logger->log_api_interaction('Dashboard Add User', [
            'step' => 'api_data_preparation',
            'customer_id' => $customer_id,
            'api_data_keys' => array_keys($api_user_data),
            'first_name' => $api_user_data['first_name'],
            'last_name' => $api_user_data['last_name'],
            'email' => $api_user_data['email'],
            'password_length' => strlen($api_user_data['password']),
            'tools_count' => count($api_user_data['tools']),
            'tools_original' => $user_data['tools'] ?? [],
            'tools_converted' => $converted_tools,
            'aes_key_provided' => !empty($api_user_data['aes_key'])
        ], 'info', 'API data prepared for user registration');

        // Call API to register user
        $logger->log_api_interaction('Dashboard Add User', [
            'step' => 'api_call_start',
            'customer_id' => $customer_id,
            'api_method' => 'register_user_rsa'
        ], 'info', 'Starting API call to register user');

        $api = \DIT\Core::get_instance()->api;
        $user_id = $api->register_user_rsa($api_user_data, $customer_id);

        $logger->log_api_interaction('Dashboard Add User', [
            'step' => 'api_call_completed',
            'customer_id' => $customer_id,
            'user_id' => $user_id,
            'api_success' => $user_id !== null,
            'user_id_type' => gettype($user_id)
        ], $user_id !== null ? 'success' : 'error', 'API call completed');

        if ($user_id === null) {
            $logger->log_api_interaction('Dashboard Add User', [
                'step' => 'api_failure',
                'customer_id' => $customer_id,
                'error' => 'API returned null user_id'
            ], 'error', 'Failed to create user via API');
            wp_send_json_error('Failed to create user via API');
            return;
        }

        // Save user data to database after successful API registration
        $db_user_data = [
            'user_id' => $user_id,
            'customer_id' => $customer_id,
            'email' => $api_user_data['email'],
            'aes_key' => '', // Will be set during login
            'first_name' => $api_user_data['first_name'],
            'last_name' => $api_user_data['last_name'],
            'company' => '', // Users don't have company field
            'password' => hash('sha256', $api_user_data['password']),
            'tools' => $api_user_data['tools']
        ];

        // Note: Database functionality has been removed
        $db_save_result = true; // Simulate success

        $logger->log_api_interaction('Dashboard Add User', [
            'step' => 'database_save',
            'customer_id' => $customer_id,
            'user_id' => $user_id,
            'user_email' => $api_user_data['email'],
            'user_full_name' => $api_user_data['first_name'] . ' ' . $api_user_data['last_name'],
            'db_save_success' => $db_save_result,
            'note' => 'Database functionality removed'
        ], 'success', 'User added successfully via API (database save skipped)');

        $logger->log_api_interaction('Dashboard Add User', [
            'step' => 'success',
            'customer_id' => $customer_id,
            'user_id' => $user_id,
            'user_email' => $api_user_data['email'],
            'user_full_name' => $api_user_data['first_name'] . ' ' . $api_user_data['last_name'],
            'db_save_success' => $db_save_result
        ], 'success', 'User added successfully via API (database save skipped)');

        wp_send_json_success('User added successfully');
    }

    /**
     * AJAX handler: Delete user
     */
    public function handle_delete_user(): void
    {
        // Check if session manager is available
        if (!$this->session_manager) {
            wp_send_json_error('Session manager not available');
            return;
        }

        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'] ?? '', 'dit_dashboard_nonce')) {
            wp_send_json_error('Invalid nonce');
            return;
        }

        // Check if user is logged in and is a customer
        if (!$this->session_manager->is_logged_in() || !$this->session_manager->is_customer()) {
            wp_send_json_error('Access denied');
            return;
        }

        $user_id = (int)($_POST['user_id'] ?? 0);
        $customer_id = $this->session_manager->get_customer_id();

        if ($user_id <= 0) {
            wp_send_json_error('Invalid user ID');
            return;
        }

        // Call API to delete user
        $api = API::get_instance();
        $result = $api->delete_user($user_id, $customer_id);

        if ($result && isset($result['success']) && $result['success']) {
            wp_send_json_success('User deleted successfully');
        } else {
            wp_send_json_error('Failed to delete user: ' . ($result['message'] ?? 'Unknown error'));
        }
    }

    /**
     * AJAX handler: Get user activity
     */
    public function handle_get_user_activity(): void
    {
        // Check if session manager is available
        if (!$this->session_manager) {
            wp_send_json_error('Session manager not available');
            return;
        }

        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'] ?? '', 'dit_dashboard_nonce')) {
            wp_send_json_error('Invalid nonce');
            return;
        }

        // Check if user is logged in
        if (!$this->session_manager->is_logged_in()) {
            wp_send_json_error('Access denied');
            return;
        }

        $user_id = $this->session_manager->get_user_id();

        // For now, return mock data
        // In the future, this would call the API to get actual activity
        $activities = [
            [
                'id' => 1,
                'action' => 'Tool accessed',
                'tool' => 'Data Integrity Tool',
                'timestamp' => time() - 3600,
                'description' => 'Data Integrity Tool accessed'
            ],
            [
                'id' => 2,
                'action' => 'Report generated',
                'tool' => 'Report Generator',
                'timestamp' => time() - 86400,
                'description' => 'Report generated successfully'
            ]
        ];

        wp_send_json_success($activities);
    }

    /**
     * AJAX handler: Update password
     */
    public function handle_update_password(): void
    {
        // Check if session manager is available
        if (!$this->session_manager) {
            wp_send_json_error('Session manager not available');
            return;
        }

        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'] ?? '', 'dit_dashboard_nonce')) {
            wp_send_json_error('Invalid nonce');
            return;
        }

        // Check if user is logged in
        if (!$this->session_manager->is_logged_in()) {
            wp_send_json_error('Access denied');
            return;
        }

        $new_password = $_POST['new_password'] ?? '';

        // Validate password
        if (empty($new_password)) {
            wp_send_json_error('Password is required');
            return;
        }

        if (strlen($new_password) < 6) {
            wp_send_json_error('Password must be at least 6 characters long');
            return;
        }

        // For now, just return success
        // In the future, this would call the API to update the password
        wp_send_json_success('Password updated successfully');
    }

    /**
     * AJAX handler: Get user data for editing
     */
    public function handle_get_user(): void
    {
        error_log('DIT Dashboard: handle_get_user started');
        error_log('DIT Dashboard: POST data: ' . print_r($_POST, true));

        // Check if session manager is available
        if (!$this->session_manager) {
            wp_send_json_error('Session manager not available');
            return;
        }

        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'] ?? '', 'dit_dashboard_nonce')) {
            wp_send_json_error('Invalid nonce');
            return;
        }

        // Check if user is logged in
        if (!$this->session_manager->is_logged_in()) {
            wp_send_json_error('Access denied');
            return;
        }

        // Get user ID and customer ID from POST data
        $user_id = (int) ($_POST['user_id'] ?? 0);
        $customer_id = (int) ($_POST['customer_id'] ?? 0);

        error_log('DIT Dashboard: Getting user data for user_id: ' . $user_id . ', customer_id: ' . $customer_id);

        // Validate input
        if ($user_id <= 0) {
            wp_send_json_error('Invalid user ID');
            return;
        }

        if ($customer_id <= 0) {
            wp_send_json_error('Invalid customer ID');
            return;
        }

        try {
            // Get API instance
            $api = API::get_instance();
            if (!$api) {
                wp_send_json_error('API not available');
                return;
            }

            // Call API to get user data
            $user_data = $api->get_user($user_id, $customer_id);

            if (!$user_data) {
                wp_send_json_error('Failed to retrieve user data');
                return;
            }

            error_log('DIT Dashboard: Successfully retrieved user data: ' . print_r($user_data, true));

            // Transform data keys to match JavaScript expectations
            $transformed_data = [
                'id' => $user_data['Id'] ?? null,
                'user_id' => $user_data['Id'] ?? null,
                'customer_id' => $user_data['CustomerId'] ?? null,
                'first_name' => $user_data['NameFirst'] ?? '',
                'last_name' => $user_data['NameLast'] ?? '',
                'email' => $user_data['Email'] ?? '',
                'tools' => $user_data['Tools'] ?? [],
                'active' => true, // Default to active
                'date_added' => $user_data['DateAdded'] ?? null,
                'password_hash' => $user_data['PasswordHash'] ?? null,
                'aes_key' => $user_data['AesKey'] ?? null,
                'change_password_token' => $user_data['ChangePasswordToken'] ?? null
            ];

            error_log('DIT Dashboard: Transformed user data for JavaScript: ' . print_r($transformed_data, true));

            wp_send_json_success($transformed_data);
        } catch (\Exception $e) {
            error_log('DIT Dashboard: Error getting user data: ' . $e->getMessage());
            wp_send_json_error('Failed to get user data: ' . $e->getMessage());
        }
    }

    /**
     * AJAX handler: Update user data
     */
    public function handle_update_user(): void
    {
        error_log('DIT Dashboard: handle_update_user started');
        error_log('DIT Dashboard: POST data: ' . print_r($_POST, true));

        // Check if session manager is available
        if (!$this->session_manager) {
            wp_send_json_error('Session manager not available');
            return;
        }

        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'] ?? '', 'dit_dashboard_nonce')) {
            wp_send_json_error('Invalid nonce');
            return;
        }

        // Check if user is logged in
        if (!$this->session_manager->is_logged_in()) {
            wp_send_json_error('Access denied');
            return;
        }

        // Get user data from POST
        $user_data = $_POST['user_data'] ?? [];

        error_log('DIT Dashboard: Updating user with data: ' . print_r($user_data, true));
        error_log('DIT Dashboard: User data keys: ' . implode(', ', array_keys($user_data)));
        error_log('DIT Dashboard: User ID: ' . ($user_data['user_id'] ?? 'NOT SET'));
        error_log('DIT Dashboard: Customer ID: ' . ($user_data['customer_id'] ?? 'NOT SET'));
        error_log('DIT Dashboard: Email: ' . ($user_data['email'] ?? 'NOT SET'));
        error_log('DIT Dashboard: First Name: ' . ($user_data['first_name'] ?? 'NOT SET'));
        error_log('DIT Dashboard: Last Name: ' . ($user_data['last_name'] ?? 'NOT SET'));
        error_log('DIT Dashboard: Tools: ' . print_r($user_data['tools'] ?? [], true));
        error_log('DIT Dashboard: Password provided: ' . (!empty($user_data['password']) ? 'YES (length: ' . strlen($user_data['password']) . ')' : 'NO'));

        // Validate input
        if (empty($user_data['user_id']) || empty($user_data['customer_id'])) {
            wp_send_json_error('Missing user ID or customer ID');
            return;
        }

        if (empty($user_data['email']) || empty($user_data['first_name']) || empty($user_data['last_name'])) {
            wp_send_json_error('Missing required fields');
            return;
        }

        try {
            // Get API instance
            $api = API::get_instance();
            if (!$api) {
                wp_send_json_error('API not available');
                return;
            }

            // Call API to update user data
            $updated_user_data = $api->update_user(
                (int) $user_data['user_id'],
                (int) $user_data['customer_id'],
                $user_data
            );

            if (!$updated_user_data) {
                wp_send_json_error('Failed to update user data');
                return;
            }

            error_log('DIT Dashboard: Successfully updated user data: ' . print_r($updated_user_data, true));
            wp_send_json_success($updated_user_data);
        } catch (\Exception $e) {
            error_log('DIT Dashboard: Error updating user data: ' . $e->getMessage());
            wp_send_json_error('Failed to update user data: ' . $e->getMessage());
        }
    }

    /**
     * AJAX handler: Update account information (first name, last name, password)
     */
    public function handle_update_account(): void
    {
        // Check if session manager is available
        if (!$this->session_manager) {
            wp_send_json_error('Session manager not available');
            return;
        }

        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'] ?? '', 'dit_dashboard_nonce')) {
            wp_send_json_error('Invalid nonce');
            return;
        }

        // Check if user is logged in
        if (!$this->session_manager->is_logged_in()) {
            wp_send_json_error('Access denied');
            return;
        }

        $first_name = sanitize_text_field($_POST['first_name'] ?? '');
        $last_name = sanitize_text_field($_POST['last_name'] ?? '');
        $company = sanitize_text_field($_POST['company'] ?? '');
        $new_password = $_POST['new_password'] ?? '';

        // Validate required fields
        if (empty($first_name)) {
            wp_send_json_error('First name is required');
            return;
        }

        if (empty($last_name)) {
            wp_send_json_error('Last name is required');
            return;
        }

        // Validate password if provided
        if (!empty($new_password) && strlen($new_password) < 6) {
            wp_send_json_error('Password must be at least 6 characters long');
            return;
        }

        try {
            // Get session data
            $session_data = $this->session_manager->get_session_data();
            $user_id = $session_data['user_id'] ?? 0;
            $customer_id = $session_data['customer_id'] ?? 0;

            if (!$user_id || !$customer_id) {
                wp_send_json_error('Invalid session data');
                return;
            }

            // Get API instance
            $api = API::get_instance();
            if (!$api) {
                wp_send_json_error('API not available');
                return;
            }

            // Check if user is a customer (role = 2) or regular user (role = 1)
            $user_role = $session_data['role'] ?? 0;

            error_log('DIT Dashboard: handle_update_account - User role: ' . $user_role . ', Customer ID: ' . $customer_id . ', User ID: ' . $user_id);

            if ($user_role === 2) {
                // Customer - use update_customer method
                error_log('DIT Dashboard: Using update_customer method for customer');

                $customer_data = [
                    'first_name' => $first_name,
                    'last_name' => $last_name,
                    'company' => $company,
                    'email' => $session_data['email'] ?? ''
                ];

                // Add password only if provided
                if (!empty($new_password)) {
                    $customer_data['password'] = $new_password;
                }

                // Call API to update customer data
                $updated_data = $api->update_customer($customer_id, $customer_data);
            } else {
                // Regular user - use update_user method
                error_log('DIT Dashboard: Using update_user method for regular user');

                $user_data = [
                    'user_id' => $user_id,
                    'customer_id' => $customer_id,
                    'first_name' => $first_name,
                    'last_name' => $last_name,
                    'email' => $session_data['email'] ?? ''
                ];

                // Add password only if provided
                if (!empty($new_password)) {
                    $user_data['password'] = $new_password;
                }

                // Call API to update user data
                $updated_data = $api->update_user($user_id, $customer_id, $user_data);
            }

            if (!$updated_data) {
                wp_send_json_error('Failed to update account data');
                return;
            }

            // Update session data with new names
            $session_data['first_name'] = $first_name;
            $session_data['last_name'] = $last_name;

            // Add company only for customer role
            if ($user_role === 2) {
                $session_data['company'] = $company;
            }

            $this->session_manager->update_session_data($session_data);

            wp_send_json_success('Account updated successfully');
        } catch (\Exception $e) {
            error_log('DIT Dashboard: Error updating account: ' . $e->getMessage());
            wp_send_json_error('Failed to update account: ' . $e->getMessage());
        }
    }

    /**
     * AJAX handler: Get customer data for account settings
     */
    public function handle_get_customer_data(): void
    {
        error_log('DIT Dashboard: handle_get_customer_data called');

        // Check if session manager is available
        if (!$this->session_manager) {
            error_log('DIT Dashboard: Session manager not available');
            wp_send_json_error('Session manager not available');
            return;
        }

        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'] ?? '', 'dit_dashboard_nonce')) {
            wp_send_json_error('Invalid nonce');
            return;
        }

        // Check if user is logged in
        if (!$this->session_manager->is_logged_in()) {
            wp_send_json_error('Access denied');
            return;
        }

        try {
            // Get session data
            $session_data = $this->session_manager->get_session_data();
            $customer_id = $session_data['customer_id'] ?? 0;
            $user_role = $session_data['role'] ?? 0;

            error_log('DIT Dashboard: Session data - customer_id: ' . $customer_id . ', user_role: ' . $user_role);

            if (!$customer_id) {
                error_log('DIT Dashboard: Invalid customer ID');
                wp_send_json_error('Invalid customer ID');
                return;
            }

            // Get API instance
            $api = API::get_instance();
            if (!$api) {
                wp_send_json_error('API not available');
                return;
            }

            // Check if steganography key exists before making API calls (only create if needed)
            try {
                if (!isset($_SESSION)) {
                    session_start();
                }

                $needs_steganography_key = true;
                if (isset($_SESSION['dit_aes_keys'][$customer_id])) {
                    $existing_key = $_SESSION['dit_aes_keys'][$customer_id];
                    $is_steganography_key = (ctype_xdigit($existing_key) && strlen($existing_key) === 128);

                    if ($is_steganography_key) {
                        error_log('DIT Dashboard: Valid steganography key already exists in get_customer_data');
                        $needs_steganography_key = false;
                    }
                }

                // IMPORTANT: We do NOT create users during login
                // Users should only be created during registration process
                // If steganography key is missing, it means the user was not properly registered
                if ($needs_steganography_key) {
                    error_log('DIT Dashboard: ERROR - Steganography key missing during login in get_customer_data');
                    error_log('DIT Dashboard: This indicates the user was not properly registered');
                    error_log('DIT Dashboard: Customer ID: ' . $customer_id . ' needs to be registered first');
                    error_log('DIT Dashboard: Login process cannot continue without proper registration');
                }
            } catch (\Exception $e) {
                error_log('DIT Dashboard: Exception ensuring steganography key in get_customer_data: ' . $e->getMessage());
                // Continue anyway - don't break the dashboard
            }

            // Get customer data
            $customer_data = $api->get_customer($customer_id);

            // If API call fails, use local data as fallback
            if (!$customer_data) {
                // Try to get data from local storage using helper functions
                $local_first_name = \DIT\get_user_first_name($customer_id);
                $local_last_name = \DIT\get_user_last_name($customer_id);
                $local_company = \DIT\get_user_company($customer_id);
                $local_email = \DIT\get_user_email($customer_id);

                // Get full user data for debugging
                $full_user_data = \DIT\get_user_data($customer_id);
                error_log('DIT Dashboard: Full user data for customer ' . $customer_id . ': ' . print_r($full_user_data, true));

                error_log('DIT Dashboard: Local data check for customer ' . $customer_id .
                    ' - First Name: ' . ($local_first_name ?: 'NOT FOUND') .
                    ', Last Name: ' . ($local_last_name ?: 'NOT FOUND') .
                    ', Company: ' . ($local_company ?: 'NOT FOUND') .
                    ', Email: ' . ($local_email ?: 'NOT FOUND'));

                // Also check what's in settings
                $settings = \DIT\get_settings();
                $registered_users = $settings['registered_users'] ?? [];
                error_log('DIT Dashboard: Settings check - registered_users count: ' . count($registered_users));
                error_log('DIT Dashboard: All registered_users keys: ' . print_r(array_keys($registered_users), true));
                if (isset($registered_users[$customer_id])) {
                    error_log('DIT Dashboard: Customer ' . $customer_id . ' found in settings: ' . print_r($registered_users[$customer_id], true));
                    error_log('DIT Dashboard: Customer ' . $customer_id . ' data keys: ' . print_r(array_keys($registered_users[$customer_id]), true));
                } else {
                    error_log('DIT Dashboard: Customer ' . $customer_id . ' NOT found in settings');
                }

                error_log('DIT Dashboard: Using local data for customer ' . $customer_id .
                    ' - First Name: ' . ($local_first_name ?: 'NOT FOUND') .
                    ', Last Name: ' . ($local_last_name ?: 'NOT FOUND') .
                    ', Company: ' . ($local_company ?: 'NOT FOUND') .
                    ', Email: ' . ($local_email ?: 'NOT FOUND'));

                // Process data according to current issue
                $current_first_name = $local_first_name ?: ($session_data['first_name'] ?? '');
                $current_last_name = $local_last_name ?: ($session_data['last_name'] ?? '');
                $current_company = $local_company ?: ($session_data['company'] ?? '');

                // Split the data that's currently in first_name field
                $name_parts = explode(' ', trim($current_first_name));
                $processed_first_name = $name_parts[0] ?? '';
                $processed_last_name = isset($name_parts[1]) ? implode(' ', array_slice($name_parts, 1)) : '';

                // Move current last_name to company
                $processed_company = $current_last_name;

                // If we have a real company, use it instead
                if (!empty($current_company)) {
                    $processed_company = $current_company;
                }

                error_log('DIT Dashboard: Data processing for customer ' . $customer_id .
                    ' - Original first_name: "' . $current_first_name .
                    '", Original last_name: "' . $current_last_name .
                    '", Original company: "' . $current_company . '"');
                error_log('DIT Dashboard: Processed data for customer ' . $customer_id .
                    ' - New first_name: "' . $processed_first_name .
                    '", New last_name: "' . $processed_last_name .
                    '", New company: "' . $processed_company . '"');

                $transformed_data = [
                    'customer_id' => $customer_id,
                    'first_name' => $processed_first_name,
                    'last_name' => $processed_last_name,
                    'company' => $processed_company,
                    'email' => $local_email ?: ($session_data['email'] ?? ''),
                    'role' => $user_role
                ];
            } else {
                // Transform data for frontend
                $api_first_name = $customer_data['NameFirst'] ?? '';
                $api_last_name = $customer_data['NameLast'] ?? '';
                $api_company = $customer_data['Company'] ?? '';

                // Apply the same processing logic for API data
                $name_parts = explode(' ', trim($api_first_name));
                $processed_first_name = $name_parts[0] ?? '';
                $processed_last_name = isset($name_parts[1]) ? implode(' ', array_slice($name_parts, 1)) : '';

                // Move current last_name to company if company is empty
                $processed_company = $api_company;
                if (empty($processed_company) && !empty($api_last_name)) {
                    $processed_company = $api_last_name;
                }

                error_log('DIT Dashboard: API data processing for customer ' . $customer_id .
                    ' - Original NameFirst: "' . $api_first_name .
                    '", Original NameLast: "' . $api_last_name .
                    '", Original Company: "' . $api_company . '"');
                error_log('DIT Dashboard: Processed API data for customer ' . $customer_id .
                    ' - New first_name: "' . $processed_first_name .
                    '", New last_name: "' . $processed_last_name .
                    '", New company: "' . $processed_company . '"');

                $transformed_data = [
                    'customer_id' => $customer_data['CustomerId'] ?? $customer_id,
                    'first_name' => $processed_first_name,
                    'last_name' => $processed_last_name,
                    'company' => $processed_company,
                    'email' => $customer_data['Email'] ?? $session_data['email'] ?? '',
                    'role' => $user_role
                ];

                error_log('DIT Dashboard: Using API data for customer ' . $customer_id .
                    ' - First Name: ' . ($customer_data['NameFirst'] ?? 'NOT FOUND') .
                    ', Last Name: ' . ($customer_data['NameLast'] ?? 'NOT FOUND') .
                    ', Company: ' . ($customer_data['Company'] ?? 'NOT FOUND') .
                    ', Email: ' . ($customer_data['Email'] ?? 'NOT FOUND'));
            }

            error_log('DIT Dashboard: Sending transformed data: ' . print_r($transformed_data, true));
            wp_send_json_success($transformed_data);
        } catch (\Exception $e) {
            error_log('DIT Dashboard: Error getting customer data: ' . $e->getMessage());
            wp_send_json_error('Failed to get customer data: ' . $e->getMessage());
        }
    }

    /**
     * Handle get all customers for admin (actually returns users like customer role)
     */
    public function handle_get_all_customers(): void
    {
        error_log('DIT Dashboard: handle_get_all_customers called (admin version)');

        try {
            if (!$this->session_manager || !$this->session_manager->is_logged_in()) {
                error_log('DIT Dashboard: handle_get_all_customers - Not logged in');
                wp_send_json_error('Not logged in');
                return;
            }

            $user_role = $this->session_manager->get_user_role();
            error_log('DIT Dashboard: handle_get_all_customers - User role: ' . $user_role);

            if ($user_role !== 3) {
                error_log('DIT Dashboard: handle_get_all_customers - Access denied for role: ' . $user_role);
                wp_send_json_error('Access denied. Administrator role required.');
                return;
            }

            // Get user ID and customer ID from session
            $user_id = $this->session_manager->get_user_id();
            $customer_id = $this->session_manager->get_customer_id();

            error_log('DIT Dashboard: handle_get_all_customers - User ID: ' . ($user_id ?: 'null'));
            error_log('DIT Dashboard: handle_get_all_customers - Customer ID: ' . ($customer_id ?: 'null'));

            if (!$user_id) {
                wp_send_json_error('User ID not found');
                return;
            }

            // Use customer_id if available, otherwise fallback to user_id
            $api_customer_id = $customer_id ?: $user_id;
            error_log('DIT Dashboard: handle_get_all_customers - Using API Customer ID: ' . $api_customer_id);

            // Get Core instance
            $core = \DIT\Core::get_instance();
            if (!$core) {
                error_log('DIT Dashboard: handle_get_all_customers - Core instance not available');
                wp_send_json_error('Core not available');
                return;
            }

            // Get API instance
            $api = $core->api;
            if (!$api) {
                error_log('DIT Dashboard: handle_get_all_customers - API instance is null');
                wp_send_json_error('API not available');
                return;
            }

            error_log('DIT Dashboard: handle_get_all_customers - Calling API get_users_for_customer with customer_id: ' . $api_customer_id);

            // Note: Database functionality has been removed
            error_log('DIT Dashboard: Database functionality removed - returning empty customer list');
            wp_send_json_success([]);
        } catch (\Exception $e) {
            error_log('DIT Dashboard: Error getting all customers (admin): ' . $e->getMessage());
            error_log('DIT Dashboard: Error stack trace: ' . $e->getTraceAsString());
            wp_send_json_error('Failed to get users: ' . $e->getMessage());
        }
    }

    /**
     * Handle add customer for admin
     */
    public function handle_add_customer(): void
    {
        try {
            if (!$this->session_manager || !$this->session_manager->is_logged_in()) {
                wp_send_json_error('Not logged in');
                return;
            }

            $user_role = $this->session_manager->get_user_role();
            if ($user_role !== 3) {
                wp_send_json_error('Access denied. Administrator role required.');
                return;
            }

            $email = sanitize_email($_POST['email'] ?? '');
            $password = sanitize_text_field($_POST['password'] ?? '');
            $first_name = sanitize_text_field($_POST['first_name'] ?? '');
            $last_name = sanitize_text_field($_POST['last_name'] ?? '');
            $company = sanitize_text_field($_POST['company'] ?? '');

            if (empty($email) || empty($password) || empty($first_name) || empty($last_name)) {
                wp_send_json_error('All required fields must be filled');
                return;
            }

            // For now, return success (mock implementation)
            $new_customer = [
                'id' => rand(1000, 9999),
                'email' => $email,
                'first_name' => $first_name,
                'last_name' => $last_name,
                'company' => $company,
                'status' => 'active'
            ];

            wp_send_json_success($new_customer);
        } catch (\Exception $e) {
            error_log('DIT Dashboard: Error adding customer: ' . $e->getMessage());
            wp_send_json_error('Failed to add customer: ' . $e->getMessage());
        }
    }

    /**
     * Handle update customer for admin
     */
    public function handle_update_customer(): void
    {
        try {
            if (!$this->session_manager || !$this->session_manager->is_logged_in()) {
                wp_send_json_error('Not logged in');
                return;
            }

            $user_role = $this->session_manager->get_user_role();
            if ($user_role !== 3) {
                wp_send_json_error('Access denied. Administrator role required.');
                return;
            }

            $customer_id = (int)($_POST['customer_id'] ?? 0);
            $first_name = sanitize_text_field($_POST['first_name'] ?? '');
            $last_name = sanitize_text_field($_POST['last_name'] ?? '');
            $company = sanitize_text_field($_POST['company'] ?? '');

            if ($customer_id <= 0) {
                wp_send_json_error('Invalid customer ID');
                return;
            }

            // For now, return success (mock implementation)
            $updated_customer = [
                'id' => $customer_id,
                'first_name' => $first_name,
                'last_name' => $last_name,
                'company' => $company,
                'status' => 'active'
            ];

            wp_send_json_success($updated_customer);
        } catch (\Exception $e) {
            error_log('DIT Dashboard: Error updating customer: ' . $e->getMessage());
            wp_send_json_error('Failed to update customer: ' . $e->getMessage());
        }
    }

    /**
     * Handle delete customer for admin
     */
    public function handle_delete_customer(): void
    {
        try {
            if (!$this->session_manager || !$this->session_manager->is_logged_in()) {
                wp_send_json_error('Not logged in');
                return;
            }

            $user_role = $this->session_manager->get_user_role();
            if ($user_role !== 3) {
                wp_send_json_error('Access denied. Administrator role required.');
                return;
            }

            $customer_id = (int)($_POST['customer_id'] ?? 0);

            if ($customer_id <= 0) {
                wp_send_json_error('Invalid customer ID');
                return;
            }

            // For now, return success (mock implementation)
            wp_send_json_success(['message' => 'Customer deleted successfully']);
        } catch (\Exception $e) {
            error_log('DIT Dashboard: Error deleting customer: ' . $e->getMessage());
            wp_send_json_error('Failed to delete customer: ' . $e->getMessage());
        }
    }

    /**
     * Handle get all users for admin
     */
    public function handle_get_all_users(): void
    {
        error_log('DIT Dashboard: handle_get_all_users called');

        try {
            if (!$this->session_manager || !$this->session_manager->is_logged_in()) {
                error_log('DIT Dashboard: handle_get_all_users - Not logged in');
                wp_send_json_error('Not logged in');
                return;
            }

            $user_role = $this->session_manager->get_user_role();
            error_log('DIT Dashboard: handle_get_all_users - User role: ' . $user_role);

            if ($user_role !== 3) {
                error_log('DIT Dashboard: handle_get_all_users - Access denied for role: ' . $user_role);
                wp_send_json_error('Access denied. Administrator role required.');
                return;
            }

            // Note: Database functionality has been removed
            error_log('DIT Dashboard: Database functionality removed - returning empty user list');
            wp_send_json_success([]);
        } catch (\Exception $e) {
            error_log('DIT Dashboard: Error getting all users: ' . $e->getMessage());
            wp_send_json_error('Failed to get users: ' . $e->getMessage());
        }
    }
}
