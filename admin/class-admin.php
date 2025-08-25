<?php

namespace DIT;

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class Admin
 * Handles admin functionality
 */
class Admin
{
    /**
     * Initialize admin functionality
     */
    public function init()
    {
        // Add admin menu with higher priority
        add_action('admin_menu', [$this, 'add_admin_menu'], 20);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_scripts']);

        // Add AJAX handlers
        add_action('wp_ajax_dit_save_settings', [$this, 'ajax_save_settings']);
        add_action('wp_ajax_dit_test_api', [$this, 'ajax_test_api']);
        add_action('wp_ajax_dit_clear_logs', [$this, 'ajax_clear_logs']);
        add_action('wp_ajax_dit_get_logs', [$this, 'ajax_get_logs']);
        add_action('wp_ajax_dit_clear_cache', [$this, 'ajax_clear_cache']);
        add_action('wp_ajax_dit_get_cache_status', [$this, 'ajax_get_cache_status']);

        // Handle log downloads
        add_action('admin_init', [$this, 'handle_log_download']);
    }

    /**
     * Add admin menu
     */
    public function add_admin_menu()
    {

        // Check if we're in admin area
        if (!is_admin()) {
            return;
        }

        // Check user capabilities
        if (!current_user_can('manage_options')) {
            return;
        }

        // Add main menu page
        $main_page = add_menu_page(
            __('DIT Integration', 'dit-integration'),
            __('DIT Integration', 'dit-integration'),
            'manage_options',
            'dit-integration',
            [$this, 'render_settings_page'],
            'dashicons-admin-generic',
            30
        );


        // Add logs submenu page
        $logs_page = add_submenu_page(
            'dit-integration',
            __('DIT Logs', 'dit-integration'),
            __('Logs', 'dit-integration'),
            'manage_options',
            'dit-integration-logs',
            [$this, 'render_logs_page']
        );


        // Add login debug test submenu page
        $debug_page = add_submenu_page(
            'dit-integration',
            __('Login Debug Test', 'dit-integration'),
            __('Login Debug', 'dit-integration'),
            'manage_options',
            'dit-integration-login-debug',
            [$this, 'render_login_debug_page']
        );


        // Add direct admin login submenu page
        $admin_login_page = add_submenu_page(
            'dit-integration',
            __('Direct Admin Login', 'dit-integration'),
            __('Admin Login', 'dit-integration'),
            'manage_options',
            'dit-integration-admin-login',
            [$this, 'render_direct_admin_login_page']
        );




        // Add test admin auto login submenu page
        $test_admin_auto_login_page = add_submenu_page(
            'dit-integration',
            __('Test Admin Auto Login', 'dit-integration'),
            __('Auto Login', 'dit-integration'),
            'manage_options',
            'dit-integration-test-admin-auto-login',
            [$this, 'render_test_admin_auto_login_page']
        );


        // Add test admin session check submenu page
        $test_admin_session_check_page = add_submenu_page(
            'dit-integration',
            __('Test Admin Session Check', 'dit-integration'),
            __('Session Check', 'dit-integration'),
            'manage_options',
            'dit-integration-test-admin-session-check',
            [$this, 'render_test_admin_session_check_page']
        );
    }

    /**
     * Register settings
     */
    public function register_settings()
    {
        register_setting('dit_settings', 'dit_settings', [$this, 'sanitize_settings']);

        add_settings_section(
            'dit_general',
            __('General Settings', 'dit-integration'),
            [$this, 'render_general_section'],
            'dit-integration'
        );

        add_settings_field(
            'signup_form',
            __('Sign Up Form', 'dit-integration'),
            [$this, 'render_signup_form_field'],
            'dit-integration',
            'dit_general'
        );

        add_settings_field(
            'signin_form',
            __('Sign In Form', 'dit-integration'),
            [$this, 'render_signin_form_field'],
            'dit-integration',
            'dit_general'
        );

        add_settings_field(
            'license_type',
            __('License Type', 'dit-integration'),
            [$this, 'render_license_type_field'],
            'dit-integration',
            'dit_general'
        );

        add_settings_field(
            'subscription_duration',
            __('Subscription Duration', 'dit-integration'),
            [$this, 'render_subscription_duration_field'],
            'dit-integration',
            'dit_general'
        );

        add_settings_field(
            'metered_license_count',
            __('Metered License Count', 'dit-integration'),
            [$this, 'render_metered_license_count_field'],
            'dit-integration',
            'dit_general'
        );

        add_settings_field(
            'debug_logging',
            __('Debug Logging', 'dit-integration'),
            [$this, 'render_debug_logging_field'],
            'dit-integration',
            'dit_general'
        );

        add_settings_field(
            'login_page_id',
            __('Login/Registration Page', 'dit-integration'),
            [$this, 'render_login_page_field'],
            'dit-integration',
            'dit_general'
        );
    }

    /**
     * Enqueue admin scripts
     */
    public function enqueue_scripts($hook)
    {
        // Only enqueue on our plugin's pages
        if (strpos($hook, 'dit-integration') === false) {
            return;
        }

        // Enqueue admin.js for all plugin pages
        wp_enqueue_script(
            'dit-admin',
            DIT_PLUGIN_URL . 'assets/js/admin.js',
            ['jquery'],
            DIT_PLUGIN_VERSION,
            true
        );

        // Enqueue logs.js only on the logs page
        if ($hook === 'dit-integration_page_dit-integration-logs') {
            wp_enqueue_script(
                'dit-logs',
                DIT_PLUGIN_URL . 'assets/js/logs.js',
                ['jquery'],
                DIT_PLUGIN_VERSION,
                true
            );
        }

        // Localize script with debug info
        $admin_data = [
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('dit-admin-nonce'),
            'i18n' => [
                'saving' => __('Saving...', 'dit-integration'),
                'testing' => __('Testing...', 'dit-integration'),
            ],
        ];
        wp_localize_script('dit-admin', 'ditAdmin', $admin_data);

        // Also localize for logs.js if on logs page
        if ($hook === 'dit-integration_page_dit-integration-logs') {
            $logs_data = [
                'ajaxUrl' => admin_url('admin-ajax.php'),
                'nonce' => wp_create_nonce('dit-admin-nonce'),
            ];
            wp_localize_script('dit-logs', 'ditAdmin', $logs_data);
        }

        // Enqueue WordPress media scripts
        wp_enqueue_media();

        // Enqueue WordPress admin styles
        wp_enqueue_style('wp-admin');
        wp_enqueue_style('wp-components');

        // Enqueue tooltipster
        wp_enqueue_style(
            'tooltipster',
            'https://cdnjs.cloudflare.com/ajax/libs/tooltipster/4.2.8/css/tooltipster.bundle.min.css',
            [],
            '4.2.8'
        );

        wp_enqueue_script(
            'tooltipster',
            'https://cdnjs.cloudflare.com/ajax/libs/tooltipster/4.2.8/js/tooltipster.bundle.min.js',
            ['jquery'],
            '4.2.8',
            true
        );

        // Get plugin URL
        $plugin_url = plugin_dir_url(dirname(__FILE__));

        // Enqueue plugin styles
        wp_enqueue_style(
            'dit-admin',
            $plugin_url . 'assets/css/admin.css',
            ['wp-admin', 'wp-components', 'tooltipster'],
            DIT_PLUGIN_VERSION
        );

        // Enqueue jQuery
        wp_enqueue_script('jquery');
    }

    /**
     * Render settings page
     */
    public function render_settings_page()
    {
        // Check user capabilities
        if (!current_user_can('manage_options')) {
            return;
        }

        // Handle troubleshooting actions
        $action = isset($_GET['action']) ? sanitize_text_field($_GET['action']) : '';

        switch ($action) {
            case 'fix-dashboard':
                include DIT_PLUGIN_DIR . 'fix-dashboard-redirect.php';
                return;

            case 'test-login':
                include DIT_PLUGIN_DIR . 'test-login-redirect.php';
                return;

            case 'set-dashboard':
                $this->handle_set_dashboard();
                return;

            case 'migrate-dashboard':
                include DIT_PLUGIN_DIR . 'migrate-dashboard-settings.php';
                return;
        }

        // Get settings
        $settings = get_option('dit_settings', []);

        // Include template
        include dirname(__FILE__) . '/partials/settings-page.php';
    }

    /**
     * Render general section
     */
    public function render_general_section()
    {
        echo '<p>' . esc_html__('Configure your DIT Integration settings below.', 'dit-integration') . '</p>';
    }

    /**
     * Render signup form field
     */
    public function render_signup_form_field()
    {
        $settings = get_option('dit_settings', []);
        $signup_form = $settings['signup_form'] ?? '';
        $forms = $this->get_available_forms();
?>
        <select id="dit_signup_form" name="dit_settings[signup_form]" class="regular-text">
            <option value=""><?php _e('Select a form', 'dit-integration'); ?></option>
            <?php if (!empty($forms)) : ?>
                <?php foreach ($forms as $form) : ?>
                    <option value="<?php echo esc_attr($form->ID); ?>"
                        <?php selected($signup_form, $form->ID); ?>>
                        <?php echo esc_html($form->post_title); ?>
                    </option>
                <?php endforeach; ?>
            <?php endif; ?>
        </select>
        <p class="description"><?php _e('Select the WPForms form for user registration.', 'dit-integration'); ?></p>
    <?php
    }

    /**
     * Render signin form field
     */
    public function render_signin_form_field()
    {
        $settings = get_option('dit_settings', []);
        $signin_form = $settings['signin_form'] ?? '';
        $forms = $this->get_available_forms();
    ?>
        <select id="dit_signin_form" name="dit_settings[signin_form]" class="regular-text">
            <option value=""><?php _e('Select a form', 'dit-integration'); ?></option>
            <?php if (!empty($forms)) : ?>
                <?php foreach ($forms as $form) : ?>
                    <option value="<?php echo esc_attr($form->ID); ?>"
                        <?php selected($signin_form, $form->ID); ?>>
                        <?php echo esc_html($form->post_title); ?>
                    </option>
                <?php endforeach; ?>
            <?php endif; ?>
        </select>
        <p class="description"><?php _e('Select the WPForms form for user login.', 'dit-integration'); ?></p>
    <?php
    }

    /**
     * Render license type field
     */
    public function render_license_type_field()
    {
        $settings = get_option('dit_settings', []);
        $license_type = $settings['license_type'] ?? 'unlimited';
    ?>
        <select id="dit-settings-license-type" name="dit_settings[license_type]">
            <option value="unlimited" <?php selected($license_type, 'unlimited'); ?>>
                <?php esc_html_e('Unlimited', 'dit-integration'); ?>
            </option>
            <option value="metered" <?php selected($license_type, 'metered'); ?>>
                <?php esc_html_e('Metered', 'dit-integration'); ?>
            </option>
        </select>
    <?php
    }

    /**
     * Render subscription duration field
     */
    public function render_subscription_duration_field()
    {
        $settings = get_option('dit_settings', []);
        $duration = $settings['subscription_duration'] ?? 'monthly';
    ?>
        <select name="dit_settings[subscription_duration]">
            <option value="monthly" <?php selected($duration, 'monthly'); ?>>
                <?php esc_html_e('Monthly', 'dit-integration'); ?>
            </option>
            <option value="yearly" <?php selected($duration, 'yearly'); ?>>
                <?php esc_html_e('Yearly', 'dit-integration'); ?>
            </option>
        </select>
    <?php
    }

    /**
     * Render metered license count field
     */
    public function render_metered_license_count_field()
    {
        $settings = get_option('dit_settings', []);
        $count = $settings['metered_license_count'] ?? 100;
    ?>
        <input type="number" name="dit_settings[metered_license_count]" value="<?php echo esc_attr($count); ?>" min="1">
    <?php
    }

    /**
     * Render debug logging field
     */
    public function render_debug_logging_field()
    {
        $settings = get_option('dit_settings', []);
        $debug = $settings['debug_mode'] ?? false;
    ?>
        <label class="dit-form-field">
            <input type="checkbox" name="dit_settings[debug_mode]" value="1" <?php checked($debug); ?>>
            <?php esc_html_e('Enable debug logging', 'dit-integration'); ?>
        </label>
    <?php
    }

    /**
     * Render login/registration page field
     */
    public function render_login_page_field()
    {
        $options = get_option('dit_settings', []);
        $selected = isset($options['login_page_id']) ? (int)$options['login_page_id'] : 0;
        $pages = get_pages(['sort_column' => 'post_title', 'sort_order' => 'asc']);
        echo '<select name="dit_settings[login_page_id]" id="login_page_id">';
        echo '<option value="0">' . esc_html__('— Select —', 'dit-integration') . '</option>';
        foreach ($pages as $page) {
            printf(
                '<option value="%d"%s>%s</option>',
                $page->ID,
                selected($selected, $page->ID, false),
                esc_html($page->post_title)
            );
        }
        echo '</select>';
        if ($selected) {
            echo '<p><a href="' . get_permalink($selected) . '" target="_blank">' . esc_html__('View page', 'dit-integration') . '</a></p>';
        }
        echo '<p class="description">' . esc_html__('Select the page with your custom login/registration form (API-based).', 'dit-integration') . '</p>';
    }

    /**
     * Get available forms
     *
     * @return array
     */
    private function get_available_forms()
    {
        $args = [
            'post_type' => 'wpforms',
            'posts_per_page' => -1,
            'orderby' => 'title',
            'order' => 'ASC',
        ];

        return get_posts($args);
    }

    /**
     * Handle setting dashboard page
     */
    public function handle_set_dashboard()
    {
        if (!current_user_can('manage_options')) {
            wp_die('Access denied');
        }

        $page_id = isset($_GET['page_id']) ? (int)$_GET['page_id'] : 0;

        if ($page_id) {
            $page = get_post($page_id);
            if ($page && $page->post_type === 'page') {
                $settings = get_option('dit_settings', []);
                $settings['dashboard_page_id'] = $page_id;
                update_option('dit_settings', $settings);

                echo '<div class="notice notice-success"><p>Dashboard page set to: <strong>' . esc_html($page->post_title) . '</strong></p></div>';
            } else {
                echo '<div class="notice notice-error"><p>Invalid page selected.</p></div>';
            }
        }

        // Redirect back to settings
        wp_redirect(admin_url('admin.php?page=dit-integration'));
        exit;
    }

    /**
     * Sanitize settings
     */
    public function sanitize_settings($input)
    {


        $sanitized = [];

        // Sanitize Sign Up form
        $sanitized['signup_form'] = isset($input['signup_form']) ? absint($input['signup_form']) : '';

        // Sanitize Sign In form
        $sanitized['signin_form'] = isset($input['signin_form']) ? absint($input['signin_form']) : '';

        // Sanitize license type
        $sanitized['license_type'] = isset($input['license_type']) ? sanitize_text_field($input['license_type']) : 'unlimited';

        // Sanitize metered license count
        $sanitized['metered_license_count'] = isset($input['metered_license_count']) ? absint($input['metered_license_count']) : 100;

        // Sanitize subscription duration
        $sanitized['subscription_duration'] = isset($input['subscription_duration']) ? sanitize_text_field($input['subscription_duration']) : 'monthly';

        // Sanitize debug mode
        $sanitized['debug_mode'] = isset($input['debug_mode']) ? (bool)$input['debug_mode'] : false;

        // Sanitize login page ID
        $sanitized['login_page_id'] = isset($input['login_page_id']) ? (int)$input['login_page_id'] : 0;

        // Sanitize dashboard page ID
        $sanitized['dashboard_page_id'] = isset($input['dashboard_page_id']) ? (int)$input['dashboard_page_id'] : 0;

        return $sanitized;
    }

    /**
     * Handle AJAX save settings
     */
    public function ajax_save_settings()
    {
        // Verify nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'dit-admin-nonce')) {
            wp_send_json_error(['message' => __('Security check failed.', 'dit-integration')]);
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('You do not have permission to save settings.', 'dit-integration')]);
        }

        // Get and sanitize settings
        $settings_raw = $_POST['dit_settings'] ?? [];
        $settings = [];
        foreach ($settings_raw as $key => $value) {
            $settings[$key] = sanitize_text_field($value);
        }

        if (empty($settings)) {
            wp_send_json_error(['message' => __('No settings received. Please check the form fields.', 'dit-integration')]);
        }

        // Get current settings
        $current_settings = get_option('dit_settings', []);

        // Merge with current settings
        $settings = array_merge($current_settings, $settings);

        // Save settings
        $result = update_option('dit_settings', $settings);

        // Verify settings were saved
        $saved_settings = get_option('dit_settings', []);

        // Send response
        if ($result || $saved_settings === $settings) {
            wp_send_json_success(['message' => __('Settings saved successfully.', 'dit-integration')]);
        } else {
            wp_send_json_error(['message' => __('Failed to save settings.', 'dit-integration')]);
        }
    }

    /**
     * Handle AJAX test API
     */
    public function ajax_test_api()
    {
        // Verify nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'dit-admin-nonce')) {
            wp_send_json_error(['message' => __('Security check failed.', 'dit-integration')]);
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('You do not have permission to test API.', 'dit-integration')]);
        }

        // Get settings
        $settings = get_option('dit_settings', []);

        // Test API connection
        try {
            $api = API::get_instance();
            $result = $api->test_connection();

            if ($result) {
                wp_send_json_success(['message' => __('API connection successful.', 'dit-integration')]);
            } else {
                wp_send_json_error(['message' => __('API connection failed.', 'dit-integration')]);
            }
        } catch (\Exception $e) {
            wp_send_json_error(['message' => $e->getMessage()]);
        }
    }

    /**
     * Handle AJAX clear logs
     */
    public function ajax_clear_logs()
    {


        // Verify nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'dit-admin-nonce')) {
            wp_send_json_error(['message' => __('Security check failed.', 'dit-integration')]);
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('You do not have permission to clear logs.', 'dit-integration')]);
        }

        try {
            $logger = Core::get_instance()->logger;
            $logger->clear_logs();
            wp_send_json_success(['message' => __('Logs cleared successfully.', 'dit-integration')]);
        } catch (\Exception $e) {
            wp_send_json_error(['message' => $e->getMessage()]);
        }
    }

    /**
     * Handle AJAX get logs
     */
    public function ajax_get_logs()
    {
        // Verify nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'dit-admin-nonce')) {
            wp_send_json_error(['message' => __('Security check failed.', 'dit-integration')]);
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('You do not have permission to view logs.', 'dit-integration')]);
        }

        try {
            $logger = Core::get_instance()->logger;
            $logs = $logger->get_recent_logs(100);
            wp_send_json_success(['logs' => $logs]);
        } catch (\Exception $e) {
            wp_send_json_error(['message' => $e->getMessage()]);
        }
    }

    /**
     * Render logs page
     */
    public function render_logs_page()
    {
        // Check user capabilities
        if (!current_user_can('manage_options')) {
            return;
        }

        $core = Core::get_instance();
        $logger = $core->logger;

        // Get recent logs
        $logs = $logger->get_recent_logs(100);
        $log_file_path = $logger->get_log_file_path();
    ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

            <div class="dit-logs-controls">
                <button type="button" id="dit-clear-logs" class="button button-secondary">
                    <span class="dashicons dashicons-trash"></span>
                    <?php \esc_html_e('Clear Logs', 'dit-integration'); ?>
                </button>

                <button type="button" id="dit-refresh-logs" class="button button-secondary">
                    <span class="dashicons dashicons-update"></span>
                    <?php \esc_html_e('Refresh Logs', 'dit-integration'); ?>
                </button>

                <a href="<?php echo \esc_url(\admin_url('admin.php?page=dit-integration-logs&download=1')); ?>"
                    class="button button-secondary">
                    <span class="dashicons dashicons-download"></span>
                    <?php \esc_html_e('Download Logs', 'dit-integration'); ?>
                </a>

                <div id="dit-logs-status" class="dit-logs-status" style="display: none;"></div>
            </div>

            <div class="dit-logs-info">
                <p><strong><?php esc_html_e('Log file location:', 'dit-integration'); ?></strong>
                    <code><?php echo esc_html($log_file_path); ?></code>
                </p>
                <p><strong><?php esc_html_e('Last updated:', 'dit-integration'); ?></strong>
                    <span id="dit-logs-last-updated"><?php echo esc_html(current_time('Y-m-d H:i:s')); ?></span>
                </p>
            </div>

            <div class="dit-logs-content">
                <h2><?php esc_html_e('Recent Logs', 'dit-integration'); ?></h2>
                <div class="dit-logs-display">
                    <pre id="dit-logs-content"
                        style="background: #f1f1f1; padding: 15px; border: 1px solid #ddd; max-height: 600px; overflow-y: auto;"><?php echo esc_html($logs); ?></pre>
                </div>
            </div>
        </div>

        <style>
            .dit-logs-controls {
                margin: 20px 0;
                padding: 15px;
                background: #fff;
                border: 1px solid #ddd;
                border-radius: 4px;
            }

            .dit-logs-controls .button {
                margin-right: 10px;
            }

            .dit-logs-controls .dashicons {
                margin-right: 5px;
            }

            .dit-logs-status {
                margin-top: 10px;
                padding: 10px;
                border-radius: 4px;
            }

            .dit-logs-status.success {
                background: #d4edda;
                border: 1px solid #c3e6cb;
                color: #155724;
            }

            .dit-logs-status.error {
                background: #f8d7da;
                border: 1px solid #f5c6cb;
                color: #721c24;
            }

            .dit-logs-info {
                margin: 20px 0;
                padding: 15px;
                background: #f9f9f9;
                border-left: 4px solid #0073aa;
                border-radius: 4px;
            }

            .dit-logs-content {
                margin: 20px 0;
            }

            .dit-logs-display pre {
                font-family: 'Courier New', monospace;
                font-size: 12px;
                line-height: 1.4;
                border-radius: 4px;
            }

            .button:disabled {
                opacity: 0.6;
                cursor: not-allowed;
            }
        </style>

        <script type="text/javascript">
            jQuery(document).ready(function($) {
                var nonce = '<?php echo wp_create_nonce('dit-admin-nonce'); ?>';

                // Clear logs
                $('#dit-clear-logs').on('click', function() {
                    if (confirm(
                            '<?php echo \esc_js(__('Are you sure you want to clear all logs?', 'dit-integration')); ?>'
                        )) {
                        var $button = $(this);
                        var $status = $('#dit-logs-status');

                        $button.prop('disabled', true);
                        $status.removeClass('success error').hide();

                        $.ajax({
                            url: ajaxurl,
                            type: 'POST',
                            data: {
                                action: 'dit_clear_logs',
                                nonce: nonce
                            },
                            success: function(response) {
                                if (response.success) {
                                    $status.html(response.data.message).addClass('success').show();
                                    $('#dit-logs-content').text('');
                                    $('#dit-logs-last-updated').text(new Date().toLocaleString());
                                } else {
                                    $status.html(response.data.message).addClass('error').show();
                                }
                            },
                            error: function() {
                                showError(
                                    '<?php echo \esc_js(__('An error occurred while clearing logs.', 'dit-integration')); ?>'
                                );
                            },
                            complete: function() {
                                $button.prop('disabled', false);
                            }
                        });
                    }
                });

                // Refresh logs
                $('#dit-refresh-logs').on('click', function() {
                    var $button = $(this);
                    var $status = $('#dit-logs-status');

                    $button.prop('disabled', true);
                    $status.removeClass('success error').hide();

                    $.ajax({
                        url: ajaxurl,
                        type: 'POST',
                        data: {
                            action: 'dit_get_logs',
                            nonce: nonce
                        },
                        success: function(response) {
                            if (response.success) {
                                $('#dit-logs-content').text(response.data.logs);
                                $('#dit-logs-last-updated').text(new Date().toLocaleString());
                                showSuccess(
                                    '<?php echo \esc_js(__('Logs refreshed successfully.', 'dit-integration')); ?>'
                                );
                            } else {
                                $status.html(response.data.message).addClass('error').show();
                            }
                        },
                        error: function() {
                            showError(
                                '<?php echo \esc_js(__('An error occurred while refreshing logs.', 'dit-integration')); ?>'
                            );
                        },
                        complete: function() {
                            $button.prop('disabled', false);
                        }
                    });
                });
            });
        </script>
<?php
    }

    /**
     * Handle log downloads
     */
    public function handle_log_download()
    {
        if (isset($_GET['download']) && $_GET['download'] === '1') {
            $logger = Core::get_instance()->logger;
            $log_file_path = $logger->get_log_file_path();

            if (file_exists($log_file_path)) {
                header('Content-Description: File Transfer');
                header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename="' . basename($log_file_path) . '"');
                header('Expires: 0');
                header('Cache-Control: must-revalidate');
                header('Pragma: public');
                header('Content-Length: ' . filesize($log_file_path));
                readfile($log_file_path);
                exit;
            }
        }
    }

    /**
     * AJAX handler for clearing RSA key cache
     */
    public function ajax_clear_cache()
    {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'dit-admin-nonce')) {
            wp_send_json_error(['message' => __('Security check failed.', 'dit-integration')]);
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Insufficient permissions.', 'dit-integration')]);
        }

        try {
            $core = Core::get_instance();
            $api = $core->api;

            if (method_exists($api, 'clear_rsa_key_cache')) {
                $api->clear_rsa_key_cache();
                wp_send_json_success(['message' => __('RSA key cache cleared successfully.', 'dit-integration')]);
            } else {
                wp_send_json_error(['message' => __('Cache clearing method not available.', 'dit-integration')]);
            }
        } catch (\Exception $e) {
            wp_send_json_error(['message' => __('Error clearing cache: ' . $e->getMessage(), 'dit-integration')]);
        }
    }

    /**
     * AJAX handler for getting cache status
     */
    public function ajax_get_cache_status()
    {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'], 'dit-admin-nonce')) {
            wp_send_json_error(['message' => __('Security check failed.', 'dit-integration')]);
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Insufficient permissions.', 'dit-integration')]);
        }

        try {
            $core = Core::get_instance();
            $api = $core->api;

            if (method_exists($api, 'get_rsa_key_cache_status')) {
                $status = $api->get_rsa_key_cache_status();
                wp_send_json_success(['status' => $status]);
            } else {
                wp_send_json_error(['message' => __('Cache status method not available.', 'dit-integration')]);
            }
        } catch (\Exception $e) {
            wp_send_json_error(['message' => __('Error getting cache status: ' . $e->getMessage(), 'dit-integration')]);
        }
    }

    /**
     * Render login debug test page
     */
    public function render_login_debug_page()
    {
        // Include the test script
        include_once(DIT_PLUGIN_DIR . 'admin/test-login-debug.php');
    }

    /**
     * Render direct admin login page
     */
    public function render_direct_admin_login_page()
    {
        // Include the direct admin login script
        include_once(DIT_PLUGIN_DIR . 'admin/direct-admin-login.php');
    }



    /**
     * Render test admin auto login page
     */
    public function render_test_admin_auto_login_page()
    {
        // Include the test admin auto login script
        include_once(DIT_PLUGIN_DIR . 'admin/test-admin-auto-login.php');
    }

    /**
     * Render test admin session check page
     */
    public function render_test_admin_session_check_page()
    {
        // Include the test admin session check script
        include_once(DIT_PLUGIN_DIR . 'admin/test-admin-session-check.php');
    }
}
