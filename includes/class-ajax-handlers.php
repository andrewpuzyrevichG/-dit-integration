<?php

/**
 * DIT Integration AJAX Handlers
 *
 * @package DIT_Integration
 * @since 1.0.0
 */

namespace DIT;

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class AJAX_Handlers
 * Handles all AJAX requests for the DIT Integration plugin
 */
class AJAX_Handlers
{
    /**
     * Constructor
     */
    public function __construct()
    {
        add_action('wp_ajax_dit_test_get_users', [$this, 'test_get_users_for_customer']);
        add_action('wp_ajax_dit_test_dashboard', [$this, 'test_dashboard_functionality']);
    }

    /**
     * AJAX handler for testing get users for customer
     */
    public function test_get_users_for_customer()
    {
        // Check nonce for security
        if (!wp_verify_nonce($_POST['nonce'], 'dit_test_get_users')) {
            wp_die('Security check failed');
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_die('Access denied');
        }

        $customer_id = isset($_POST['customer_id']) ? intval($_POST['customer_id']) : 82;

        // Get the API instance
        $api = \DIT\API::get_instance();

        // Test the method
        $result = $api->get_users_for_customer($customer_id);

        // Get recent logs
        $log_file = WP_CONTENT_DIR . '/uploads/dit-logs/dit-integration-logs.txt';
        $recent_logs = '';
        if (file_exists($log_file)) {
            $logs = file_get_contents($log_file);
            $lines = explode("\n", $logs);
            $recent_lines = array_slice($lines, -50); // Last 50 lines

            foreach ($recent_lines as $line) {
                if (
                    strpos($line, 'Get Users For Customer') !== false ||
                    strpos($line, 'AES Key Retrieval') !== false ||
                    strpos($line, 'encrypted_response_handler') !== false ||
                    strpos($line, 'decryption') !== false
                ) {
                    $recent_logs .= $line . "\n";
                }
            }
        }

        wp_send_json_success([
            'customer_id' => $customer_id,
            'result' => $result,
            'result_type' => gettype($result),
            'result_count' => is_array($result) ? count($result) : 0,
            'recent_logs' => $recent_logs
        ]);
    }

    /**
     * AJAX handler for testing dashboard functionality
     */
    public function test_dashboard_functionality()
    {
        // Check nonce for security
        if (!wp_verify_nonce($_POST['nonce'], 'dit_test_dashboard')) {
            wp_die('Security check failed');
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_die('Access denied');
        }

        $customer_id = isset($_POST['customer_id']) ? intval($_POST['customer_id']) : 82;

        // Test dashboard functionality
        $dashboard_data = [
            'customer_id' => $customer_id,
            'status' => 'testing',
            'users_count' => 0,
            'dashboard_class_exists' => class_exists('DIT\Dashboard'),
            'api_class_exists' => class_exists('DIT\API'),
            'session_manager_exists' => class_exists('DIT\Session_Manager')
        ];

        // Try to get users through dashboard
        if (class_exists('DIT\Dashboard')) {
            try {
                $dashboard = new \DIT\Dashboard();
                $dashboard_data['dashboard_created'] = true;

                // Test dashboard functionality by calling API directly
                $api = \DIT\API::get_instance();
                $users = $api->get_users_for_customer($customer_id);

                if ($users !== null) {
                    $dashboard_data['users_count'] = is_array($users) ? count($users) : 0;
                    $dashboard_data['users_data'] = $users;
                    $dashboard_data['status'] = 'success';
                    $dashboard_data['message'] = 'Users retrieved successfully through API';
                } else {
                    $dashboard_data['status'] = 'no_users';
                    $dashboard_data['error'] = 'No users returned from API';
                }
            } catch (\Exception $e) {
                $dashboard_data['status'] = 'error';
                $dashboard_data['error'] = $e->getMessage();
            }
        } else {
            $dashboard_data['status'] = 'no_class';
            $dashboard_data['error'] = 'Dashboard class not found';
        }

        // Get recent logs
        $log_file = WP_CONTENT_DIR . '/uploads/dit-logs/dit-integration-logs.txt';
        $recent_logs = '';
        if (file_exists($log_file)) {
            $logs = file_get_contents($log_file);
            $lines = explode("\n", $logs);
            $recent_lines = array_slice($lines, -30); // Last 30 lines

            foreach ($recent_lines as $line) {
                if (
                    strpos($line, 'Dashboard') !== false ||
                    strpos($line, 'Get Users') !== false ||
                    strpos($line, 'AES Key') !== false
                ) {
                    $recent_logs .= $line . "\n";
                }
            }
        }

        $dashboard_data['recent_logs'] = $recent_logs;

        wp_send_json_success($dashboard_data);
    }
}
