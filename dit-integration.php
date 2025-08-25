<?php

/**
 * Plugin Name: DIT Integration
 * Plugin URI: https://dataintegritytool.com
 * Description: Integration with Data Integrity Tool API, WPForms and Stripe
 * Version: 1.2.0
 * Author: Data Integrity Tool
 * Author URI: https://dataintegritytool.com
 * Text Domain: dit-integration
 * Domain Path: /languages
 * Requires at least: 5.8
 * Requires PHP: 7.4
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('DIT_PLUGIN_FILE', __FILE__);
define('DIT_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('DIT_PLUGIN_URL', plugin_dir_url(__FILE__));
define('DIT_PLUGIN_VERSION', '1.2.0');

// Global flag to prevent multiple initializations
global $dit_plugin_initialized;
$dit_plugin_initialized = false;

// Verify constants are set correctly
if (!defined('DIT_PLUGIN_DIR')) {
    // DIT_PLUGIN_DIR not defined
}

if (!defined('DIT_PLUGIN_FILE')) {
    // DIT_PLUGIN_FILE not defined
}

// Autoloader for plugin classes
spl_autoload_register(function ($class) {
    // Check if the class is in our namespace
    if (strpos($class, 'DIT\\') !== 0) {
        return;
    }

    // Remove namespace from class name
    $class_name = str_replace('DIT\\', '', $class);

    // Convert class name to file name format
    $file_name = 'class-' . strtolower(str_replace('_', '-', $class_name)) . '.php';

    // Build possible file paths
    $paths = [
        DIT_PLUGIN_DIR . 'admin/' . $file_name,
        DIT_PLUGIN_DIR . 'includes/' . $file_name
    ];



    // Check each path and include the file if it exists
    foreach ($paths as $file_path) {


        if (file_exists($file_path)) {
            // Try to include the file
            try {
                require_once $file_path;
            } catch (Exception $e) {
                // Exception while including file
            } catch (Error $e) {
                // Error while including file
            }
            return;
        }
    }
});

// Verify class files exist (after autoloader registration)
$class_files = [
    'includes/class-core.php',
    'includes/class-logger.php',
    'includes/class-api.php',
    'includes/class-wpforms.php'
];



// Manually load critical classes to ensure they are available
try {
    // Always load API class manually to ensure it's available
    $api_file = DIT_PLUGIN_DIR . 'includes/class-api.php';
    if (file_exists($api_file)) {
        require_once $api_file;
    }



    if (!class_exists('DIT\\WPForms')) {
        $wpforms_file = DIT_PLUGIN_DIR . 'includes/class-wpforms.php';
        if (file_exists($wpforms_file)) {
            require_once $wpforms_file;
        }
    }
} catch (Exception $e) {
    // Exception during manual class loading
} catch (Error $e) {
    // Error during manual class loading
}

// Load helpers file with utility functions
$helpers_file = DIT_PLUGIN_DIR . 'includes/helpers.php';
if (file_exists($helpers_file)) {
    require_once $helpers_file;
}

// Verify assets directory exists
$assets_dir = DIT_PLUGIN_DIR . 'assets';
$js_dir = $assets_dir . '/js';
$css_dir = $assets_dir . '/css';

if (!file_exists($assets_dir)) {
    mkdir($assets_dir, 0755, true);
}

if (!file_exists($js_dir)) {
    mkdir($js_dir, 0755, true);
}

if (!file_exists($css_dir)) {
    mkdir($css_dir, 0755, true);
}

// Verify assets files exist
$js_file = $js_dir . '/admin.js';
$css_file = $css_dir . '/admin.css';

/**
 * Check if WPForms is active
 */
function dit_check_wpforms()
{
    if (!function_exists('is_plugin_active')) {
        include_once(ABSPATH . 'wp-admin/includes/plugin.php');
    }

    $wpforms_lite = is_plugin_active('wpforms-lite/wpforms.php');
    $wpforms_pro = is_plugin_active('wpforms/wpforms.php');
    $wpforms_function = function_exists('wpforms');
    $wpforms_class = class_exists('WPForms\WPForms');

    if (!$wpforms_lite && !$wpforms_pro) {
        add_action('admin_notices', function () use ($wpforms_lite, $wpforms_pro, $wpforms_function, $wpforms_class) {
?>
            <div class="notice notice-error">
                <p><?php _e('DIT Integration requires WPForms plugin to be installed and activated.', 'dit-integration'); ?></p>
                <p>Debug info:</p>
                <ul>
                    <li>WPForms Lite active: <?php echo $wpforms_lite ? 'Yes' : 'No'; ?></li>
                    <li>WPForms Pro active: <?php echo $wpforms_pro ? 'Yes' : 'No'; ?></li>
                    <li>wpforms() function exists: <?php echo $wpforms_function ? 'Yes' : 'No'; ?></li>
                    <li>WPForms\WPForms class exists: <?php echo $wpforms_class ? 'Yes' : 'No'; ?></li>
                </ul>
            </div>
        <?php
        });
        return false;
    }
    return true;
}

/**
 * Check if Stripe is available through WPForms
 */
function dit_check_stripe()
{
    if (!class_exists('WPForms_Stripe')) {
        add_action('admin_notices', function () {
        ?>
            <div class="notice notice-warning">
                <p><?php _e('DIT Integration: WPForms Stripe addon is not active. Payment processing will not be available.', 'dit-integration'); ?>
                </p>
            </div>
<?php
        });
        return false;
    }
    return true;
}

// Check dependencies before loading the plugin
if (!dit_check_wpforms()) {
    return;
}

/**
 * The code that runs during plugin activation.
 */
function activate_dit()
{
    // Check dependencies before activation
    if (!dit_check_wpforms()) {
        deactivate_plugins(plugin_basename(__FILE__));
        wp_die(__('DIT Integration requires WPForms plugin to be installed and activated.', 'dit-integration'));
    }

    // Note: Database functionality has been removed

    // Set default options
    add_option('dit_settings', [
        'dit_api_key' => '',
        'dit_api_url' => ''
    ]);

    // Create reset password page
    if (class_exists('DIT\\Page_Creator')) {
        \DIT\Page_Creator::create_reset_password_page();
    }

    // Register custom page templates
    add_filter('theme_page_templates', array('DIT\\Page_Creator', 'register_page_templates'));

    // Flush rewrite rules to register dashboard pages
    flush_rewrite_rules();
}

/**
 * The code that runs during plugin deactivation.
 */
function deactivate_dit()
{
    // Note: Database functionality has been removed

    // Flush rewrite rules
    flush_rewrite_rules();
}

register_activation_hook(__FILE__, 'activate_dit');
register_deactivation_hook(__FILE__, 'deactivate_dit');

// Load custom page templates
add_filter('template_include', 'dit_load_custom_template');

// Initialize the plugin (single hook to prevent duplication)
add_action('plugins_loaded', 'run_dit', 20);

// REMOVED: admin_init hook to prevent duplicate initialization

// Initialize PHP sessions early
add_action('init', 'dit_init_sessions', 1);

/**
 * Initialize PHP sessions for DIT plugin
 */
function dit_init_sessions()
{
    if (!session_id()) {
        session_start();
    }
}

/**
 * Load custom page templates
 */
function dit_load_custom_template($template)
{
    if (is_page()) {
        $page_template = get_post_meta(get_the_ID(), '_wp_page_template', true);

        if ($page_template === 'reset-password.php') {
            $custom_template = DIT_PLUGIN_DIR . 'templates/' . $page_template;
            if (file_exists($custom_template)) {
                return $custom_template;
            }
        }
    }

    return $template;
}

/**
 * Initialize the plugin
 */
function run_dit()
{
    global $dit_plugin_initialized;

    // Prevent multiple initializations
    if ($dit_plugin_initialized) {
        return;
    }

    $dit_plugin_initialized = true;

    // Load plugin text domain
    load_plugin_textdomain('dit-integration', false, dirname(plugin_basename(__FILE__)) . '/languages');

    // Check Stripe availability
    dit_check_stripe();

    if (class_exists('DIT\\Core')) {
        $plugin = \DIT\Core::get_instance();
        $plugin->run();
    }

    // Initialize AJAX handlers
    if (class_exists('DIT\\AJAX_Handlers')) {
        new \DIT\AJAX_Handlers();
    }
}

// Heartbeat AJAX handler for session keep-alive
add_action('wp_ajax_dit_session_heartbeat', 'dit_session_heartbeat_handler');
add_action('wp_ajax_nopriv_dit_session_heartbeat', 'dit_session_heartbeat_handler');

function dit_session_heartbeat_handler()
{
    if (!session_id()) {
        session_start();
    }

    if (isset($_SESSION['dit_user_session'])) {
        $_SESSION['dit_user_session']['last_activity'] = time();
        wp_send_json_success(['status' => 'ok', 'updated' => true]);
    } else {
        wp_send_json_success(['status' => 'no_session', 'updated' => false]);
    }
    wp_die();
}
