<?php

/**
 * Plugin Name: DIT Integration
 * Plugin URI: https://dataintegritytool.com
 * Description: Integration with Data Integrity Tool API, WPForms and Stripe
 * Version: 1.0.1
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
define('DIT_PLUGIN_VERSION', '1.0.1');

// Global flag to prevent multiple initializations
global $dit_plugin_initialized;
$dit_plugin_initialized = false;

// Debug information (only in debug mode)
if (defined('WP_DEBUG') && WP_DEBUG) {
    error_log('DIT Integration: Plugin file: ' . DIT_PLUGIN_FILE);
    error_log('DIT Integration: Plugin directory: ' . DIT_PLUGIN_DIR);
    error_log('DIT Integration: Plugin URL: ' . DIT_PLUGIN_URL);
    error_log('DIT Integration: Plugin version: ' . DIT_PLUGIN_VERSION);
}

// Verify constants are set correctly
if (!defined('DIT_PLUGIN_DIR')) {
    error_log('DIT Integration: ERROR - DIT_PLUGIN_DIR not defined!');
} else {
    error_log('DIT Integration: DIT_PLUGIN_DIR is defined: ' . DIT_PLUGIN_DIR);
}

if (!defined('DIT_PLUGIN_FILE')) {
    error_log('DIT Integration: ERROR - DIT_PLUGIN_FILE not defined!');
} else {
    error_log('DIT Integration: DIT_PLUGIN_FILE is defined: ' . DIT_PLUGIN_FILE);
}

// Verify class files exist
$class_files = [
    'includes/class-core.php',
    'includes/class-logger.php',
    'includes/class-api.php',
    'includes/class-encryption.php',
    'includes/class-wpforms.php'
];

foreach ($class_files as $file) {
    $full_path = DIT_PLUGIN_DIR . $file;
    if (file_exists($full_path)) {
        error_log('DIT Integration: Class file exists: ' . $file);
    } else {
        error_log('DIT Integration: ERROR - Class file missing: ' . $file);
    }
}

// Verify assets directory exists
$assets_dir = DIT_PLUGIN_DIR . 'assets';
$js_dir = $assets_dir . '/js';
$css_dir = $assets_dir . '/css';

if (!file_exists($assets_dir)) {
    error_log('DIT Integration: Assets directory does not exist: ' . $assets_dir);
    mkdir($assets_dir, 0755, true);
}

if (!file_exists($js_dir)) {
    error_log('DIT Integration: JS directory does not exist: ' . $js_dir);
    mkdir($js_dir, 0755, true);
}

if (!file_exists($css_dir)) {
    error_log('DIT Integration: CSS directory does not exist: ' . $css_dir);
    mkdir($css_dir, 0755, true);
}

// Verify assets files exist
$js_file = $js_dir . '/admin.js';
$css_file = $css_dir . '/admin.css';

if (!file_exists($js_file)) {
    error_log('DIT Integration: JS file does not exist: ' . $js_file);
}

if (!file_exists($css_file)) {
    error_log('DIT Integration: CSS file does not exist: ' . $css_file);
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
        DIT_PLUGIN_DIR . 'includes/' . $file_name,
        DIT_PLUGIN_DIR . 'admin/' . $file_name
    ];

    // Debug logging (only in debug mode)
    if (defined('WP_DEBUG') && WP_DEBUG) {
        error_log('DIT Integration: Autoloader trying to load class: ' . $class);
        error_log('DIT Integration: Looking for file: ' . $file_name);
    }

    // Check each path and include the file if it exists
    foreach ($paths as $file_path) {
        if (file_exists($file_path)) {
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('DIT Integration: Found file at: ' . $file_path);
                error_log('DIT Integration: File permissions: ' . decoct(fileperms($file_path)));
                error_log('DIT Integration: File size: ' . filesize($file_path) . ' bytes');
            }

            // Try to include the file
            try {
                require_once $file_path;

                if (defined('WP_DEBUG') && WP_DEBUG) {
                    error_log('DIT Integration: File included successfully');
                    if (class_exists($class)) {
                        error_log('DIT Integration: Class ' . $class . ' loaded successfully');
                    }
                }
            } catch (Exception $e) {
                error_log('DIT Integration: Exception while including file: ' . $e->getMessage());
            } catch (Error $e) {
                error_log('DIT Integration: Error while including file: ' . $e->getMessage());
            }
            return;
        }
    }

    if (defined('WP_DEBUG') && WP_DEBUG) {
        error_log('DIT Integration: File not found for class: ' . $class);
    }
});

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
                <p><?php _e('DIT Integration: WPForms Stripe addon is not active. Payment processing will not be available.', 'dit-integration'); ?></p>
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

    // Create necessary database tables
    // Set default options
    add_option('dit_settings', [
        'dit_api_key' => '',
        'dit_api_url' => '',
        'encryption_key' => wp_generate_password(32, true, true)
    ]);
}

/**
 * The code that runs during plugin deactivation.
 */
function deactivate_dit()
{
    // Cleanup if necessary
}

register_activation_hook(__FILE__, 'activate_dit');
register_deactivation_hook(__FILE__, 'deactivate_dit');

// Initialize the plugin
add_action('plugins_loaded', 'run_dit', 0);

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

    if (defined('WP_DEBUG') && WP_DEBUG) {
        error_log('DIT Integration: Starting plugin initialization');
    }

    // Load plugin text domain
    load_plugin_textdomain('dit-integration', false, dirname(plugin_basename(__FILE__)) . '/languages');

    if (defined('WP_DEBUG') && WP_DEBUG) {
        error_log('DIT Integration: Text domain loaded');
    }

    // Check Stripe availability
    dit_check_stripe();

    if (defined('WP_DEBUG') && WP_DEBUG) {
        error_log('DIT Integration: Stripe check completed');
    }

    // Initialize main plugin class
    if (defined('WP_DEBUG') && WP_DEBUG) {
        error_log('DIT Integration: Initializing Core class');
    }

    if (class_exists('DIT\\Core')) {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('DIT Integration: Core class found');
        }

        $plugin = \DIT\Core::get_instance();

        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('DIT Integration: Core instance created');
        }

        $plugin->run();

        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('DIT Integration: Core run completed');
        }
    } else {
        error_log('DIT Integration: Core class not found');
    }
}
