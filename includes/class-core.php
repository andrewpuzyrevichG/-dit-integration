<?php

namespace DIT;

use Exception;

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class Core
 * Main plugin class
 */
class Core
{
    /**
     * Plugin instance
     *
     * @var Core
     */
    private static $instance = null;

    /**
     * Admin instance
     *
     * @var Admin
     */
    public $admin;

    /**
     * API instance
     *
     * @var API
     */
    public $api;

    /**
     * Encryption instance
     *
     * @var Encryption
     */
    public $encryption;

    /**
     * WPForms instance
     *
     * @var WPForms
     */
    public $wpforms;

    /**
     * Stripe instance
     *
     * @var Stripe
     */
    public $stripe;

    /**
     * Logger instance
     *
     * @var Logger
     */
    public $logger;

    /**
     * Session Manager instance
     *
     * @var Session_Manager
     */
    public $session_manager;

    /**
     * Dashboard instance
     *
     * @var Dashboard
     */
    public $dashboard;

    /**
     * Reset Password instance
     *
     * @var Reset_Password
     */
    public $reset_password;

    /**
     * Steganography instance
     *
     * @var Steganography
     */
    public $steganography;

    /**
     * Get plugin instance
     *
     * @return Core
     */
    public static function get_instance()
    {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Constructor
     */
    private function __construct()
    {
        // Plugin will be initialized in run() method
    }

    /**
     * Initialize plugin
     */
    public function init()
    {
        error_log('DIT Integration: Core init started');

        // Initialize logger first
        try {
            $this->logger = new Logger();
            error_log('DIT Integration: Logger initialized successfully');
        } catch (Exception $e) {
            error_log('DIT Integration: Failed to initialize Logger - ' . $e->getMessage());
        }

        // Initialize components only when needed
        if (is_admin()) {
            error_log('DIT Integration: Initializing admin components');
            try {
                // Admin class should be loaded by autoloader from admin/ directory
                if (!class_exists('DIT\\Admin')) {
                    error_log('DIT Integration: Admin class not found after autoloader');
                }

                if (class_exists('DIT\\Admin')) {
                    error_log('DIT Integration: Admin class found');
                    $this->admin = new Admin();
                    error_log('DIT Integration: Admin instance created');
                    $this->admin->init();
                    error_log('DIT Integration: Admin initialized successfully');
                } else {
                    error_log('DIT Integration: Admin class not found after manual load');
                }
            } catch (Exception $e) {
                error_log('DIT Integration: Failed to initialize Admin - ' . $e->getMessage());
                error_log('DIT Integration: Exception trace: ' . $e->getTraceAsString());
            }
        } else {
            error_log('DIT Integration: Not in admin area, will check admin status after Session Manager initialization');
        }

        // Initialize API - ensure class is loaded
        try {
            // Always try to load API class manually first
            $api_file = DIT_PLUGIN_DIR . 'includes/class-api.php';
            if (file_exists($api_file)) {
                require_once $api_file;
                error_log('DIT Integration: API class loaded manually in Core init');
            } else {
                error_log('DIT Integration: ERROR - API file not found: ' . $api_file);
            }

            if (class_exists('DIT\\API')) {
                $this->api = API::get_instance();
                $this->api->init();
                error_log('DIT Integration: API initialized successfully');
            } else {
                error_log('DIT Integration: ERROR - API class not found after manual load');
                $this->api = null;
            }
        } catch (Exception $e) {
            error_log('DIT Integration: Failed to initialize API - ' . $e->getMessage());
            error_log('DIT Integration: API exception trace: ' . $e->getTraceAsString());
            // Don't throw exception, just log the error and continue
            $this->api = null;
        }

        // Initialize encryption - ensure class is loaded
        try {
            if (!class_exists('DIT\\Encryption')) {
                error_log('DIT Integration: Encryption class not found, trying to load manually');
                $encryption_file = DIT_PLUGIN_DIR . 'includes/class-encryption.php';
                if (file_exists($encryption_file)) {
                    require_once $encryption_file;
                    error_log('DIT Integration: Encryption file loaded manually');
                } else {
                    error_log('DIT Integration: Encryption file not found at: ' . $encryption_file);
                }
            }

            if (class_exists('DIT\\Encryption')) {
                $this->encryption = new Encryption();
                $this->encryption->init();
                error_log('DIT Integration: Encryption initialized successfully');
            } else {
                error_log('DIT Integration: Encryption class still not found after manual load');
                // Don't throw exception, just log the error and continue
                $this->encryption = null;
            }
        } catch (Exception $e) {
            error_log('DIT Integration: Failed to initialize Encryption - ' . $e->getMessage());
            error_log('DIT Integration: Encryption exception trace: ' . $e->getTraceAsString());
            // Don't throw exception, just log the error and continue
            $this->encryption = null;
        }

        // Initialize Steganography - ensure class is loaded
        try {
            if (!class_exists('DIT\\Steganography')) {
                error_log('DIT Integration: Steganography class not found, trying to load manually');
                $steganography_file = DIT_PLUGIN_DIR . 'includes/class-steganography.php';
                if (file_exists($steganography_file)) {
                    require_once $steganography_file;
                    error_log('DIT Integration: Steganography file loaded manually');
                } else {
                    error_log('DIT Integration: Steganography file not found at: ' . $steganography_file);
                }
            }

            if (class_exists('DIT\\Steganography')) {
                $this->steganography = new Steganography();
                error_log('DIT Integration: Steganography initialized successfully');
            } else {
                error_log('DIT Integration: Steganography class still not found after manual load');
                $this->steganography = null;
            }
        } catch (Exception $e) {
            error_log('DIT Integration: Failed to initialize Steganography - ' . $e->getMessage());
            error_log('DIT Integration: Steganography exception trace: ' . $e->getTraceAsString());
            $this->steganography = null;
        }

        // Initialize WPForms integration
        if (class_exists('DIT\\WPForms')) {
            try {
                $this->wpforms = new WPForms();
                $this->wpforms->init();
                error_log('DIT Integration: WPForms initialized successfully');
            } catch (Exception $e) {
                error_log('DIT Integration: Failed to initialize WPForms - ' . $e->getMessage());
            }
        } else {
            error_log('DIT Integration: WPForms class not found, trying to load manually');

            // Try to load WPForms class manually
            $wpforms_file = DIT_PLUGIN_DIR . 'includes/class-wpforms.php';
            if (file_exists($wpforms_file)) {
                require_once $wpforms_file;
                error_log('DIT Integration: WPForms file loaded manually');

                if (class_exists('DIT\\WPForms')) {
                    try {
                        $this->wpforms = new WPForms();
                        $this->wpforms->init();
                        error_log('DIT Integration: WPForms initialized successfully after manual load');
                    } catch (Exception $e) {
                        error_log('DIT Integration: Failed to initialize WPForms after manual load - ' . $e->getMessage());
                        $this->wpforms = null;
                    }
                } else {
                    error_log('DIT Integration: WPForms class still not found after manual load');
                    $this->wpforms = null;
                }
            } else {
                error_log('DIT Integration: WPForms file not found at: ' . $wpforms_file);
                $this->wpforms = null;
            }
        }

        // Initialize Stripe integration
        if (class_exists('WPForms_Stripe')) {
            try {
                $this->stripe = new Stripe();
                $this->stripe->init();
                error_log('DIT Integration: Stripe initialized successfully');
            } catch (Exception $e) {
                error_log('DIT Integration: Failed to initialize Stripe - ' . $e->getMessage());
            }
        }

        // Initialize Session Manager
        try {
            if (!class_exists('DIT\\Session_Manager')) {
                $session_manager_file = DIT_PLUGIN_DIR . 'includes/class-session-manager.php';
                if (file_exists($session_manager_file)) {
                    require_once $session_manager_file;
                    error_log('DIT Integration: Session Manager file loaded manually');
                } else {
                    error_log('DIT Integration: Session Manager file not found at: ' . $session_manager_file);
                }
            }

            if (class_exists('DIT\\Session_Manager')) {
                $this->session_manager = new Session_Manager();
                error_log('DIT Integration: Session Manager initialized successfully');
            } else {
                error_log('DIT Integration: Session Manager class not found after manual load');
                $this->session_manager = null;
            }
        } catch (Exception $e) {
            error_log('DIT Integration: Failed to initialize Session Manager - ' . $e->getMessage());
            $this->session_manager = null;
        }

        // Initialize Dashboard
        try {
            if (!class_exists('DIT\\Dashboard')) {
                $dashboard_file = DIT_PLUGIN_DIR . 'includes/class-dashboard.php';
                if (file_exists($dashboard_file)) {
                    require_once $dashboard_file;
                    error_log('DIT Integration: Dashboard file loaded manually');
                } else {
                    error_log('DIT Integration: Dashboard file not found at: ' . $dashboard_file);
                }
            }

            if (class_exists('DIT\\Dashboard')) {
                $this->dashboard = new Dashboard();
                $this->dashboard->init();
                error_log('DIT Integration: Dashboard initialized successfully');

                // Flush rewrite rules to ensure dashboard pages are registered
                flush_rewrite_rules();
                error_log('DIT Integration: Rewrite rules flushed after dashboard initialization');
            } else {
                error_log('DIT Integration: Dashboard class not found after manual load');
                $this->dashboard = null;
            }
        } catch (Exception $e) {
            error_log('DIT Integration: Failed to initialize Dashboard - ' . $e->getMessage());
            $this->dashboard = null;
        }

        // Initialize Reset Password
        try {
            if (!class_exists('DIT\\Reset_Password')) {
                $reset_password_file = DIT_PLUGIN_DIR . 'includes/class-reset-password.php';
                if (file_exists($reset_password_file)) {
                    require_once $reset_password_file;
                    error_log('DIT Integration: Reset Password file loaded manually');
                } else {
                    error_log('DIT Integration: Reset Password file not found at: ' . $reset_password_file);
                }
            }

            if (class_exists('DIT\\Reset_Password')) {
                $this->reset_password = new Reset_Password();
                error_log('DIT Integration: Reset Password initialized successfully');
            } else {
                error_log('DIT Integration: Reset Password class not found after manual load');
                $this->reset_password = null;
            }
        } catch (Exception $e) {
            error_log('DIT Integration: Failed to initialize Reset Password - ' . $e->getMessage());
            $this->reset_password = null;
        }

        // Check if admin user is logged in on frontend and initialize admin components
        if (!is_admin() && $this->session_manager && $this->session_manager->is_logged_in()) {
            try {
                $user_role = $this->session_manager->get_user_role();
                error_log('DIT Integration: Frontend user role: ' . $user_role);

                if ($user_role === 3) {
                    error_log('DIT Integration: Admin user detected on frontend, initializing admin components');

                    if (class_exists('DIT\\Admin')) {
                        error_log('DIT Integration: Admin class found for frontend admin');
                        $this->admin = new Admin();
                        error_log('DIT Integration: Admin instance created for frontend');
                        $this->admin->init();
                        error_log('DIT Integration: Admin initialized successfully for frontend');
                    } else {
                        error_log('DIT Integration: Admin class not found for frontend');
                    }
                } else {
                    error_log('DIT Integration: Frontend user is not admin (role: ' . $user_role . ')');
                }
            } catch (Exception $e) {
                error_log('DIT Integration: Failed to check admin status or initialize Admin - ' . $e->getMessage());
            }
        }

        error_log('DIT Integration: Core init completed');
    }

    /**
     * Run plugin
     */
    public function run()
    {
        // Load text domain
        add_action('plugins_loaded', [$this, 'load_textdomain']);

        // Initialize the plugin
        $this->init();
    }

    /**
     * Load plugin text domain
     */
    public function load_textdomain()
    {
        load_plugin_textdomain('dit-integration', false, dirname(plugin_basename(DIT_PLUGIN_DIR)) . '/languages');
    }
}
