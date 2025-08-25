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
        // Initialize logger first
        try {
            $this->logger = new Logger();
        } catch (Exception $e) {
            // Failed to initialize Logger
        }

        // Initialize components only when needed
        if (is_admin()) {
            try {
                if (class_exists('DIT\\Admin')) {
                    $this->admin = new Admin();
                    $this->admin->init();
                }
            } catch (Exception $e) {
                // Failed to initialize Admin
            }
        }

        // Initialize API - ensure class is loaded
        try {
            // Always try to load API class manually first
            $api_file = DIT_PLUGIN_DIR . 'includes/class-api.php';
            if (file_exists($api_file)) {
                require_once $api_file;
            }

            if (class_exists('DIT\\API')) {
                $this->api = API::get_instance();
                $this->api->init();
            } else {
                $this->api = null;
            }
        } catch (Exception $e) {
            // Failed to initialize API
            $this->api = null;
        }

        // Initialize encryption - ensure class is loaded
        try {
            if (!class_exists('DIT\\Encryption')) {
                $encryption_file = DIT_PLUGIN_DIR . 'includes/class-encryption.php';
                if (file_exists($encryption_file)) {
                    require_once $encryption_file;
                }
            }

            if (class_exists('DIT\\Encryption')) {
                $this->encryption = new Encryption();
                $this->encryption->init();
            } else {
                $this->encryption = null;
            }
        } catch (Exception $e) {
            $this->encryption = null;
        }

        // Initialize Steganography - ensure class is loaded
        try {
            if (!class_exists('DIT\\Steganography')) {
                $steganography_file = DIT_PLUGIN_DIR . 'includes/class-steganography.php';
                if (file_exists($steganography_file)) {
                    require_once $steganography_file;
                }
            }

            if (class_exists('DIT\\Steganography')) {
                $this->steganography = new Steganography();
            } else {
                $this->steganography = null;
            }
        } catch (Exception $e) {
            $this->steganography = null;
        }

        // Initialize WPForms integration
        if (class_exists('DIT\\WPForms')) {
            try {
                $this->wpforms = new WPForms();
                $this->wpforms->init();
            } catch (Exception $e) {
                // Failed to initialize WPForms
            }
        } else {
            // Try to load WPForms class manually (only if not already initialized)
            if (!$this->wpforms) {
                $wpforms_file = DIT_PLUGIN_DIR . 'includes/class-wpforms.php';
                if (file_exists($wpforms_file)) {
                    require_once $wpforms_file;

                    if (class_exists('DIT\\WPForms')) {
                        try {
                            $this->wpforms = new WPForms();
                            $this->wpforms->init();
                        } catch (Exception $e) {
                            $this->wpforms = null;
                        }
                    } else {
                        $this->wpforms = null;
                    }
                } else {
                    $this->wpforms = null;
                }
            }
        }

        // Initialize Stripe integration
        if (class_exists('WPForms_Stripe')) {
            try {
                $this->stripe = new Stripe();
                $this->stripe->init();
            } catch (Exception $e) {
                // Failed to initialize Stripe
            }
        }

        // Initialize Session Manager
        try {
            if (!class_exists('DIT\\Session_Manager')) {
                $session_manager_file = DIT_PLUGIN_DIR . 'includes/class-session-manager.php';
                if (file_exists($session_manager_file)) {
                    require_once $session_manager_file;
                }
            }

            if (class_exists('DIT\\Session_Manager')) {
                $this->session_manager = new Session_Manager();
            } else {
                $this->session_manager = null;
            }
        } catch (Exception $e) {
            $this->session_manager = null;
        }

        // Initialize Dashboard
        try {
            if (!class_exists('DIT\\Dashboard')) {
                $dashboard_file = DIT_PLUGIN_DIR . 'includes/class-dashboard.php';
                if (file_exists($dashboard_file)) {
                    require_once $dashboard_file;
                }
            }

            if (class_exists('DIT\\Dashboard')) {
                $this->dashboard = new Dashboard();
                $this->dashboard->init();

                // Flush rewrite rules to ensure dashboard pages are registered
                flush_rewrite_rules();
            } else {
                $this->dashboard = null;
            }
        } catch (Exception $e) {
            $this->dashboard = null;
        }

        // Initialize Reset Password
        try {
            if (!class_exists('DIT\\Reset_Password')) {
                $reset_password_file = DIT_PLUGIN_DIR . 'includes/class-reset-password.php';
                if (file_exists($reset_password_file)) {
                    require_once $reset_password_file;
                }
            }

            if (class_exists('DIT\\Reset_Password')) {
                $this->reset_password = new Reset_Password();
            } else {
                $this->reset_password = null;
            }
        } catch (Exception $e) {
            $this->reset_password = null;
        }

        // Check if admin user is logged in on frontend and initialize admin components
        if (!is_admin() && $this->session_manager && $this->session_manager->is_logged_in()) {
            try {
                $user_role = $this->session_manager->get_user_role();

                if ($user_role === 3) {
                    if (class_exists('DIT\\Admin')) {
                        $this->admin = new Admin();
                        $this->admin->init();
                    }
                }
            } catch (Exception $e) {
                // Failed to check admin status or initialize Admin
            }
        }
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
