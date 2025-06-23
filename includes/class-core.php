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
        // Initialize components when WordPress is ready
        add_action('init', [$this, 'init'], 0);
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
                if (class_exists('DIT\\Admin')) {
                    error_log('DIT Integration: Admin class found');
                    $this->admin = new Admin();
                    error_log('DIT Integration: Admin instance created');
                    $this->admin->init();
                    error_log('DIT Integration: Admin initialized successfully');
                } else {
                    error_log('DIT Integration: Admin class not found');
                }
            } catch (Exception $e) {
                error_log('DIT Integration: Failed to initialize Admin - ' . $e->getMessage());
                error_log('DIT Integration: Exception trace: ' . $e->getTraceAsString());
            }
        } else {
            error_log('DIT Integration: Not in admin area, skipping admin initialization');
        }

        // Initialize API - ensure class is loaded
        try {
            if (!class_exists('DIT\\API')) {
                error_log('DIT Integration: API class not found, trying to load manually');
                $api_file = DIT_PLUGIN_DIR . 'includes/class-api.php';
                if (file_exists($api_file)) {
                    require_once $api_file;
                    error_log('DIT Integration: API file loaded manually');
                } else {
                    error_log('DIT Integration: API file not found at: ' . $api_file);
                }
            }

            if (class_exists('DIT\\API')) {
                $this->api = new API();
                $this->api->init();
                error_log('DIT Integration: API initialized successfully');
            } else {
                error_log('DIT Integration: API class still not found after manual load');
                // Don't throw exception, just log the error and continue
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

        // Initialize WPForms integration
        if (class_exists('DIT\\WPForms')) {
            try {
                $this->wpforms = new WPForms();
                $this->wpforms->init();
                error_log('DIT Integration: WPForms initialized successfully');
            } catch (Exception $e) {
                error_log('DIT Integration: Failed to initialize WPForms - ' . $e->getMessage());
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

        error_log('DIT Integration: Core init completed');
    }

    /**
     * Run plugin
     */
    public function run()
    {
        // Load text domain
        add_action('plugins_loaded', [$this, 'load_textdomain']);
    }

    /**
     * Load plugin text domain
     */
    public function load_textdomain()
    {
        load_plugin_textdomain('dit-integration', false, dirname(plugin_basename(DIT_PLUGIN_DIR)) . '/languages');
    }
}
