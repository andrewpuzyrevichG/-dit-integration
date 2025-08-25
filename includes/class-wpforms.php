<?php

namespace DIT;

use Exception;

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class WPForms
 * Handles WPForms integration
 */
class WPForms
{
    /**
     * Core plugin instance.
     *
     * @var Core
     */
    private $core;

    /**
     * Initialize the WPForms handler.
     */
    public function init()
    {
        error_log('DIT WPForms: Initialization started');

        try {
            $this->core = Core::get_instance();
            error_log('DIT WPForms: Core instance obtained');

            // Check if WPForms plugin is active
            if (!class_exists('WPForms')) {
                error_log('DIT WPForms: ERROR - WPForms plugin is not active');
                return;
            }
            error_log('DIT WPForms: WPForms plugin is active');

            // Register hooks with error handling
            try {
                add_action('wpforms_process_complete', [$this, 'handle_form_submission'], 10, 4);
                error_log('DIT WPForms: wpforms_process_complete hook registered successfully');
            } catch (Exception $e) {
                error_log('DIT WPForms: ERROR - Failed to register wpforms_process_complete hook: ' . $e->getMessage());
            }

            try {
                add_action('wpforms_process', [$this, 'handle_payment'], 10, 3);
                error_log('DIT WPForms: wpforms_process hook registered successfully');
            } catch (Exception $e) {
                error_log('DIT WPForms: ERROR - Failed to register wpforms_process hook: ' . $e->getMessage());
            }

            // Hook to process checkbox values (changed to wpforms_process to avoid duplicate wpforms_process_complete)
            try {
                add_action('wpforms_process', [$this, 'process_checkbox_values'], 5, 3);
                error_log('DIT WPForms: process_checkbox_values hook registered successfully (wpforms_process)');
            } catch (Exception $e) {
                error_log('DIT WPForms: ERROR - Failed to register process_checkbox_values hook: ' . $e->getMessage());
            }

            // Add AJAX response filter to ensure proper JSON output
            try {
                add_filter('wpforms_ajax_success_response_data', [$this, 'filter_ajax_response'], 10, 4);
                error_log('DIT WPForms: AJAX response filter registered successfully');
            } catch (Exception $e) {
                error_log('DIT WPForms: ERROR - Failed to register AJAX response filter: ' . $e->getMessage());
            }

            error_log('DIT WPForms: Initialization completed successfully');
        } catch (Exception $e) {
            error_log('DIT WPForms: CRITICAL ERROR during initialization: ' . $e->getMessage());
            error_log('DIT WPForms: Exception trace: ' . $e->getTraceAsString());
        }
    }

    /**
     * Filter AJAX response to ensure proper JSON output
     */
    public function filter_ajax_response($response_data, $form_data, $fields, $entry_id)
    {
        error_log('DIT WPForms: Filtering AJAX response for form ' . $form_data['id']);

        // Ensure response is properly formatted
        if (!is_array($response_data)) {
            $response_data = [];
        }

        // Add our custom data if needed
        $response_data['dit_processed'] = true;
        $response_data['form_id'] = $form_data['id'];
        $response_data['entry_id'] = $entry_id;

        // Add success message and redirect if this was a signup
        $settings = get_option('dit_settings');
        $signup_form = $settings['signup_form'] ?? '';

        if ($form_data['id'] == $signup_form) {
            $response_data['message'] = __('Registration successful! You can now log in.', 'dit-integration');
            $response_data['redirect'] = home_url('/wp-login.php');
        }

        error_log('DIT WPForms: AJAX response filtered successfully');

        return $response_data;
    }

    /**
     * Handle form submission.
     *
     * @param array $fields Form fields.
     * @param array $entry Form entry.
     * @param array $form_data Form data.
     * @param int $entry_id Entry ID.
     */
    public function handle_form_submission($fields, $entry, $form_data, $entry_id)
    {
        error_log('DIT WPForms: Form submission started');
        error_log('DIT WPForms: Form ID: ' . ($form_data['id'] ?? 'unknown'));
        error_log('DIT WPForms: Entry ID: ' . $entry_id);
        error_log('DIT WPForms: Fields count: ' . count($fields));

        try {
            // Get settings
            $settings = get_option('dit_settings');
            $signup_form = $settings['signup_form'] ?? '';
            $signin_form = $settings['signin_form'] ?? '';

            error_log('DIT WPForms: Settings loaded - signup_form: ' . $signup_form . ', signin_form: ' . $signin_form);

            // Check if this form should be processed (either signup or signin)
            if (empty($signup_form) && empty($signin_form)) {
                error_log('DIT WPForms: No forms configured for processing');
                return; // No forms configured
            }

            $form_id = $form_data['id'];
            $is_signup_form = ($form_id == $signup_form);
            $is_signin_form = ($form_id == $signin_form);

            error_log('DIT WPForms: Form type check - is_signup: ' . ($is_signup_form ? 'true' : 'false') . ', is_signin: ' . ($is_signin_form ? 'true' : 'false'));

            if (!$is_signup_form && !$is_signin_form) {
                error_log('DIT WPForms: Form ' . $form_id . ' is not configured for processing');
                return; // This form is not configured for processing
            }

            // Determine form type for logging
            $form_type = $is_signup_form ? 'signup' : 'signin';
            error_log('DIT WPForms: Processing ' . $form_type . ' form');

            // Get form fields
            $form_fields = $form_data['fields'];
            $submitted_data = [];

            // Process each field
            foreach ($fields as $field) {
                $field_id = $field['id'];
                $field_type = $form_fields[$field_id]['type'];
                $field_value = $field['value'];

                // Include all fields for debugging, even empty ones
                $submitted_data[$field_id] = [
                    'type' => $field_type,
                    'value' => $field_value,
                    'is_empty' => empty($field_value)
                ];
            }

            error_log('DIT WPForms: Processed ' . count($submitted_data) . ' form fields');

            // Log all submitted fields for debugging
            $core = Core::get_instance();
            $logger = $core->logger;
            $logger->log_form_submission(
                $form_data['id'],
                [
                    'form_type' => $form_type,
                    'step' => 'form_processing_start',
                    'timestamp' => current_time('Y-m-d H:i:s'),
                    'submitted_fields_count' => count($submitted_data)
                ]
            );

            // Process based on form type - use process_form_submission for both signup and signin
            // as it contains the proper API logic for authentication
            error_log('DIT WPForms: Calling process_form_submission for form type: ' . $form_type . ' with ' . count($submitted_data) . ' fields');
            $this->process_form_submission($submitted_data, $form_data, $form_type);
        } catch (Exception $e) {
            error_log('DIT WPForms: CRITICAL ERROR during form submission: ' . $e->getMessage());
            error_log('DIT WPForms: Exception trace: ' . $e->getTraceAsString());
        }
    }

    /**
     * Process signup form submission
     */
    private function process_signup_form($user_data, $entry_id)
    {
        // ANTI-DUPLICATE PROTECTION: Prevent multiple simultaneous processing of the same email
        static $processing_emails = [];
        $email = $user_data['email'] ?? '';

        if (in_array($email, $processing_emails)) {
            error_log('DIT WPForms: DUPLICATE REQUEST PREVENTED for email: ' . $email);
            return; // Stop processing duplicate
        }

        $processing_emails[] = $email;

        error_log('DIT WPForms: Processing signup form for email: ' . $email);

        try {
            // Step 1: Register customer with DIT API
            $customer_result = $this->register_customer_with_dit($user_data);

            if (!$customer_result || !isset($customer_result['customer_id'])) {
                error_log('DIT WPForms: ERROR - Customer registration failed');
                return;
            }

            $customer_id = $customer_result['customer_id'];
            error_log('DIT WPForms: Customer registered successfully with ID: ' . $customer_id);

            // Step 2: Create WordPress user
            $wp_user_id = $this->create_wordpress_user($user_data, $customer_id);

            if (!$wp_user_id) {
                error_log('DIT WPForms: ERROR - WordPress user creation failed');
                return;
            }

            error_log('DIT WPForms: WordPress user created successfully with ID: ' . $wp_user_id);

            // Note: Database functionality has been removed
            error_log('DIT WPForms: Database functionality removed - user data not saved to custom tables');

            // Step 4: Update settings with new user
            $this->update_plugin_settings($customer_id, $user_data, $wp_user_id);

            error_log('DIT WPForms: Signup process completed successfully for customer ID: ' . $customer_id);
        } catch (Exception $e) {
            error_log('DIT WPForms: ERROR during signup processing: ' . $e->getMessage());
        } finally {
            // ANTI-DUPLICATE CLEANUP: Remove email from processing array
            $key = array_search($email, $processing_emails);
            if ($key !== false) {
                unset($processing_emails[$key]);
            }
        }
    }

    /**
     * Create WordPress user
     */
    private function create_wordpress_user($user_data, $customer_id)
    {
        error_log('DIT WPForms: Creating WordPress user for email: ' . $user_data['email']);

        try {
            // Check if user already exists
            $existing_user = get_user_by('email', $user_data['email']);
            if ($existing_user) {
                error_log('DIT WPForms: User already exists with ID: ' . $existing_user->ID);
                return $existing_user->ID;
            }

            // Prepare user data
            $username = sanitize_user($user_data['email']);
            $email = sanitize_email($user_data['email']);
            $password = $user_data['password'] ?? wp_generate_password();

            // Create user
            $user_id = wp_create_user($username, $password, $email);

            if (is_wp_error($user_id)) {
                error_log('DIT WPForms: ERROR creating WordPress user: ' . $user_id->get_error_message());
                return false;
            }

            // Update user meta
            wp_update_user([
                'ID' => $user_id,
                'first_name' => $user_data['first_name'] ?? '',
                'last_name' => $user_data['last_name'] ?? '',
                'display_name' => $user_data['name'] ?? $user_data['first_name'] . ' ' . $user_data['last_name']
            ]);

            // Add custom meta
            update_user_meta($user_id, 'dit_customer_id', $customer_id);
            update_user_meta($user_id, 'dit_role_id', $user_data['role_id'] ?? 2);

            if (!empty($user_data['company'])) {
                update_user_meta($user_id, 'company', $user_data['company']);
            }

            error_log('DIT WPForms: WordPress user created successfully with ID: ' . $user_id);
            return $user_id;
        } catch (Exception $e) {
            error_log('DIT WPForms: ERROR during WordPress user creation: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Update plugin settings with new user
     */
    private function update_plugin_settings($customer_id, $user_data, $wp_user_id)
    {
        error_log('DIT WPForms: Updating plugin settings for customer ID: ' . $customer_id);

        try {
            // Get current settings
            $current_settings = get_option('dit_settings', []);

            // Initialize registered_users if not exists
            if (!isset($current_settings['registered_users'])) {
                $current_settings['registered_users'] = [];
            }

            // Add new user
            $current_settings['registered_users'][$customer_id] = [
                'name' => $user_data['name'] ?? $user_data['first_name'] . ' ' . $user_data['last_name'],
                'customer_id' => $customer_id,
                'registration_date' => current_time('Y-m-d H:i:s'),
                'last_updated' => current_time('Y-m-d H:i:s'),
                'aes_key_stored_in_cookie' => true,
                'first_name' => $user_data['first_name'] ?? '',
                'last_name' => $user_data['last_name'] ?? '',
                'company' => $user_data['company'] ?? '',
                'email' => $user_data['email'],
                'role' => $user_data['role_id'] ?? 2,
                'max_seats' => 10,
                'initial_user_created' => true,
                'wp_user_id' => $wp_user_id
            ];

            // Update settings
            $update_result = update_option('dit_settings', $current_settings);

            if ($update_result) {
                error_log('DIT WPForms: Plugin settings updated successfully');
            } else {
                error_log('DIT WPForms: WARNING - Plugin settings update returned false');
            }
        } catch (Exception $e) {
            error_log('DIT WPForms: ERROR updating plugin settings: ' . $e->getMessage());
        }
    }

    private function process_form_submission($submitted_data, $form_data, $form_type)
    {
        error_log('DIT WPForms: process_form_submission called for form type: ' . $form_type . ' with form ID: ' . $form_data['id']);

        $core = Core::get_instance();
        $logger = $core->logger;
        $api = $core->api;

        // Check if API is available
        if ($api === null) {
            $logger->log_form_submission(
                $form_data['id'],
                [
                    'form_type' => $form_type,
                    'step' => 'api_not_available',
                    'error' => 'API class not initialized'
                ],
                'error',
                'API class not available - registration cannot proceed'
            );
            return false;
        }

        try {
            if ($form_type === 'signup') {
                // Handle signup form
                $logger->log_form_submission(
                    $form_data['id'],
                    [
                        'form_type' => $form_type,
                        'step' => 'signup_start',
                        'timestamp' => current_time('mysql'),
                        'submitted_fields_count' => count($submitted_data)
                    ],
                    'info',
                    'Starting Sign Up process'
                );

                $user_data = $this->extract_user_data($submitted_data, $form_data);
                if (empty($user_data)) {
                    $logger->log_form_submission(
                        $form_data['id'],
                        [
                            'form_type' => $form_type,
                            'step' => 'extract_data_failed',
                            'submitted_fields' => array_keys($submitted_data),
                            'submitted_data' => $submitted_data
                        ],
                        'error',
                        'Could not extract user data from signup form submission'
                    );
                    return false;
                }

                $logger->log_form_submission(
                    $form_data['id'],
                    [
                        'form_type' => $form_type,
                        'step' => 'extract_data_success',
                        'has_email' => !empty($user_data['email']),
                        'has_password' => !empty($user_data['password']),
                        'has_name' => !empty($user_data['name']),
                        'email' => $user_data['email'],
                        'name' => $user_data['name'] ?? 'not_provided',
                        'password_length' => strlen($user_data['password']),
                        'user_data_keys' => array_keys($user_data)
                    ],
                    'info',
                    'User data extracted successfully for registration'
                );

                // Register customer with DIT API
                $logger->log_form_submission(
                    $form_data['id'],
                    [
                        'form_type' => $form_type,
                        'step' => 'register_customer_api_request',
                        'email' => $user_data['email'],
                        'name' => $user_data['name'] ?? 'not_provided',
                        'password_length' => strlen($user_data['password']),
                        'user_data' => $user_data
                    ],
                    'info',
                    'Sending registration data to DIT API'
                );

                $customer_id = $api->register_customer($user_data);

                $logger->log_form_submission(
                    $form_data['id'],
                    [
                        'form_type' => $form_type,
                        'step' => 'register_customer_api_response',
                        'email' => $user_data['email'],
                        'customer_id' => $customer_id,
                        'registration_success' => $customer_id !== null,
                        'customer_id_type' => gettype($customer_id),
                        'user_data_sent' => $user_data
                    ],
                    $customer_id !== null ? 'success' : 'error',
                    $customer_id !== null ? 'Customer registered successfully with ID: ' . $customer_id : 'Customer registration failed'
                );

                if ($customer_id === null) {
                    $logger->log_form_submission(
                        $form_data['id'],
                        [
                            'form_type' => $form_type,
                            'step' => 'register_customer_failed',
                            'email' => $user_data['email'],
                            'user_data' => $user_data
                        ],
                        'error',
                        'Customer registration failed - API returned null'
                    );
                    return false;
                }

                $logger->log_form_submission(
                    $form_data['id'],
                    [
                        'form_type' => $form_type,
                        'step' => 'register_customer_success',
                        'email' => $user_data['email'],
                        'customer_id' => $customer_id,
                        'registration_complete' => true
                    ],
                    'success',
                    'Customer registration completed successfully'
                );

                // Step 2: Automatically create a User account for this Customer
                $logger->log_form_submission(
                    $form_data['id'],
                    [
                        'form_type' => $form_type,
                        'step' => 'create_user_for_customer_start',
                        'email' => $user_data['email'],
                        'customer_id' => $customer_id,
                        'user_data' => $user_data
                    ],
                    'info',
                    'Starting automatic User creation for Customer'
                );

                // Create user with role 1 (User) for this Customer
                $user_data_for_api = [
                    'first_name' => $user_data['first_name'] ?? '',
                    'last_name' => $user_data['last_name'] ?? '',
                    'email' => $user_data['email'],
                    'password' => $user_data['password'],
                    'tools' => $user_data['tools'] ?? [],
                    'aes_key' => '', // Will be retrieved from customer storage
                    'role_id' => 1 // User role (1)
                ];

                $logger->log_form_submission(
                    $form_data['id'],
                    [
                        'form_type' => $form_type,
                        'step' => 'register_user_api_request',
                        'email' => $user_data['email'],
                        'customer_id' => $customer_id,
                        'user_data' => $user_data_for_api,
                        'role_id' => 1
                    ],
                    'info',
                    'Sending user registration data with role 1 to DIT API'
                );

                // Register user with role 1 through API
                $user_id = $api->register_user_rsa($user_data_for_api, $customer_id);

                $logger->log_form_submission(
                    $form_data['id'],
                    [
                        'form_type' => $form_type,
                        'step' => 'register_user_api_response',
                        'email' => $user_data['email'],
                        'customer_id' => $customer_id,
                        'user_id' => $user_id,
                        'user_success' => $user_id !== null,
                        'role_id' => 1
                    ],
                    $user_id !== null ? 'success' : 'error',
                    $user_id !== null ? 'User with role 1 registered successfully with ID: ' . $user_id : 'User registration failed'
                );

                if ($user_id === null) {
                    $logger->log_form_submission(
                        $form_data['id'],
                        [
                            'form_type' => $form_type,
                            'step' => 'user_registration_failed',
                            'email' => $user_data['email'],
                            'customer_id' => $customer_id,
                            'role_id' => 1
                        ],
                        'error',
                        'User registration failed - API returned null'
                    );
                    // Continue anyway as customer was created successfully
                } else {
                    $logger->log_form_submission(
                        $form_data['id'],
                        [
                            'form_type' => $form_type,
                            'step' => 'user_registration_success',
                            'email' => $user_data['email'],
                            'customer_id' => $customer_id,
                            'user_id' => $user_id,
                            'role_id' => 1
                        ],
                        'success',
                        'User with role 1 created successfully'
                    );
                }

                // Step 3: Save Customer data to session (user with role 1 created through API)
                if (!isset($_SESSION['dit_registered_customers'])) {
                    $_SESSION['dit_registered_customers'] = [];
                }

                // Save Customer data in session
                $_SESSION['dit_registered_customers'][$customer_id] = [
                    'name' => $user_data['name'] ?? $user_data['first_name'] ?? 'Customer',
                    'customer_id' => $customer_id,
                    'registration_date' => current_time('mysql'),
                    'last_updated' => current_time('mysql'),
                    'first_name' => $user_data['first_name'] ?? '',
                    'last_name' => $user_data['last_name'] ?? '',
                    'company' => $user_data['company'] ?? '',
                    'email' => $user_data['email'],
                    'role' => 2, // Customer role
                    'max_seats' => 10, // Maximum seats for this customer
                    'user_created' => true, // User with role 1 created through API
                    'user_id' => $user_id ?? null
                ];

                $logger->log_form_submission(
                    $form_data['id'],
                    [
                        'form_type' => $form_type,
                        'step' => 'save_to_session',
                        'email' => $user_data['email'],
                        'customer_id' => $customer_id,
                        'user_created' => true,
                        'user_id' => $user_id ?? null,
                        'session_data_stored' => true
                    ],
                    'info',
                    'Customer data saved to session'
                );
            } elseif ($form_type === 'signin') {
                // Handle signin form
                $logger->log_form_submission(
                    $form_data['id'],
                    [
                        'form_type' => $form_type,
                        'step' => 'signin_start',
                        'timestamp' => current_time('mysql'),
                        'submitted_fields_count' => count($submitted_data)
                    ],
                    'info',
                    'Starting Sign In process'
                );

                $user_data = $this->extract_signin_data($submitted_data, $form_data);
                if (empty($user_data)) {
                    $logger->log_form_submission(
                        $form_data['id'],
                        [
                            'form_type' => $form_type,
                            'step' => 'extract_data_failed',
                            'submitted_fields' => array_keys($submitted_data),
                            'submitted_data' => $submitted_data
                        ],
                        'error',
                        'Could not extract user data from signin form submission'
                    );
                    return false;
                }

                $logger->log_form_submission(
                    $form_data['id'],
                    [
                        'form_type' => $form_type,
                        'step' => 'extract_data_success',
                        'has_email' => !empty($user_data['email']),
                        'has_password' => !empty($user_data['password']),
                        'has_role_id' => !empty($user_data['role_id']),
                        'email' => $user_data['email'],
                        'password_length' => strlen($user_data['password']),
                        'role_id' => $user_data['role_id'] ?? 'not_provided',
                        'user_data_keys' => array_keys($user_data)
                    ],
                    'info',
                    'User data extracted successfully for login'
                );

                $logger->log_form_submission(
                    $form_data['id'],
                    [
                        'form_type' => $form_type,
                        'step' => 'get_login_roles_start',
                        'email' => $user_data['email']
                    ],
                    'info',
                    'Starting get_login_roles_for_email with API'
                );

                $roles = $api->get_login_roles_for_email($user_data['email']);

                $logger->log_form_submission(
                    $form_data['id'],
                    [
                        'form_type' => $form_type,
                        'step' => 'get_login_roles_result',
                        'email' => $user_data['email'],
                        'roles_result' => $roles,
                        'roles_count' => is_array($roles) ? count($roles) : 0,
                        'roles_success' => is_array($roles) && count($roles) > 0,
                        'roles_type' => gettype($roles)
                    ],
                    (is_array($roles) && count($roles) > 0) ? 'info' : 'error',
                    (is_array($roles) && count($roles) > 0) ? 'Roles received: ' . implode(', ', $roles) : 'No roles found for email'
                );

                if (!is_array($roles) || count($roles) === 0) {
                    $logger->log_form_submission(
                        $form_data['id'],
                        [
                            'form_type' => $form_type,
                            'step' => 'get_login_roles_failed',
                            'email' => $user_data['email'],
                            'roles_result' => $roles
                        ],
                        'error',
                        'No roles found for this email'
                    );

                    // Try to create user with role 1 if no roles found
                    $logger->log_form_submission(
                        $form_data['id'],
                        [
                            'form_type' => $form_type,
                            'step' => 'create_user_attempt',
                            'email' => $user_data['email'],
                            'note' => 'No roles found, attempting to create user with role 1'
                        ],
                        'info',
                        'Attempting to create user with role 1 since no roles were found'
                    );

                    // Get customer ID from session
                    $customer_id = null;
                    if (isset($_SESSION['dit_registered_customers'])) {
                        foreach ($_SESSION['dit_registered_customers'] as $id => $user_info) {
                            if ($user_info['email'] === $user_data['email']) {
                                $customer_id = $id;
                                break;
                            }
                        }
                    }

                    if ($customer_id) {
                        // Create user with role 1
                        $user_data_for_api = [
                            'first_name' => $user_data['first_name'] ?? '',
                            'last_name' => $user_data['last_name'] ?? '',
                            'email' => $user_data['email'],
                            'password' => $user_data['password'],
                            'tools' => $user_data['tools'] ?? [],
                            'aes_key' => '', // Will be retrieved from customer storage
                            'role_id' => 1 // User role (1)
                        ];

                        $user_id = $api->register_user_rsa($user_data_for_api, $customer_id);

                        if ($user_id) {
                            $logger->log_form_submission(
                                $form_data['id'],
                                [
                                    'form_type' => $form_type,
                                    'step' => 'user_creation_success',
                                    'email' => $user_data['email'],
                                    'customer_id' => $customer_id,
                                    'user_id' => $user_id,
                                    'role_id' => 1
                                ],
                                'success',
                                'User with role 1 created successfully during login'
                            );

                            // Continue with login using role 1
                            $selected_role = 1;
                        } else {
                            $logger->log_form_submission(
                                $form_data['id'],
                                [
                                    'form_type' => $form_type,
                                    'step' => 'user_creation_failed',
                                    'email' => $user_data['email'],
                                    'customer_id' => $customer_id
                                ],
                                'error',
                                'Failed to create user with role 1'
                            );

                            // Show user-friendly error message
                            $this->show_access_denied_message($form_data['id'], 'У вас немає прав для доступу до цієї сторінки. Зверніться до адміністратора для отримання доступу.');
                            return false;
                        }
                    } else {
                        // Show user-friendly error message
                        $this->show_access_denied_message($form_data['id'], 'У вас немає прав для доступу до цієї сторінки. Зверніться до адміністратора для отримання доступу.');
                        return false;
                    }
                }

                // Визначаємо роль (тільки якщо не встановлено раніше)
                if (!isset($selected_role)) {
                    $selected_role = null;
                    if (count($roles) === 1) {
                        $selected_role = $roles[0];
                        $logger->log_form_submission(
                            $form_data['id'],
                            [
                                'form_type' => $form_type,
                                'step' => 'role_auto_selected',
                                'email' => $user_data['email'],
                                'selected_role' => $selected_role,
                                'roles_available' => $roles
                            ],
                            'info',
                            'Role auto-selected (only one available): ' . $selected_role
                        );
                    } else {
                        // Якщо кілька ролей — шукаємо у даних форми (має бути додаткове поле, наприклад, role_id)
                        $selected_role = $user_data['role_id'] ?? null;
                        $logger->log_form_submission(
                            $form_data['id'],
                            [
                                'form_type' => $form_type,
                                'step' => 'role_selection_check',
                                'email' => $user_data['email'],
                                'roles_available' => $roles,
                                'user_selected_role' => $selected_role,
                                'role_valid' => $selected_role && in_array($selected_role, $roles)
                            ],
                            ($selected_role && in_array($selected_role, $roles)) ? 'info' : 'error',
                            ($selected_role && in_array($selected_role, $roles)) ? 'User role selected: ' . $selected_role : 'Role not selected or invalid'
                        );

                        if (!$selected_role || !in_array($selected_role, $roles)) {
                            $logger->log_form_submission(
                                $form_data['id'],
                                [
                                    'form_type' => $form_type,
                                    'step' => 'role_not_selected',
                                    'email' => $user_data['email'],
                                    'roles' => $roles,
                                    'user_selected_role' => $selected_role
                                ],
                                'error',
                                'Role not selected or invalid for this email'
                            );
                            return false;
                        }
                    }
                }

                // Step 2: Login with WebLogin API using steganographic encryption
                $logger->log_form_submission(
                    $form_data['id'],
                    [
                        'form_type' => $form_type,
                        'step' => 'weblogin_api_request',
                        'email' => $user_data['email'],
                        'role_id' => $selected_role,
                        'password_length' => strlen($user_data['password']),
                        'login_data' => [
                            'email' => $user_data['email'],
                            'role_id' => $selected_role,
                            'password_length' => strlen($user_data['password'])
                        ]
                    ],
                    'info',
                    'Sending login data to WebLogin API with steganographic encryption (developer procedure)'
                );

                // Note: Steganography creation is now handled internally by login_with_steganography method
                // This follows the developer's procedure exactly

                // Call WebLogin API with plain text password (as per developer procedure)
                // The method now handles steganographic encryption internally
                $login_result = $api->login_with_steganography(
                    $user_data['email'],
                    $user_data['password'], // Plain text password, not hash
                    $selected_role
                );

                $logger->log_form_submission(
                    $form_data['id'],
                    [
                        'form_type' => $form_type,
                        'step' => 'weblogin_api_response',
                        'email' => $user_data['email'],
                        'role_id' => $selected_role,
                        'login_result' => $login_result,
                        'login_success' => $login_result !== null,
                        'has_user_id' => isset($login_result['UserId']),
                        'user_id' => $login_result['UserId'] ?? null,
                        'error_code' => $login_result['errorcode'] ?? null,
                        'error_message' => $login_result['errormessage'] ?? null,
                        'response_type' => gettype($login_result),
                        'note' => 'WebLogin API response received (developer procedure step 6 completed)'
                    ],
                    $login_result !== null ? 'info' : 'error',
                    $login_result !== null ? 'WebLogin API call completed successfully' : 'WebLogin API call failed'
                );

                if ($login_result === null) {
                    $logger->log_form_submission(
                        $form_data['id'],
                        [
                            'form_type' => $form_type,
                            'step' => 'weblogin_failed_null',
                            'email' => $user_data['email'],
                            'role_id' => $selected_role,
                            'login_result' => $login_result,
                            'note' => 'WebLogin API failed - API returned null'
                        ],
                        'error',
                        'WebLogin API failed - API returned null'
                    );
                    return false;
                }

                // Check for login errors
                if (isset($login_result['errorcode']) && $login_result['errorcode'] !== 0) {
                    $logger->log_form_submission(
                        $form_data['id'],
                        [
                            'form_type' => $form_type,
                            'step' => 'weblogin_error_code',
                            'email' => $user_data['email'],
                            'role_id' => $selected_role,
                            'error_code' => $login_result['errorcode'],
                            'error_message' => $login_result['errormessage'] ?? 'No error message',
                            'full_response' => $login_result,
                            'response_keys' => array_keys($login_result),
                            'note' => 'WebLogin API failed with error code'
                        ],
                        'error',
                        'WebLogin API failed with error code: ' . $login_result['errorcode'] . ' - ' . ($login_result['errormessage'] ?? 'No error message')
                    );
                    return false;
                }

                $logger->log_form_submission(
                    $form_data['id'],
                    [
                        'form_type' => $form_type,
                        'step' => 'weblogin_success',
                        'email' => $user_data['email'],
                        'role_id' => $selected_role,
                        'user_id' => $login_result['UserId'] ?? null,
                        'error_code' => $login_result['errorcode'] ?? null,
                        'login_result_keys' => array_keys($login_result),
                        'full_login_response' => $login_result,
                        'note' => 'WebLogin API successful - all developer procedure steps completed'
                    ],
                    'success',
                    'WebLogin API successful - proceeding to database sync'
                );

                // Step 3: Validate API response data
                $user_id = $login_result['UserId'] ?? null;

                if (!$user_id) {
                    $logger->log_form_submission(
                        $form_data['id'],
                        [
                            'step' => 'missing_user_id',
                            'login_result' => $login_result,
                            'available_fields' => array_keys($login_result)
                        ],
                        'error',
                        'User ID not found in API response'
                    );
                    return false;
                }

                $logger->log_form_submission(
                    $form_data['id'],
                    [
                        'form_type' => $form_type,
                        'step' => 'api_validation_success',
                        'user_id' => $user_id,
                        'role' => $selected_role,
                        'has_aes_key' => !empty($login_result['AesKey']),
                        'aes_key_length' => strlen($login_result['AesKey'] ?? '')
                    ],
                    'success',
                    'API validation successful - proceeding to database sync'
                );

                // Step 4: Update AES key storage with customer_id for compatibility
                // ВАЖЛИВО: Це має бути викликано ТІЛЬКИ для legacy RSA реєстрацій, НЕ для нових стеганографічних логінів
                if ($user_id && $steganography_data) {
                    $logger->log_form_submission(
                        $form_data['id'],
                        [
                            'form_type' => $form_type,
                            'step' => 'aes_key_update_skipped',
                            'user_id' => $user_id,
                            'role_id' => $selected_role,
                            'steganography_available' => !empty($steganography_data),
                            'note' => 'Skipping AES key update - new steganography login, no legacy conversion needed'
                        ],
                        'info',
                        'Skipping AES key storage update for customer_id: ' . $user_id . ' (new steganography login)'
                    );

                    // НЕ викликаємо update_aes_key_storage для нових стеганографічних логінів
                    // Це запобігає перезапису стеганографічного ключа legacy ключем
                }



                // Step 5: Begin session (optional - can be done later when user starts using tools)
                if ($user_id) {
                    // Get settings for license type and tool type
                    $settings = get_option('dit_settings', []);
                    $license_type = ($settings['license_type'] ?? 'unlimited') === 'metered' ? 0 : 1;
                    $tool_type = 0; // Default to VFX, can be made configurable

                    $logger->log_form_submission(
                        $form_data['id'],
                        [
                            'form_type' => $form_type,
                            'step' => 'session_start',
                            'email' => $user_data['email'],
                            'user_id' => $user_id,
                            'role_id' => $selected_role,
                            'license_type' => $license_type,
                            'license_type_name' => $license_type === 0 ? 'Metered' : 'Time-based',
                            'tool_type' => $tool_type,
                            'tool_type_name' => 'VFX',
                            'session_data' => [
                                'user_id' => $user_id,
                                'license_type' => $license_type,
                                'tool_type' => $tool_type
                            ]
                        ],
                        'info',
                        'BeginSession API removed - proceeding to Session Manager initialization'
                    );

                    // BeginSession API removed - only needed for tools
                    // Session creation is now handled by Session Manager directly
                    $session_result = null;

                    $logger->log_form_submission(
                        $form_data['id'],
                        [
                            'form_type' => $form_type,
                            'step' => 'session_result',
                            'email' => $user_data['email'],
                            'user_id' => $user_id,
                            'role_id' => $selected_role,
                            'session_result' => $session_result,
                            'session_success' => true, // Always true since API removed
                            'has_session_id' => false, // No session ID from API
                            'session_id' => null,
                            'remaining_seconds' => null,
                            'session_error' => null,
                            'session_result_keys' => [],
                            'full_session_response' => null,
                            'note' => 'BeginSession API removed - session creation handled by Session Manager'
                        ],
                        'info',
                        'BeginSession API removed - proceeding to Session Manager initialization'
                    );

                    // Initialize session with Session Manager
                    $session_manager = new Session_Manager();
                    $session_init_success = $session_manager->init_session($login_result, $user_data, $session_result);

                    $logger->log_form_submission(
                        $form_data['id'],
                        [
                            'form_type' => $form_type,
                            'step' => 'session_manager_init',
                            'email' => $user_data['email'],
                            'user_id' => $user_id,
                            'role_id' => $selected_role,
                            'session_init_success' => $session_init_success,
                            'session_manager_available' => class_exists('DIT\\Session_Manager'),
                            'login_result_keys' => array_keys($login_result),
                            'user_data_keys' => array_keys($user_data)
                        ],
                        $session_init_success ? 'info' : 'error',
                        $session_init_success ? 'Session manager initialization completed' : 'Session manager initialization failed'
                    );

                    if ($session_init_success) {
                        $logger->log_form_submission(
                            $form_data['id'],
                            [
                                'form_type' => $form_type,
                                'step' => 'session_initialized',
                                'email' => $user_data['email'],
                                'user_id' => $user_id,
                                'role_id' => $selected_role,
                                'session_id' => null, // No session ID from BeginSession API
                                'remaining_seconds' => null, // No remaining seconds from BeginSession API
                                'user_role' => $session_manager->get_user_role(),
                                'session_data_stored' => true,
                                'login_complete' => true,
                                'note' => 'BeginSession API removed - session data managed by Session Manager'
                            ],
                            'success',
                            'Login and session initialization successful - redirecting to dashboard'
                        );

                        // Redirect to dashboard page after successful login
                        $settings = get_option('dit_settings', []);
                        $dashboard_page_id = isset($settings['dashboard_page_id']) ? (int)$settings['dashboard_page_id'] : 0;

                        if ($dashboard_page_id) {
                            $redirect_url = get_permalink($dashboard_page_id);
                        } else {
                            // Fallback to home page if no dashboard page is configured
                            $redirect_url = home_url();
                        }

                        $logger->log_form_submission(
                            $form_data['id'],
                            [
                                'form_type' => $form_type,
                                'step' => 'redirect',
                                'email' => $user_data['email'],
                                'user_id' => $user_id,
                                'role_id' => $selected_role,
                                'dashboard_page_id' => $dashboard_page_id,
                                'redirect_url' => $redirect_url
                            ],
                            'success',
                            'Redirecting to: ' . $redirect_url
                        );

                        wp_redirect($redirect_url);
                        exit;
                    } else {
                        $logger->log_form_submission(
                            $form_data['id'],
                            [
                                'form_type' => $form_type,
                                'step' => 'session_init_failed',
                                'email' => $user_data['email'],
                                'user_id' => $user_id,
                                'role_id' => $selected_role,
                                'session_result' => $session_result,
                                'session_manager_available' => class_exists('DIT\\Session_Manager'),
                                'login_result_keys' => array_keys($login_result),
                                'user_data_keys' => array_keys($user_data),
                                'session_init_success' => $session_init_success
                            ],
                            'error',
                            'Login successful but session initialization failed'
                        );
                        return false;
                    }
                } else {
                    $logger->log_form_submission(
                        $form_data['id'],
                        [
                            'form_type' => $form_type,
                            'step' => 'no_user_id',
                            'email' => $user_data['email'],
                            'role_id' => $selected_role,
                            'login_result' => $login_result,
                            'login_result_keys' => $login_result ? array_keys($login_result) : [],
                            'has_user_id' => isset($login_result['UserId']),
                            'user_id_value' => $login_result['UserId'] ?? null,
                            'login_success' => $login_result !== null,
                            'error_code' => $login_result['errorcode'] ?? null
                        ],
                        'error',
                        'Login successful but no user ID returned'
                    );
                    return false;
                }

                $logger->log_form_submission(
                    $form_data['id'],
                    [
                        'form_type' => $form_type,
                        'step' => 'signin_complete',
                        'email' => $user_data['email'],
                        'role_id' => $selected_role,
                        'user_id' => $user_id ?? null,
                        'session_id' => $session_result['SessionId'] ?? null,
                        'process_success' => true,
                        'login_complete' => true
                    ],
                    'success',
                    'Sign In process completed successfully'
                );
            }

            return true;
        } catch (Exception $e) {
            $logger->log_form_submission(
                $form_data['id'],
                [
                    'form_type' => $form_type,
                    'error' => $e->getMessage()
                ],
                'error',
                'Exception during form processing'
            );
            return false;
        }
    }

    /**
     * Extract user data from form fields
     */
    private function extract_user_data($submitted_data, $form_fields, $form_type = 'signup')
    {
        error_log('DIT WPForms: Extracting user data from form fields');

        try {
            $user_data = [];

            foreach ($submitted_data as $field_id => $field) {
                $field_type = $field['type'];
                $field_value = $field['value'];

                // Map form fields to user data
                switch ($field_type) {
                    case 'name':
                        // Handle name field (can be first/last or full name)
                        if (is_array($field_value)) {
                            $user_data['first_name'] = $field_value['first'] ?? '';
                            $user_data['last_name'] = $field_value['last'] ?? '';
                            $user_data['name'] = trim($user_data['first_name'] . ' ' . $user_data['last_name']);
                        } else {
                            $user_data['name'] = $field_value;
                            // Try to split full name
                            $name_parts = explode(' ', $field_value, 2);
                            $user_data['first_name'] = $name_parts[0] ?? '';
                            $user_data['last_name'] = $name_parts[1] ?? '';
                        }
                        break;

                    case 'text':
                        // Handle text fields - check field label or ID for specific mapping
                        $field_label = strtolower($form_fields[$field_id]['label'] ?? '');
                        if (strpos($field_label, 'first') !== false || strpos($field_label, 'ім\'я') !== false) {
                            $user_data['first_name'] = $field_value;
                        } elseif (strpos($field_label, 'last') !== false || strpos($field_label, 'прізвище') !== false) {
                            $user_data['last_name'] = $field_value;
                        } elseif (strpos($field_label, 'company') !== false || strpos($field_label, 'компанія') !== false) {
                            $user_data['company'] = $field_value;
                        } else {
                            // Generic text field - store as description if not already set
                            if (!isset($user_data['description'])) {
                                $user_data['description'] = $field_value;
                            }
                        }
                        break;

                    case 'textarea':
                        // Handle textarea fields
                        $field_label = strtolower($form_fields[$field_id]['label'] ?? '');
                        if (strpos($field_label, 'description') !== false || strpos($field_label, 'опис') !== false) {
                            $user_data['description'] = $field_value;
                        } elseif (strpos($field_label, 'notes') !== false || strpos($field_label, 'нотатки') !== false) {
                            $user_data['notes'] = $field_value;
                        } else {
                            // Generic textarea - store as description if not already set
                            if (!isset($user_data['description'])) {
                                $user_data['description'] = $field_value;
                            }
                        }
                        break;

                    case 'email':
                        $user_data['email'] = sanitize_email($field_value);
                        break;

                    case 'password':
                        $user_data['password'] = $field_value;
                        break;

                    case 'checkbox':
                        // Handle checkbox fields for tools
                        if (!isset($user_data['tools'])) {
                            $user_data['tools'] = [];
                        }

                        if (!empty($field_value)) {
                            if (is_array($field_value)) {
                                // Clean each tool value - remove newlines and extra whitespace
                                foreach ($field_value as $tool) {
                                    $clean_tool = trim(str_replace(["\n", "\r", "\t"], ' ', $tool));
                                    if (!empty($clean_tool)) {
                                        $user_data['tools'][] = $clean_tool;
                                    }
                                }
                            } else {
                                // Clean single tool value - remove newlines and extra whitespace
                                $clean_tool = trim(str_replace(["\n", "\r", "\t"], ' ', $field_value));
                                if (!empty($clean_tool)) {
                                    $user_data['tools'][] = $clean_tool;
                                }
                            }
                        }
                        break;
                }
            }

            // Set defaults for missing fields
            if (!isset($user_data['first_name'])) $user_data['first_name'] = '';
            if (!isset($user_data['last_name'])) $user_data['last_name'] = '';
            if (!isset($user_data['company'])) $user_data['company'] = '';
            if (!isset($user_data['description'])) $user_data['description'] = '';
            if (!isset($user_data['notes'])) $user_data['notes'] = '';
            if (!isset($user_data['tools'])) $user_data['tools'] = [];
            if (!isset($user_data['subscription_time'])) $user_data['subscription_time'] = '365 days';
            if (!isset($user_data['role_id'])) $user_data['role_id'] = 2; // Default to Customer role

            // Transform Tools from strings to numeric values (0-3)
            if (!empty($user_data['tools']) && is_array($user_data['tools'])) {
                $numeric_tools = [];
                foreach ($user_data['tools'] as $tool) {
                    $tool_number = $this->map_tool_to_number($tool);
                    if ($tool_number !== null) {
                        $numeric_tools[] = $tool_number;
                    }
                }
                $user_data['tools'] = $numeric_tools;
            }

            // Ensure name is set
            if (empty($user_data['name']) && (!empty($user_data['first_name']) || !empty($user_data['last_name']))) {
                $user_data['name'] = trim($user_data['first_name'] . ' ' . $user_data['last_name']);
            }

            // Validate required fields
            if (empty($user_data['email'])) {
                error_log('DIT WPForms: ERROR - Email is required');
                return false;
            }

            if (empty($user_data['password'])) {
                error_log('DIT WPForms: ERROR - Password is required');
                return false;
            }

            error_log('DIT WPForms: User data extracted successfully');
            error_log('DIT WPForms: Extracted data: ' . print_r($user_data, true));

            return $user_data;
        } catch (Exception $e) {
            error_log('DIT WPForms: ERROR extracting user data: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Extract signin data from form submission
     *
     * @param array $submitted_data Form submission data
     * @param array $form_data Form configuration
     * @return array|false User data or false on failure
     */
    public function extract_signin_data($submitted_data, $form_data)
    {
        error_log('DIT WPForms: extract_signin_data called with ' . count($submitted_data) . ' fields for form ' . $form_data['id']);

        $user_data = [];
        $core = Core::get_instance();
        $logger = $core->logger;

        // Log all submitted data for debugging
        $logger->log_form_submission(
            $form_data['id'],
            [
                'step' => 'extract_signin_data_start',
                'submitted_data' => $submitted_data,
                'submitted_fields_count' => count($submitted_data),
                'submitted_field_types' => array_column($submitted_data, 'type'),
                'submitted_field_ids' => array_keys($submitted_data)
            ],
            'info',
            'Starting signin data extraction'
        );

        // Look for email, password, and role fields
        foreach ($submitted_data as $field_id => $field) {
            $field_type = $field['type'];
            $field_value = $field['value'];

            $logger->log_form_submission(
                $form_data['id'],
                [
                    'step' => 'processing_field',
                    'field_id' => $field_id,
                    'field_type' => $field_type,
                    'field_value' => $field_type === 'password' ? '***HIDDEN***' : $field_value,
                    'field_empty' => empty($field_value)
                ],
                'info',
                'Processing field: ' . $field_type
            );

            if (empty($field_value)) {
                continue;
            }

            switch ($field_type) {
                case 'email':
                    $user_data['email'] = sanitize_email($field_value);
                    break;
                case 'password':
                    $user_data['password'] = $field_value; // Plain password for hashing
                    break;
                case 'select':
                case 'radio':
                case 'checkbox':
                    // Check if this is a role field by looking at field properties
                    $field_config = $form_data['fields'][$field_id] ?? [];
                    $field_label = strtolower($field_config['label'] ?? '');
                    $field_name = strtolower($field_config['name'] ?? '');

                    // Check if this field is for role selection
                    if (
                        strpos($field_label, 'role') !== false ||
                        strpos($field_name, 'role') !== false ||
                        $field_id == 4
                    ) { // Assuming field ID 4 is the role field based on logs

                        $role_value = is_array($field_value) ? $field_value[0] : $field_value;

                        // Map text role names to numeric values for API
                        $role_mapping = [
                            'administrator' => 3,
                            'customer' => 2,
                            'user' => 1,
                            'admin' => 3,
                            'client' => 2,
                            'standard' => 1
                        ];

                        // Convert to lowercase for comparison
                        $role_lower = strtolower(trim($role_value));

                        // Map the role value
                        if (isset($role_mapping[$role_lower])) {
                            $user_data['role_id'] = $role_mapping[$role_lower];
                        } else {
                            // If it's already a number, use it directly
                            if (is_numeric($role_value)) {
                                $user_data['role_id'] = (int)$role_value;
                            } else {
                                // Unknown role value
                                $user_data['role_id'] = null;
                            }
                        }

                        $logger->log_form_submission(
                            $form_data['id'],
                            [
                                'step' => 'role_field_found',
                                'field_id' => $field_id,
                                'field_type' => $field_type,
                                'field_label' => $field_config['label'] ?? 'no_label',
                                'field_name' => $field_config['name'] ?? 'no_name',
                                'original_role_value' => $role_value,
                                'role_lower' => $role_lower,
                                'mapped_role_id' => $user_data['role_id'],
                                'role_mapping_used' => isset($role_mapping[$role_lower]) ? $role_mapping[$role_lower] : 'none',
                                'role_value_type' => gettype($user_data['role_id'])
                            ],
                            $user_data['role_id'] !== null ? 'info' : 'error',
                            $user_data['role_id'] !== null ? 'Role field found and mapped successfully' : 'Role field found but mapping failed'
                        );
                    }
                    break;
            }
        }

        // Check if we have required fields
        if (empty($user_data['email']) || empty($user_data['password'])) {
            $logger->log_form_submission(
                $form_data['id'],
                [
                    'step' => 'missing_required_fields',
                    'has_email' => !empty($user_data['email']),
                    'has_password' => !empty($user_data['password']),
                    'has_role_id' => !empty($user_data['role_id']),
                    'extracted_data' => array_keys($user_data)
                ],
                'error',
                'Missing required fields for signin'
            );
            return false;
        }

        // Check if role was successfully mapped
        if (empty($user_data['role_id'])) {
            $logger->log_form_submission(
                $form_data['id'],
                [
                    'step' => 'role_mapping_failed',
                    'has_email' => !empty($user_data['email']),
                    'has_password' => !empty($user_data['password']),
                    'has_role_id' => !empty($user_data['role_id']),
                    'extracted_data' => array_keys($user_data),
                    'user_data' => $user_data
                ],
                'error',
                'Role mapping failed - role_id is empty or null'
            );
            return false;
        }

        // Log signin data extraction
        $logger->log_form_submission(
            $form_data['id'],
            [
                'step' => 'extract_signin_data_success',
                'has_email' => !empty($user_data['email']),
                'has_password' => !empty($user_data['password']),
                'has_role_id' => !empty($user_data['role_id']),
                'email' => $user_data['email'],
                'role_id' => $user_data['role_id'] ?? 'not_provided',
                'password_length' => strlen($user_data['password']),
                'extracted_data_keys' => array_keys($user_data)
            ],
            'info',
            'Signin data extracted successfully'
        );

        error_log('DIT WPForms: extract_signin_data completed successfully. Email: ' . $user_data['email'] . ', Role ID: ' . $user_data['role_id']);
        return $user_data;
    }

    /**
     * Handle payment processing.
     *
     * @param array $fields Form fields.
     * @param array $entry Form entry.
     * @param array $form_data Form data.
     */
    public function handle_payment($fields, $entry, $form_data)
    {
        error_log('DIT WPForms: Payment handling called for form ' . $form_data['id']);
        // Payment processing logic will be implemented here
        return true;
    }

    /**
     * Add form settings section
     *
     * @param array $sections Form settings sections
     * @param array $form_data Form data
     * @return array
     */
    public function add_form_settings_section($sections, $form_data)
    {
        $sections['dit'] = [
            'id' => 'dit',
            'name' => __('DIT Integration', 'dit-integration'),
        ];

        return $sections;
    }

    /**
     * Add form settings content
     *
     * @param array $form_data Form data
     */
    public function add_form_settings_content($form_data)
    {
        $settings = $form_data['settings']['dit'] ?? [];
?>
        <div class="wpforms-panel-content-section wpforms-panel-content-section-dit">
            <div class="wpforms-panel-content-section-title">
                <?php esc_html_e('DIT Integration', 'dit-integration'); ?>
            </div>

            <div class="wpforms-panel-content-section-content">
                <div class="wpforms-field-row">
                    <div class="wpforms-field-row-block">
                        <label>
                            <input type="checkbox" name="settings[dit][enabled]" value="1"
                                <?php checked(!empty($settings['enabled'])); ?>>
                            <?php esc_html_e('Enable DIT Integration', 'dit-integration'); ?>
                        </label>
                    </div>
                </div>
            </div>
        </div>
<?php
    }

    /**
     * Process checkbox values (deprecated - now handled in extract_user_data)
     */
    public function process_checkbox_values($fields, $entry, $form_data, $entry_id)
    {
        error_log('DIT WPForms: Checkbox processing method called (deprecated)');

        // Log that this method is deprecated
        $core = Core::get_instance();
        if ($core && $core->logger) {
            $core->logger->log_form_submission(
                $form_data['id'],
                [
                    'method' => 'process_checkbox_values',
                    'note' => 'Checkbox processing now handled in extract_user_data method'
                ]
            );
        }
    }

    /**
     * Show access denied message to user
     *
     * @param int $form_id Form ID
     * @param string $message Error message to display
     */
    private function show_access_denied_message($form_id, $message)
    {
        // Store error message in session for display
        if (!session_id()) {
            session_start();
        }

        $_SESSION['dit_access_denied_message'] = $message;
        $_SESSION['dit_access_denied_form_id'] = $form_id;

        // Add error message to WPForms
        wpforms()->process->errors[$form_id]['header'] = $message;

        // Log the access denied attempt
        $core = Core::get_instance();
        $logger = $core->logger;

        $logger->log_form_submission(
            $form_id,
            [
                'step' => 'access_denied',
                'message' => $message,
                'session_id' => session_id()
            ],
            'error',
            'Access denied - user has no roles assigned'
        );
    }

    /**
     * Process signin form submission
     */
    private function process_signin_form($user_data, $entry_id)
    {
        error_log('DIT WPForms: Processing signin form for email: ' . $user_data['email']);

        try {
            // For signin, we need to authenticate existing user
            $user = get_user_by('email', $user_data['email']);

            if (!$user) {
                error_log('DIT WPForms: ERROR - User not found for signin: ' . $user_data['email']);
                return;
            }

            // Get customer ID from user meta
            $customer_id = get_user_meta($user->ID, 'dit_customer_id', true);

            if (!$customer_id) {
                error_log('DIT WPForms: ERROR - No customer ID found for user: ' . $user->ID);
                return;
            }

            error_log('DIT WPForms: Signin successful for user ID: ' . $user->ID . ', customer ID: ' . $customer_id);

            // Update last login
            update_user_meta($user->ID, 'dit_last_login', current_time('Y-m-d H:i:s'));
        } catch (Exception $e) {
            error_log('DIT WPForms: ERROR during signin processing: ' . $e->getMessage());
        }
    }

    /**
     * Register customer with DIT API
     */
    private function register_customer_with_dit($user_data)
    {
        error_log('DIT WPForms: Registering customer with DIT API for email: ' . $user_data['email']);

        try {
            $core = Core::get_instance();
            $api = $core->api;

            if (!$api) {
                error_log('DIT WPForms: ERROR - API instance not available');
                return false;
            }

            // Prepare customer data
            $customer_data = [
                'first_name' => $user_data['first_name'] ?? '',
                'last_name' => $user_data['last_name'] ?? '',
                'email' => $user_data['email'],
                'password' => $user_data['password'] ?? '',
                'company' => $user_data['company'] ?? '',
                'description' => $user_data['description'] ?? '',
                'notes' => $user_data['notes'] ?? '',
                'tools' => $user_data['tools'] ?? [],
                'subscription_time' => $user_data['subscription_time'] ?? '365 days',
                'role_id' => $user_data['role_id'] ?? 2
            ];

            // Register customer
            $result = $api->register_customer_rsa($customer_data);

            if ($result && isset($result['customer_id'])) {
                error_log('DIT WPForms: Customer registered successfully with ID: ' . $result['customer_id']);
                return $result;
            } else {
                error_log('DIT WPForms: ERROR - Customer registration failed');
                return false;
            }
        } catch (Exception $e) {
            error_log('DIT WPForms: ERROR during customer registration: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Save user data to database
     */
    private function save_user_data_to_database($user_data, $customer_id, $wp_user_id)
    {
        error_log('DIT WPForms: Database functionality removed - user data not saved to custom tables');
    }

    /**
     * Extract customer_id from login result
     * 
     * @param array $login_result Login API response
     * @return int|null Customer ID or null if not found
     */
    private function extract_customer_id_from_login_result(array $login_result): ?int
    {
        $core = Core::get_instance();
        $logger = $core->logger;

        // Try to get customer_id from different fields in API response
        $customer_id = null;
        $source_field = null;

        if (isset($login_result['CustomerId']) && is_numeric($login_result['CustomerId'])) {
            $customer_id = (int)$login_result['CustomerId'];
            $source_field = 'CustomerId';
        } elseif (isset($login_result['customer_id']) && is_numeric($login_result['customer_id'])) {
            $customer_id = (int)$login_result['customer_id'];
            $source_field = 'customer_id';
        } elseif (isset($login_result['custOrUserID']) && is_numeric($login_result['custOrUserID'])) {
            // Check if this is customer_id or user_id
            // For now, assume it's customer_id if it's different from UserId
            $user_id = $login_result['UserId'] ?? null;
            if ($user_id && $login_result['custOrUserID'] != $user_id) {
                $customer_id = (int)$login_result['custOrUserID'];
                $source_field = 'custOrUserID';
            }
        }

        $logger->log_form_submission(
            0, // Form ID not available in this context
            [
                'step' => 'extract_customer_id',
                'customer_id' => $customer_id,
                'source_field' => $source_field,
                'available_fields' => array_keys($login_result),
                'login_result_preview' => array_intersect_key($login_result, array_flip(['UserId', 'CustomerId', 'customer_id', 'custOrUserID']))
            ],
            $customer_id !== null ? 'info' : 'warning',
            $customer_id !== null ? "Customer ID extracted: {$customer_id} from field: {$source_field}" : 'Customer ID not found in API response'
        );

        return $customer_id;
    }

    /**
     * Map tool string values to numeric values (0-3)
     * 
     * @param string $tool Tool string value
     * @return int|null Numeric value (0-3) or null if not found
     */
    private function map_tool_to_number(string $tool): ?int
    {
        // Normalize tool string (remove extra spaces, convert to lowercase)
        $normalized_tool = strtolower(trim($tool));

        // Map tool strings to numeric values with multiple variations
        $tool_mapping = [
            // VFX variations
            'vfx' => 0,
            'visual effects' => 0,
            'effects' => 0,

            // DI variations
            'di' => 1,
            'digital intermediate' => 1,
            'digital' => 1,
            'intermediate' => 1,

            // Archive variations
            'archive' => 2,
            'archiving' => 2,
            'storage' => 2,

            // Production variations
            'production' => 3,
            'post production' => 3,
            'post' => 3,
            'post-prod' => 3
        ];

        // Check if tool exists in mapping
        if (isset($tool_mapping[$normalized_tool])) {
            return $tool_mapping[$normalized_tool];
        }

        // Try partial matching for combined values (e.g., "VFX Archive" contains "vfx")
        foreach ($tool_mapping as $key => $value) {
            if (strpos($normalized_tool, $key) !== false) {
                error_log('DIT WPForms: INFO - Partial match found for tool: ' . $tool . ' → ' . $key . ' → ' . $value);
                return $value;
            }
        }

        // If not found, log warning and return null
        error_log('DIT WPForms: WARNING - Unknown tool value: ' . $tool . ' (normalized: ' . $normalized_tool . ')');
        return null;
    }
}
