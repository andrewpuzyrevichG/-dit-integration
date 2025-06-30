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
        $this->core = Core::get_instance();
        add_action('wpforms_process_complete', [$this, 'handle_form_submission'], 10, 4);
        add_action('wpforms_process', [$this, 'handle_payment'], 10, 3);

        // Add any initialization logic here
        // For example, we could verify WPForms is active
        if (!class_exists('WPForms')) {
            error_log('DIT Integration: WPForms plugin is not active');
        }

        // Hook to process checkbox values
        add_action('wpforms_process_complete', [$this, 'process_checkbox_values'], 5, 4);
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
        try {
            // Get settings
            $settings = get_option('dit_settings');
            $signup_form = $settings['signup_form'] ?? '';
            $signin_form = $settings['signin_form'] ?? '';

            // Check if this form should be processed (either signup or signin)
            if (empty($signup_form) && empty($signin_form)) {
                return; // No forms configured
            }

            $form_id = $form_data['id'];
            $is_signup_form = ($form_id == $signup_form);
            $is_signin_form = ($form_id == $signin_form);

            if (!$is_signup_form && !$is_signin_form) {
                return; // This form is not configured for processing
            }

            // Determine form type for logging
            $form_type = $is_signup_form ? 'signup' : 'signin';

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

            // Log all submitted fields for debugging
            $core = Core::get_instance();
            $logger = $core->logger;
            $logger->log_form_submission(
                $form_data['id'],
                [
                    'form_type' => $form_type,
                    'all_fields_count' => count($submitted_data),
                    'all_field_types' => array_column($submitted_data, 'type'),
                    'all_field_ids' => array_keys($submitted_data),
                    'empty_fields' => array_keys(array_filter($submitted_data, function ($field) {
                        return $field['is_empty'];
                    }))
                ],
                'info',
                'All form fields processed'
            );

            // Process the form submission
            $result = $this->process_form_submission($submitted_data, $form_data, $form_type);

            // If this is an AJAX form submission, send JSON response
            if (wp_doing_ajax()) {
                if ($result === true) {
                    $success_message = $form_type === 'signup' ?
                        __('Registration successful', 'dit-integration') :
                        __('Login successful', 'dit-integration');

                    wp_send_json_success([
                        'message' => $success_message,
                        'redirect' => home_url()
                    ]);
                    exit;
                } else {
                    $error_message = $form_type === 'signup' ?
                        __('Registration failed', 'dit-integration') :
                        __('Login failed', 'dit-integration');

                    wp_send_json_error([
                        'message' => $error_message
                    ]);
                    exit;
                }
            }
        } catch (Exception $e) {
            // Log the error
            error_log('DIT Integration: Form submission error - ' . $e->getMessage());

            // If this is an AJAX form submission, send JSON response
            if (wp_doing_ajax()) {
                wp_send_json_error([
                    'message' => __('An error occurred during processing', 'dit-integration')
                ]);
                exit;
            }
        }
    }

    private function process_form_submission($submitted_data, $form_data, $form_type)
    {
        $core = Core::get_instance();
        $logger = $core->logger;
        $api = $core->api;

        try {
            if ($form_type === 'signup') {
                // Handle signup form
                $user_data = $this->extract_user_data($submitted_data, $form_data);
                if (empty($user_data)) {
                    $logger->log_form_submission(
                        $form_data['id'],
                        ['form_type' => $form_type],
                        'error',
                        'Could not extract user data from signup form submission'
                    );
                    error_log('DIT Integration: Could not extract user data from signup form submission');
                    return false;
                }

                // Register customer with DIT API
                $customer_id = $api->register_customer($user_data);

                if ($customer_id === null) {
                    $logger->log_form_submission(
                        $form_data['id'],
                        ['form_type' => $form_type],
                        'error',
                        'Customer registration failed'
                    );
                    error_log('DIT Integration: Customer registration failed');
                    return false;
                }

                $logger->log_form_submission(
                    $form_data['id'],
                    [
                        'form_type' => $form_type,
                        'customer_id' => $customer_id
                    ],
                    'success',
                    'Customer registration successful'
                );
            } elseif ($form_type === 'signin') {
                // Handle signin form
                $user_data = $this->extract_signin_data($submitted_data, $form_data);
                if (empty($user_data)) {
                    $logger->log_form_submission(
                        $form_data['id'],
                        ['form_type' => $form_type],
                        'error',
                        'Could not extract user data from signin form submission'
                    );
                    error_log('DIT Integration: Could not extract user data from signin form submission');
                    return false;
                }

                // Login customer with DIT API
                $login_result = $api->login($user_data['email'], hash('sha256', $user_data['password']));

                if ($login_result === false) {
                    $logger->log_form_submission(
                        $form_data['id'],
                        ['form_type' => $form_type],
                        'error',
                        'Customer login failed'
                    );
                    error_log('DIT Integration: Customer login failed');
                    return false;
                }

                $logger->log_form_submission(
                    $form_data['id'],
                    [
                        'form_type' => $form_type,
                        'email' => $user_data['email']
                    ],
                    'success',
                    'Customer login successful'
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
            error_log('DIT Integration: Exception during form processing - ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Extract user data from form submission
     *
     * @param array $submitted_data Form submission data
     * @param array $form_data Form configuration
     * @return array|false User data or false on failure
     */
    private function extract_user_data($submitted_data, $form_data)
    {
        $user_data = [];
        $core = Core::get_instance();
        $logger = $core->logger;

        // Look for common field types
        foreach ($submitted_data as $field_id => $field) {
            $field_type = $field['type'];
            $field_value = $field['value'];

            // For name fields, we want to capture them even if empty initially
            // as we'll provide fallback values later
            if (empty($field_value) && $field_type !== 'name' && $field_type !== 'text') {
                continue;
            }

            switch ($field_type) {
                case 'email':
                    $user_data['email'] = sanitize_email($field_value);
                    break;
                case 'name':
                case 'text':
                    // For name fields, always capture the value (even if empty)
                    if (empty($user_data['first_name'])) {
                        $user_data['first_name'] = sanitize_text_field($field_value);
                    } else {
                        $user_data['last_name'] = sanitize_text_field($field_value);
                    }
                    break;
                case 'password':
                    $user_data['password'] = $field_value; // Plain password as per API documentation
                    break;
                case 'phone':
                    $user_data['phone'] = sanitize_text_field($field_value);
                    break;
                case 'address':
                    $user_data['address'] = sanitize_textarea_field($field_value);
                    break;
                case 'textarea':
                    // Use textarea for description or notes
                    if (empty($user_data['description'])) {
                        $user_data['description'] = sanitize_textarea_field($field_value);
                    } else {
                        $user_data['notes'] = sanitize_textarea_field($field_value);
                    }
                    break;
                case 'checkbox':
                    // Process checkbox values to extract numbers
                    if (is_array($field_value)) {
                        $converted_values = [];
                        foreach ($field_value as $value) {
                            // Check if value has format "Name | Number"
                            if (strpos($value, '|') !== false) {
                                $parts = explode('|', $value);
                                if (count($parts) === 2) {
                                    $number = trim($parts[1]);
                                    if (is_numeric($number)) {
                                        $converted_values[] = (int)$number;
                                    }
                                }
                            }
                        }

                        if (!empty($converted_values)) {
                            $user_data['tools'] = $converted_values;

                            $logger->log_form_submission(
                                $form_data['id'],
                                [
                                    'field_id' => $field_id,
                                    'original_values' => $field_value,
                                    'converted_values' => $converted_values
                                ],
                                'info',
                                'Checkbox values converted to tools array'
                            );
                        }
                    }
                    break;
            }
        }

        // Combine first_name and last_name into a single 'name' field for the API
        $name_parts = [];
        if (!empty($user_data['first_name'])) {
            $name_parts[] = $user_data['first_name'];
        }
        if (!empty($user_data['last_name'])) {
            $name_parts[] = $user_data['last_name'];
        }

        if (!empty($name_parts)) {
            $user_data['name'] = implode(' ', $name_parts);
        }

        // Set default values for required API fields as per documentation
        if (empty($user_data['name'])) {
            $user_data['name'] = 'New Customer'; // Default name as per documentation
        }

        if (empty($user_data['description'])) {
            $user_data['description'] = ''; // Empty description as per documentation
        }

        if (empty($user_data['notes'])) {
            $user_data['notes'] = 'new customer'; // Default notes as per documentation
        }

        // Set default tools array only if no checkbox values were found
        if (empty($user_data['tools'])) {
            $user_data['tools'] = []; // Empty array if no checkboxes selected
        }

        // Set default metering and subscription values as per documentation
        if (empty($user_data['meteringSeconds'])) {
            $user_data['meteringSeconds'] = 10000; // Default metering seconds
        }

        if (empty($user_data['subscriptionTime'])) {
            $user_data['subscriptionTime'] = '365 days'; // Default subscription time
        }

        // Log essential form data (without sensitive information)
        $logger->log_form_submission(
            $form_data['id'],
            [
                'submitted_fields_count' => count($submitted_data),
                'has_email' => !empty($user_data['email']),
                'has_name' => !empty($user_data['name']),
                'has_password' => !empty($user_data['password']),
                'has_phone' => !empty($user_data['phone']),
                'has_address' => !empty($user_data['address']),
                'has_description' => !empty($user_data['description']),
                'has_notes' => !empty($user_data['notes']),
                'tools_count' => count($user_data['tools']),
                'tools_values' => $user_data['tools'],
                'metering_seconds' => $user_data['meteringSeconds'],
                'subscription_time' => $user_data['subscriptionTime']
            ],
            'info',
            'Form data extracted successfully with API-compliant defaults'
        );

        return $user_data;
    }

    /**
     * Extract signin data from form submission
     *
     * @param array $submitted_data Form submission data
     * @param array $form_data Form configuration
     * @return array|false User data or false on failure
     */
    private function extract_signin_data($submitted_data, $form_data)
    {
        $user_data = [];
        $core = Core::get_instance();
        $logger = $core->logger;

        // Look for email and password fields
        foreach ($submitted_data as $field_id => $field) {
            $field_type = $field['type'];
            $field_value = $field['value'];

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
            }
        }

        // Check if we have required fields
        if (empty($user_data['email']) || empty($user_data['password'])) {
            $logger->log_form_submission(
                $form_data['id'],
                [
                    'has_email' => !empty($user_data['email']),
                    'has_password' => !empty($user_data['password'])
                ],
                'error',
                'Missing required fields for signin'
            );
            return false;
        }

        // Log signin data extraction
        $logger->log_form_submission(
            $form_data['id'],
            [
                'has_email' => !empty($user_data['email']),
                'has_password' => !empty($user_data['password']),
                'email' => $user_data['email']
            ],
            'info',
            'Signin data extracted successfully'
        );

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
        // Skip if form doesn't have payment enabled
        if (empty($form_data['settings']['payment_enabled'])) {
            return;
        }

        // Get settings to check debug mode
        $settings = get_option('dit_settings');
        $debug_mode = $settings['debug_mode'] ?? false;

        // Get payment amount
        $amount = $this->get_payment_amount($fields, $form_data);
        if ($amount <= 0) {
            return;
        }

        // If debug mode is enabled, simulate successful payment
        if ($debug_mode) {
            $core = Core::get_instance();
            $logger = $core->logger;

            $logger->log_api_interaction(
                'Stripe Payment',
                [
                    'form_id' => $form_data['id'],
                    'entry_id' => $entry['id'],
                    'amount' => $amount,
                    'debug_mode' => true
                ],
                'success',
                'Payment simulated successfully in debug mode'
            );

            // Simulate successful payment response
            $simulated_payment = [
                'id' => 'pi_debug_' . time(),
                'status' => 'succeeded',
                'amount' => $amount * 100, // Convert to cents
                'currency' => 'usd',
                'created' => time(),
                'debug_mode' => true
            ];

            // Store simulated payment data
            if (!session_id()) {
                session_start();
            }
            $_SESSION['dit_simulated_payment'] = $simulated_payment;

            // Log the simulation
            error_log('DIT Integration: Payment simulated in debug mode - Amount: $' . $amount . ', Form ID: ' . $form_data['id']);

            return;
        }

        // Real Stripe processing (only when debug mode is disabled)
        if (!class_exists('WPForms_Stripe')) {
            error_log('DIT Integration: Stripe addon not available for payment processing');
            return;
        }

        // Create payment intent
        $payment_intent = $this->core->stripe->create_payment_intent($amount, 'usd', [
            'form_id' => $form_data['id'],
            'entry_id' => $entry['id'],
        ]);

        if (is_wp_error($payment_intent)) {
            wpforms_log(
                'Stripe Payment Error',
                $payment_intent->get_error_message(),
                [
                    'type' => 'error',
                    'form_id' => $form_data['id'],
                ]
            );
            return;
        }

        // Store payment intent data in session
        if (!session_id()) {
            session_start();
        }
        $_SESSION['dit_payment_intent'] = $payment_intent;
    }

    /**
     * Get payment amount from form fields.
     *
     * @param array $fields Form fields.
     * @param array $form_data Form data.
     * @return float Payment amount.
     */
    private function get_payment_amount($fields, $form_data)
    {
        $amount = 0;

        foreach ($fields as $field) {
            if ($field['type'] === 'payment-single' || $field['type'] === 'payment-total') {
                $amount = floatval($field['value']);
                break;
            }
        }

        return $amount;
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
     * Process checkbox values and convert them to array of numbers
     * Note: This method is now deprecated as checkbox processing is handled in extract_user_data
     *
     * @param array $fields Form fields data
     * @param array $entry Entry data
     * @param array $form_data Form data
     * @param int $entry_id Entry ID
     */
    public function process_checkbox_values($fields, $entry, $form_data, $entry_id)
    {
        $core = Core::get_instance();
        $logger = $core->logger;

        $logger->log_form_submission(
            $form_data['id'],
            [
                'method' => 'process_checkbox_values',
                'note' => 'Checkbox processing now handled in extract_user_data method'
            ],
            'info',
            'Checkbox processing method called (deprecated)'
        );

        // Checkbox processing is now handled in extract_user_data method
        // This method is kept for backward compatibility
    }
}
