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
            $selected_form = $settings['wpforms_form'] ?? '';

            // Check if this form should be processed
            if (empty($selected_form) || $form_data['id'] != $selected_form) {
                return;
            }

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
            $result = $this->process_form_submission($submitted_data, $form_data);

            // If this is an AJAX form submission, send JSON response
            if (wp_doing_ajax()) {
                if ($result === true) {
                    wp_send_json_success([
                        'message' => __('Registration successful', 'dit-integration'),
                        'redirect' => home_url()
                    ]);
                    exit;
                } else {
                    wp_send_json_error([
                        'message' => __('Registration failed', 'dit-integration')
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
                    'message' => __('An error occurred during registration', 'dit-integration')
                ]);
                exit;
            }
        }
    }

    private function process_form_submission($submitted_data, $form_data)
    {
        // Get API and Encryption instances
        $api = new API();
        $encryption = new Encryption();
        $core = Core::get_instance();
        $logger = $core->logger;

        try {
            // Log start of processing
            $logger->log_form_submission(
                $form_data['id'],
                ['submitted_data' => $submitted_data],
                'info',
                'Starting form submission processing'
            );

            // Check if this was a payment form
            $settings = get_option('dit_settings');
            $debug_mode = $settings['debug_mode'] ?? false;
            $has_payment = !empty($form_data['settings']['payment_enabled']);

            if ($has_payment && $debug_mode) {
                $logger->log_form_submission(
                    $form_data['id'],
                    [],
                    'info',
                    'Processing form with simulated payment (debug mode)'
                );
            } elseif ($has_payment) {
                $logger->log_form_submission(
                    $form_data['id'],
                    [],
                    'info',
                    'Processing form with real payment processing'
                );
            } else {
                $logger->log_form_submission(
                    $form_data['id'],
                    [],
                    'info',
                    'Processing form without payment'
                );
            }

            // Extract user data from form fields
            $user_data = $this->extract_user_data($submitted_data, $form_data);

            if (empty($user_data)) {
                $logger->log_form_submission(
                    $form_data['id'],
                    [],
                    'error',
                    'Could not extract user data from form submission'
                );
                error_log('DIT Integration: Could not extract user data from form submission');
                return false;
            }

            // Log extracted user data (without sensitive information)
            $logger->log_form_submission(
                $form_data['id'],
                [
                    'email' => $user_data['email'],
                    'has_password' => !empty($user_data['password']),
                    'has_name' => !empty($user_data['first_name']) || !empty($user_data['last_name'])
                ],
                'info',
                'User data extracted successfully'
            );

            // Register customer with DIT API
            $customer_id = $api->register_customer($user_data);

            if ($customer_id === null) {
                $logger->log_form_submission(
                    $form_data['id'],
                    [],
                    'error',
                    'Failed to register customer with DIT API'
                );
                error_log('DIT Integration: Failed to register customer with DIT API');
                return false;
            }

            // Log successful registration
            $logger->log_form_submission(
                $form_data['id'],
                ['customer_id' => $customer_id],
                'success',
                'Customer registered successfully'
            );

            return true;
        } catch (Exception $e) {
            $logger->log_form_submission(
                $form_data['id'],
                ['error' => $e->getMessage()],
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

        // Log the submitted data for debugging
        $logger->log_form_submission(
            $form_data['id'],
            [
                'submitted_fields_count' => count($submitted_data),
                'submitted_field_types' => array_column($submitted_data, 'type'),
                'submitted_field_ids' => array_keys($submitted_data)
            ],
            'info',
            'Starting user data extraction'
        );

        // Look for common field types
        foreach ($submitted_data as $field_id => $field) {
            $field_type = $field['type'];
            $field_value = $field['value'];

            $logger->log_form_submission(
                $form_data['id'],
                [
                    'field_id' => $field_id,
                    'field_type' => $field_type,
                    'field_value_length' => strlen($field_value),
                    'field_value_preview' => substr($field_value, 0, 50),
                    'is_empty' => $field['is_empty'] ?? false
                ],
                'info',
                'Processing field'
            );

            // For name fields, we want to capture them even if empty initially
            // as we'll provide fallback values later
            if (empty($field_value) && $field_type !== 'name' && $field_type !== 'text') {
                $logger->log_form_submission(
                    $form_data['id'],
                    [
                        'field_id' => $field_id,
                        'field_type' => $field_type
                    ],
                    'info',
                    'Skipping empty field (non-name)'
                );
                continue;
            }

            // Log when we process name/text fields (even if empty)
            if ($field_type === 'name' || $field_type === 'text') {
                $logger->log_form_submission(
                    $form_data['id'],
                    [
                        'field_id' => $field_id,
                        'field_type' => $field_type,
                        'field_value' => $field_value,
                        'field_value_length' => strlen($field_value),
                        'is_empty' => empty($field_value)
                    ],
                    'info',
                    'Processing name/text field'
                );
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
                        $logger->log_form_submission(
                            $form_data['id'],
                            [
                                'field_id' => $field_id,
                                'field_type' => $field_type,
                                'assigned_to' => 'first_name',
                                'value' => $field_value,
                                'sanitized_value' => sanitize_text_field($field_value)
                            ],
                            'info',
                            'Assigned field to first_name'
                        );
                    } else {
                        $user_data['last_name'] = sanitize_text_field($field_value);
                        $logger->log_form_submission(
                            $form_data['id'],
                            [
                                'field_id' => $field_id,
                                'field_type' => $field_type,
                                'assigned_to' => 'last_name',
                                'value' => $field_value,
                                'sanitized_value' => sanitize_text_field($field_value)
                            ],
                            'info',
                            'Assigned field to last_name'
                        );
                    }
                    break;
                case 'password':
                    $user_data['password'] = $field_value;
                    $user_data['password_hash'] = hash('sha256', $field_value);
                    break;
                case 'phone':
                    $user_data['phone'] = sanitize_text_field($field_value);
                    break;
                case 'address':
                    $user_data['address'] = sanitize_textarea_field($field_value);
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
            $logger->log_form_submission(
                $form_data['id'],
                [
                    'name_source' => 'combined_first_last',
                    'name_parts' => $name_parts,
                    'final_name' => $user_data['name']
                ],
                'info',
                'Name created from first/last name parts'
            );
        } else {
            // If no name fields found, use email as fallback
            $user_data['name'] = !empty($user_data['email']) ? $user_data['email'] : 'Unknown User';

            // Log final user data for debugging
            $logger->log_form_submission(
                $form_data['id'],
                [
                    'final_user_data_keys' => array_keys($user_data),
                    'final_name_value' => $user_data['name'] ?? 'NOT_SET',
                    'final_name_length' => strlen($user_data['name'] ?? ''),
                    'final_name_empty' => empty($user_data['name']),
                    'final_email_value' => $user_data['email'] ?? 'NOT_SET',
                    'final_password_set' => isset($user_data['password']),
                    'final_tools_set' => isset($user_data['tools']),
                    'user_data_complete' => !empty($user_data['name']) && !empty($user_data['email']) && isset($user_data['password'])
                ],
                'info',
                'Final user data extracted'
            );
        }

        // Log the extracted user data
        $logger->log_form_submission(
            $form_data['id'],
            [
                'extracted_email' => $user_data['email'] ?? 'NOT_FOUND',
                'extracted_name' => $user_data['name'] ?? 'NOT_FOUND',
                'extracted_first_name' => $user_data['first_name'] ?? 'NOT_FOUND',
                'extracted_last_name' => $user_data['last_name'] ?? 'NOT_FOUND',
                'has_password' => !empty($user_data['password']),
                'name_parts_count' => count($name_parts)
            ],
            'info',
            'User data extraction completed'
        );

        // Check if we have required fields
        if (empty($user_data['email']) || empty($user_data['password_hash'])) {
            $logger->log_form_submission(
                $form_data['id'],
                [
                    'missing_email' => empty($user_data['email']),
                    'missing_password' => empty($user_data['password_hash'])
                ],
                'error',
                'Required fields missing'
            );
            return false;
        }

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
}
