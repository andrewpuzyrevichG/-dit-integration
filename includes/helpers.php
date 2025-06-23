<?php

namespace DIT;

/**
 * Get plugin settings.
 *
 * @return array Plugin settings.
 */
function get_settings()
{
    return get_option('dit_settings', []);
}

/**
 * Get a specific plugin setting.
 *
 * @param string $key Setting key.
 * @param mixed $default Default value.
 * @return mixed Setting value.
 */
function get_setting($key, $default = '')
{
    $settings = get_settings();
    return $settings[$key] ?? $default;
}

/**
 * Log a message to the WordPress debug log.
 *
 * @param string $message Message to log.
 * @param string $level Log level (info, warning, error).
 */
function log_message($message, $level = 'info')
{
    if (defined('WP_DEBUG') && WP_DEBUG) {
        error_log(sprintf('[DIT Integration] [%s] %s', strtoupper($level), $message));
    }
}

/**
 * Check if a form has DIT integration enabled.
 *
 * @param array $form_data Form data.
 * @return bool True if integration is enabled.
 */
function is_dit_integration_enabled($form_data)
{
    return !empty($form_data['settings']['dit_integration']['dit_enabled']);
}

/**
 * Get mapped field value.
 *
 * @param array $fields Form fields.
 * @param array $form_data Form data.
 * @param string $dit_field DIT field name.
 * @return mixed Field value.
 */
function get_mapped_field_value($fields, $form_data, $dit_field)
{
    $mapping = $form_data['settings']['dit_integration']['dit_field_mapping'] ?? [];
    $field_id = $mapping[$dit_field] ?? '';

    if (empty($field_id)) {
        return '';
    }

    foreach ($fields as $field) {
        if ($field['id'] === $field_id) {
            return $field['value'];
        }
    }

    return '';
}

/**
 * Format currency amount.
 *
 * @param float $amount Amount to format.
 * @param string $currency Currency code.
 * @return string Formatted amount.
 */
function format_currency($amount, $currency = 'USD')
{
    $formatter = new \NumberFormatter('en_US', \NumberFormatter::CURRENCY);
    return $formatter->formatCurrency($amount, $currency);
}

/**
 * Sanitize API response data.
 *
 * @param mixed $data Data to sanitize.
 * @return mixed Sanitized data.
 */
function sanitize_api_response($data)
{
    if (is_array($data)) {
        foreach ($data as $key => $value) {
            $data[$key] = sanitize_api_response($value);
        }
        return $data;
    }

    if (is_string($data)) {
        return sanitize_text_field($data);
    }

    return $data;
}

/**
 * Get payment status label.
 *
 * @param string $status Payment status.
 * @return string Status label.
 */
function get_payment_status_label($status)
{
    $labels = [
        'succeeded' => __('Succeeded', 'dit-integration'),
        'processing' => __('Processing', 'dit-integration'),
        'requires_payment_method' => __('Requires Payment Method', 'dit-integration'),
        'requires_confirmation' => __('Requires Confirmation', 'dit-integration'),
        'requires_action' => __('Requires Action', 'dit-integration'),
        'requires_capture' => __('Requires Capture', 'dit-integration'),
        'canceled' => __('Canceled', 'dit-integration'),
    ];

    return $labels[$status] ?? $status;
}

/**
 * Check if Stripe is configured.
 *
 * @return bool True if Stripe is configured.
 */
function is_stripe_configured()
{
    $settings = get_settings();
    return !empty($settings['stripe_secret_key']) && !empty($settings['stripe_publishable_key']);
}

/**
 * Check if DIT API is configured.
 *
 * @return bool True if DIT API is configured.
 */
function is_dit_api_configured()
{
    $settings = get_settings();
    return !empty($settings['dit_api_url']) && !empty($settings['dit_api_key']);
}

/**
 * Save user registration data.
 *
 * @param string $user_name User name.
 * @param int $customer_id Customer ID from DIT API.
 * @param string $permanent_aes_key Permanent AES key for future use.
 * @return bool True if data was saved successfully.
 */
function save_user_data($user_name, $customer_id, $permanent_aes_key)
{
    try {
        $settings = get_settings();

        // Add user data to settings
        $settings['registered_users'][$customer_id] = [
            'name' => sanitize_text_field($user_name),
            'customer_id' => (int) $customer_id,
            'permanent_aes_key' => sanitize_text_field($permanent_aes_key),
            'registration_date' => current_time('mysql'),
            'last_updated' => current_time('mysql')
        ];

        // Save updated settings
        $result = update_option('dit_settings', $settings);

        if ($result) {
            log_message("User data saved successfully for customer ID: {$customer_id}", 'info');
            return true;
        } else {
            log_message("Failed to save user data for customer ID: {$customer_id}", 'error');
            return false;
        }
    } catch (\Exception $e) {
        log_message("Error saving user data: " . $e->getMessage(), 'error');
        return false;
    }
}

/**
 * Get user data by customer ID.
 *
 * @param int $customer_id Customer ID.
 * @return array|null User data or null if not found.
 */
function get_user_data($customer_id)
{
    $settings = get_settings();
    return $settings['registered_users'][$customer_id] ?? null;
}

/**
 * Get permanent AES key for a user.
 *
 * @param int $customer_id Customer ID.
 * @return string|null Permanent AES key or null if not found.
 */
function get_user_permanent_aes_key($customer_id)
{
    $user_data = get_user_data($customer_id);
    return $user_data['permanent_aes_key'] ?? null;
}

/**
 * Get user name by customer ID.
 *
 * @param int $customer_id Customer ID.
 * @return string|null User name or null if not found.
 */
function get_user_name($customer_id)
{
    $user_data = get_user_data($customer_id);
    return $user_data['name'] ?? null;
}
