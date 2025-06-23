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
