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

        // Add user metadata to settings (without AES key)
        $settings['registered_users'][$customer_id] = [
            'name' => sanitize_text_field($user_name),
            'customer_id' => (int) $customer_id,
            'registration_date' => current_time('mysql'),
            'last_updated' => current_time('mysql'),
            'aes_key_stored_in_cookie' => true // Flag indicating AES key is in cookie
        ];

        // Save updated settings (without AES key)
        $result = update_option('dit_settings', $settings);

        // Save AES key to user's browser cookie (more secure)
        $cookie_result = save_customer_data_to_cookies($customer_id, $permanent_aes_key, 365); // 1 year

        if ($result && $cookie_result) {
            log_message("User data saved successfully for customer ID: {$customer_id} (metadata in DB, AES key in cookie)", 'info');
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
    // Get user metadata from settings
    $settings = get_settings();
    $user_data = $settings['registered_users'][$customer_id] ?? null;

    if ($user_data) {
        // Get AES key from cookie
        $aes_key = get_aes_key_from_cookies();

        if ($aes_key) {
            $user_data['permanent_aes_key'] = $aes_key;
            log_message("User data retrieved for customer ID: {$customer_id} (metadata from DB, AES key from cookie)", 'info');
        } else {
            log_message("User metadata found but AES key not in cookie for customer ID: {$customer_id}", 'warning');
            $user_data['permanent_aes_key'] = null;
        }

        return $user_data;
    }

    log_message("User data not found for customer ID: {$customer_id}", 'info');
    return null;
}

/**
 * Get permanent AES key for a user.
 *
 * @param int $customer_id Customer ID.
 * @return string|null Permanent AES key or null if not found.
 */
function get_user_permanent_aes_key($customer_id)
{
    return get_aes_key_from_cookies();
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

/**
 * Save customer ID and AES key to user's browser cookies
 *
 * @param int $customer_id Customer ID
 * @param string $aes_key AES key to save
 * @param int $expiry_days Number of days until cookie expires (0 = session only)
 * @return bool True if cookies were set successfully
 */
function save_customer_data_to_cookies($customer_id, $aes_key, $expiry_days = 365)
{
    try {
        // Calculate expiry time
        if ($expiry_days > 0) {
            $expiry_time = time() + ($expiry_days * 24 * 60 * 60);
        } else {
            $expiry_time = 0; // Session cookie
        }

        $cookie_options = [
            'expires' => $expiry_time,
            'path' => '/',
            'domain' => '',
            'secure' => is_ssl(), // HTTPS only if available
            'httponly' => true,   // Prevent JavaScript access
            'samesite' => 'Strict' // CSRF protection
        ];

        // Save customer ID
        $customer_id_cookie = 'dit_customer_id';
        $customer_id_result = setcookie($customer_id_cookie, $customer_id, $cookie_options);

        // Save AES key
        $aes_key_cookie = 'dit_aes_key';
        $aes_key_encoded = base64_encode($aes_key);
        $aes_key_result = setcookie($aes_key_cookie, $aes_key_encoded, $cookie_options);

        if ($customer_id_result && $aes_key_result) {
            log_message("Customer ID and AES key saved to cookies for customer ID: {$customer_id}", 'info');
            return true;
        } else {
            log_message("Failed to save customer data to cookies for customer ID: {$customer_id}", 'error');
            return false;
        }
    } catch (\Exception $e) {
        log_message("Error saving customer data to cookies: " . $e->getMessage(), 'error');
        return false;
    }
}

/**
 * Get customer ID and AES key from user's browser cookies
 *
 * @return array|null Array with customer_id and aes_key, or null if not found
 */
function get_customer_data_from_cookies()
{
    try {
        $customer_id_cookie = 'dit_customer_id';
        $aes_key_cookie = 'dit_aes_key';

        if (isset($_COOKIE[$customer_id_cookie]) && isset($_COOKIE[$aes_key_cookie])) {
            $customer_id = (int) $_COOKIE[$customer_id_cookie];
            $aes_key_encoded = $_COOKIE[$aes_key_cookie];
            $aes_key = base64_decode($aes_key_encoded);

            if ($aes_key !== false && $customer_id > 0) {
                log_message("Customer data retrieved from cookies for customer ID: {$customer_id}", 'info');
                return [
                    'customer_id' => $customer_id,
                    'aes_key' => $aes_key
                ];
            } else {
                log_message("Invalid customer data format in cookies", 'warning');
                return null;
            }
        }

        log_message("Customer data not found in cookies", 'info');
        return null;
    } catch (\Exception $e) {
        log_message("Error retrieving customer data from cookies: " . $e->getMessage(), 'error');
        return null;
    }
}

/**
 * Get only customer ID from cookies
 *
 * @return int|null Customer ID or null if not found
 */
function get_customer_id_from_cookies()
{
    $customer_data = get_customer_data_from_cookies();
    return $customer_data['customer_id'] ?? null;
}

/**
 * Get only AES key from cookies
 *
 * @return string|null AES key or null if not found
 */
function get_aes_key_from_cookies()
{
    $customer_data = get_customer_data_from_cookies();
    return $customer_data['aes_key'] ?? null;
}

/**
 * Delete customer ID and AES key from user's browser cookies
 *
 * @return bool True if cookies were deleted successfully
 */
function delete_customer_data_from_cookies()
{
    try {
        $cookie_options = [
            'expires' => time() - 3600, // 1 hour ago
            'path' => '/',
            'domain' => '',
            'secure' => is_ssl(),
            'httponly' => true,
            'samesite' => 'Strict'
        ];

        // Delete customer ID cookie
        $customer_id_result = setcookie('dit_customer_id', '', $cookie_options);

        // Delete AES key cookie
        $aes_key_result = setcookie('dit_aes_key', '', $cookie_options);

        if ($customer_id_result && $aes_key_result) {
            log_message("Customer data deleted from cookies", 'info');
            return true;
        } else {
            log_message("Failed to delete customer data from cookies", 'error');
            return false;
        }
    } catch (\Exception $e) {
        log_message("Error deleting customer data from cookies: " . $e->getMessage(), 'error');
        return false;
    }
}

/**
 * Check if customer data exists in cookies
 *
 * @return bool True if both customer ID and AES key exist in cookies
 */
function has_customer_data_in_cookies()
{
    return isset($_COOKIE['dit_customer_id']) && isset($_COOKIE['dit_aes_key']);
}

/**
 * Get all DIT cookies (for debugging)
 *
 * @return array Array of cookie information
 */
function get_all_dit_cookies()
{
    $dit_cookies = [];

    if (isset($_COOKIE['dit_customer_id'])) {
        $dit_cookies['customer_id'] = [
            'value' => $_COOKIE['dit_customer_id'],
            'length' => strlen($_COOKIE['dit_customer_id'])
        ];
    }

    if (isset($_COOKIE['dit_aes_key'])) {
        $dit_cookies['aes_key'] = [
            'value' => $_COOKIE['dit_aes_key'],
            'length' => strlen($_COOKIE['dit_aes_key']),
            'encoded' => true
        ];
    }

    return $dit_cookies;
}
