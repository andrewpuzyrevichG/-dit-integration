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
    // Log message function
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
 * @param array $additional_data Additional user data (first_name, last_name, company, email).
 * @return bool True if data was saved successfully.
 */
function save_user_data($user_name, $customer_id, $permanent_aes_key, $additional_data = [])
{
    try {
        $settings = get_settings();
        $short_key = substr($permanent_aes_key, 0, 12) . '...';
        log_message("[save_user_data] Called for customer_id={$customer_id}, AES key(part)={$short_key}", 'info');

        // Add user metadata to settings (without AES key)
        $settings['registered_users'][$customer_id] = [
            'name' => sanitize_text_field($user_name),
            'customer_id' => (int) $customer_id,
            'registration_date' => current_time('mysql'),
            'last_updated' => current_time('mysql'),
            'aes_key_stored_in_cookie' => true, // Flag indicating AES key is in cookie
            'first_name' => sanitize_text_field($additional_data['first_name'] ?? ''),
            'last_name' => sanitize_text_field($additional_data['last_name'] ?? ''),
            'company' => sanitize_text_field($additional_data['company'] ?? ''),
            'email' => sanitize_email($additional_data['email'] ?? '')
        ];

        // Save updated settings (without AES key)
        $result = update_option('dit_settings', $settings);
        log_message("[save_user_data] update_option result: " . var_export($result, true), 'info');

        // Note: Cookies removed - AES key stored only in session
        $cookie_result = true; // Simulate success for backward compatibility
        log_message("[save_user_data] Cookies removed - AES key stored only in session", 'info');

        // Save AES key to session (per customer_id)
        if (!isset($_SESSION)) {
            session_start();
        }
        if (!isset($_SESSION['dit_aes_keys'])) {
            $_SESSION['dit_aes_keys'] = [];
        }
        $_SESSION['dit_aes_keys'][$customer_id] = $permanent_aes_key;
        log_message("[save_user_data] AES key saved to session for customer_id={$customer_id}", 'info');

        // Save AES key to user_meta (per customer_id)
        $meta_result = null;
        if (function_exists('get_current_user_id') && is_user_logged_in()) {
            $meta_result = update_user_meta(get_current_user_id(), 'dit_aes_key_' . $customer_id, $permanent_aes_key);
            log_message("[save_user_data] update_user_meta for user_id=" . get_current_user_id() . ", customer_id={$customer_id}, result: " . var_export($meta_result, true), 'info');
        } else {
            log_message("[save_user_data] User not logged in, user_meta not updated", 'info');
        }

        // Note: AES key is no longer stored in database, only in session/cookies/user_meta
        log_message("[save_user_data] AES key stored in session/cookies/user_meta for customer_id={$customer_id}", 'info');

        if ($result && $cookie_result) {
            log_message("User data saved successfully for customer ID: {$customer_id} (metadata in DB, AES key in session/cookies/user_meta)", 'info');
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
    $user_data = $settings['registered_users'][$customer_id] ?? null;
    if ($user_data) {
        $aes_key = get_user_permanent_aes_key($customer_id);
        $user_data['permanent_aes_key'] = $aes_key;
        return $user_data;
    }
    return null;
}

/**
 * Get permanent AES key for user by customer ID.
 *
 * @param int $customer_id Customer ID.
 * @return string|null Permanent AES key or null if not found.
 */
function get_user_permanent_aes_key($customer_id)
{
    if (!isset($_SESSION)) {
        session_start();
    }

    error_log('DIT Helpers: === GET USER PERMANENT AES KEY ===');
    error_log('DIT Helpers: Customer ID: ' . ($customer_id ?? 'NULL'));
    error_log('DIT Helpers: Session ID: ' . session_id());
    error_log('DIT Helpers: Session status: ' . (session_status() === PHP_SESSION_ACTIVE ? 'Active' : 'Inactive'));
    error_log('DIT Helpers: Session data keys: ' . (isset($_SESSION) ? implode(', ', array_keys($_SESSION)) : 'No session data'));
    error_log('DIT Helpers: dit_aes_keys exists: ' . (isset($_SESSION['dit_aes_keys']) ? 'Yes' : 'No'));
    if (isset($_SESSION['dit_aes_keys'])) {
        error_log('DIT Helpers: dit_aes_keys count: ' . count($_SESSION['dit_aes_keys']));
        error_log('DIT Helpers: dit_aes_keys keys: ' . implode(', ', array_keys($_SESSION['dit_aes_keys'])));
        if (isset($_SESSION['dit_aes_keys'][$customer_id])) {
            $key = $_SESSION['dit_aes_keys'][$customer_id];
            error_log('DIT Helpers: Found key in dit_aes_keys[' . $customer_id . '] - length: ' . strlen($key) . ', type: ' . (ctype_xdigit($key) ? 'hex' : 'binary'));
        } else {
            error_log('DIT Helpers: No key found in dit_aes_keys[' . $customer_id . ']');
        }
    }
    error_log('DIT Helpers: login_aes_key exists: ' . (isset($_SESSION['login_aes_key']) ? 'Yes' : 'No'));
    if (isset($_SESSION['login_aes_key'])) {
        $login_key = $_SESSION['login_aes_key'];
        error_log('DIT Helpers: login_aes_key length: ' . strlen($login_key) . ', type: ' . (ctype_xdigit($login_key) ? 'hex' : 'binary'));
    }
    error_log('DIT Helpers: Note: Cookies removed - AES keys stored only in session');
    error_log('DIT Helpers: Priority structure: 1) dit_aes_keys[customer_id], 2) login_aes_key (legacy)');

    // ПРІОРИТЕТ 1: Перевіряємо dit_aes_keys[customer_id] - оригінальний AES ключ
    error_log('DIT Helpers: - Checking PRIORITY 1: dit_aes_keys[' . $customer_id . ']');
    if ($customer_id && isset($_SESSION['dit_aes_keys'][$customer_id])) {
        $aes_key = $_SESSION['dit_aes_keys'][$customer_id];
        error_log('DIT Helpers: - PRIORITY 1: Key found in dit_aes_keys[' . $customer_id . ']');

        // Перевіряємо, чи це оригінальний AES ключ (32 байти) або стеганографічний (128 символів)
        if (strlen($aes_key) === 32) {
            error_log('DIT Helpers: - PRIORITY 1: Found original AES key in dit_aes_keys[' . $customer_id . ']');
            error_log('DIT Helpers: - PRIORITY 1: Key length: ' . strlen($aes_key) . ' bytes (original AES key)');
            error_log('DIT Helpers: - PRIORITY 1: Key preview: ' . bin2hex(substr($aes_key, 0, 8)) . '...');
            error_log('DIT Helpers: - PRIORITY 1: Returning original AES key');

            // ВАЖЛИВО: Повертаємо оригінальний AES ключ (32 байти)
            return $aes_key;
        } elseif (ctype_xdigit($aes_key) && strlen($aes_key) === 128) {
            error_log('DIT Helpers: - PRIORITY 1: WARNING: Found steganography key in dit_aes_keys[' . $customer_id . ']');
            error_log('DIT Helpers: - PRIORITY 1: Key length: ' . strlen($aes_key) . ' chars (steganography format)');
            error_log('DIT Helpers: - PRIORITY 1: This should be the original AES key, not steganography key');

            // Конвертуємо стеганографічний ключ в оригінальний AES ключ
            error_log('DIT Helpers: - PRIORITY 1: Converting steganography key to original AES key');
            $steganography = new \DIT\Steganography();
            $original_aes_key = $steganography->extract_aes_key_from_steganography($aes_key);
            if ($original_aes_key) {
                error_log('DIT Helpers: - PRIORITY 1: Converted steganography key to original AES key');
                error_log('DIT Helpers: - PRIORITY 1: Converted key length: ' . strlen($original_aes_key) . ' bytes');
                error_log('DIT Helpers: - PRIORITY 1: Returning converted key');
                return $original_aes_key;
            } else {
                error_log('DIT Helpers: - PRIORITY 1: Failed to convert steganography key');
            }
        } else {
            error_log('DIT Helpers: - PRIORITY 1: WARNING: Key in dit_aes_keys[' . $customer_id . '] has unknown format');
            error_log('DIT Helpers: - PRIORITY 1: Key length: ' . strlen($aes_key) . ' chars');
            error_log('DIT Helpers: - PRIORITY 1: Key type: ' . (ctype_xdigit($aes_key) ? 'hex' : 'binary'));
        }
    } else {
        error_log('DIT Helpers: - PRIORITY 1: No key found in dit_aes_keys[' . $customer_id . ']');
    }

    // ПРІОРИТЕТ 2: Cookies видалені - AES ключі зберігаються тільки в сесії
    error_log('DIT Helpers: - PRIORITY 2: Cookies removed - AES keys stored only in session');

    // ПРІОРИТЕТ 3: Legacy fallback - login_aes_key
    error_log('DIT Helpers: - Checking PRIORITY 3: login_aes_key (legacy fallback)');
    if (isset($_SESSION['login_aes_key'])) {
        $base64_key = $_SESSION['login_aes_key'];
        error_log('DIT Helpers: - PRIORITY 3: login_aes_key found in session');
        error_log('DIT Helpers: - PRIORITY 3: login_aes_key length: ' . strlen($base64_key) . ' chars');

        $binary_key = base64_decode($base64_key, true);

        if ($binary_key !== false && strlen($binary_key) === 32) {
            error_log('DIT Helpers: - PRIORITY 3: Found original AES key in login_aes_key (legacy)');
            error_log('DIT Helpers: - PRIORITY 3: Key length: ' . strlen($binary_key) . ' bytes');
            error_log('DIT Helpers: - PRIORITY 3: Returning decoded key from login_aes_key');
            return $binary_key;
        } else {
            error_log('DIT Helpers: - PRIORITY 3: Failed to decode login_aes_key or wrong length');
            if ($binary_key === false) {
                error_log('DIT Helpers: - PRIORITY 3: base64_decode failed');
            } else {
                error_log('DIT Helpers: - PRIORITY 3: Decoded key length: ' . strlen($binary_key) . ' (expected 32)');
            }
        }
    } else {
        error_log('DIT Helpers: - PRIORITY 3: No login_aes_key found in session');
    }

    // ПРІОРИТЕТ 4: Cookies видалені - AES ключі зберігаються тільки в сесії
    error_log('DIT Helpers: - PRIORITY 4: Cookies removed - AES keys stored only in session');

    error_log('DIT Helpers: - No valid AES key found for customer_id ' . $customer_id);
    error_log('DIT Helpers: - All priorities checked - no key found');
    error_log('DIT Helpers: - Final priority structure:');
    error_log('DIT Helpers:   - PRIORITY 1: dit_aes_keys[customer_id] (session)');
    error_log('DIT Helpers:   - PRIORITY 2: Cookies (removed)');
    error_log('DIT Helpers:   - PRIORITY 3: login_aes_key (session, legacy)');
    error_log('DIT Helpers:   - PRIORITY 4: Cookies (removed)');
    error_log('DIT Helpers: === GET USER PERMANENT AES KEY COMPLETE ===');
    return null;
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
 * Get user first name by customer ID.
 *
 * @param int $customer_id Customer ID.
 * @return string|null User first name or null if not found.
 */
function get_user_first_name($customer_id)
{
    $user_data = get_user_data($customer_id);
    return $user_data['first_name'] ?? null;
}

/**
 * Get user last name by customer ID.
 *
 * @param int $customer_id Customer ID.
 * @return string|null User last name or null if not found.
 */
function get_user_last_name($customer_id)
{
    $user_data = get_user_data($customer_id);
    return $user_data['last_name'] ?? null;
}

/**
 * Get user company by customer ID.
 *
 * @param int $customer_id Customer ID.
 * @return string|null User company or null if not found.
 */
function get_user_company($customer_id)
{
    $user_data = get_user_data($customer_id);
    return $user_data['company'] ?? null;
}

/**
 * Get user email by customer ID.
 *
 * @param int $customer_id Customer ID.
 * @return string|null User email or null if not found.
 */
function get_user_email($customer_id)
{
    $user_data = get_user_data($customer_id);
    return $user_data['email'] ?? null;
}

/**
 * Get customer ID by email.
 *
 * @param string $email User email.
 * @return int|null Customer ID or null if not found.
 */
function get_customer_id_by_email($email)
{
    // First try to get from session
    if (isset($_SESSION['dit_registered_customers'])) {
        foreach ($_SESSION['dit_registered_customers'] as $customer_id => $user_data) {
            if (isset($user_data['email']) && $user_data['email'] === $email) {
                log_message("Customer ID found in session for email: {$email}, ID: {$customer_id}", 'info');
                return (int) $customer_id;
            }
        }
    }

    // Fallback to WordPress settings (for backward compatibility)
    $settings = get_settings();
    $registered_users = $settings['registered_users'] ?? [];

    foreach ($registered_users as $customer_id => $user_data) {
        if (isset($user_data['email']) && $user_data['email'] === $email) {
            log_message("Customer ID found in WordPress settings for email: {$email}, ID: {$customer_id}", 'info');
            return (int) $customer_id;
        }
    }

    log_message("No customer ID found for email: {$email}", 'warning');
    return null;
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

        // Note: Cookies removed - customer data stored only in session
        log_message("Customer data stored only in session for customer ID: {$customer_id} (cookies removed)", 'info');
        return true;
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
function get_aes_key_from_cookies($customer_id = null)
{
    if ($customer_id === null && isset($_COOKIE['dit_customer_id'])) {
        $customer_id = $_COOKIE['dit_customer_id'];
    }

    // Try new format first (dit_aes_key_123)
    if ($customer_id && isset($_COOKIE['dit_aes_key_' . $customer_id])) {
        $base64_key = $_COOKIE['dit_aes_key_' . $customer_id];
        $binary_key = base64_decode($base64_key);
        return $binary_key;
    }

    // Try old format (dit_aes_key)
    if (isset($_COOKIE['dit_aes_key'])) {
        $base64_key = $_COOKIE['dit_aes_key'];
        $binary_key = base64_decode($base64_key);
        return $binary_key;
    }

    return null;
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

        // Note: Cookies removed - no cookies to delete
        log_message("No cookies to delete - customer data stored only in session", 'info');
        return true;
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
 * Get all DIT cookies for debugging.
 *
 * @return array Array of DIT cookies.
 */
function get_all_dit_cookies()
{
    $cookies = [];

    if (isset($_COOKIE['dit_customer_id'])) {
        $cookies['dit_customer_id'] = $_COOKIE['dit_customer_id'];
    }

    if (isset($_COOKIE['dit_aes_key'])) {
        $cookies['dit_aes_key'] = substr($_COOKIE['dit_aes_key'], 0, 20) . '...'; // Truncate for security
    }

    return $cookies;
}

/**
 * Save session data to user session.
 *
 * @param array $session_data Session data to save.
 * @return bool True if saved successfully.
 */
function save_session_data($session_data)
{
    try {
        if (!session_id()) {
            session_start();
        }

        $_SESSION['dit_session'] = $session_data;

        log_message("Session data saved successfully for user: " . ($session_data['email'] ?? 'unknown'), 'info');
        return true;
    } catch (\Exception $e) {
        log_message("Error saving session data: " . $e->getMessage(), 'error');
        return false;
    }
}

/**
 * Get current session data.
 *
 * @return array|null Session data or null if not found.
 */
function get_session_data()
{
    try {
        if (!session_id()) {
            session_start();
        }

        return $_SESSION['dit_session'] ?? null;
    } catch (\Exception $e) {
        log_message("Error getting session data: " . $e->getMessage(), 'error');
        return null;
    }
}

/**
 * Check if user has active session.
 *
 * @return bool True if user has active session.
 */
function has_active_session()
{
    $session_data = get_session_data();
    return $session_data !== null && !empty($session_data['session_id']);
}

/**
 * Get current session ID.
 *
 * @return int|null Session ID or null if not found.
 */
function get_current_session_id()
{
    $session_data = get_session_data();
    return $session_data['session_id'] ?? null;
}

/**
 * Get current user ID from session.
 *
 * @return int|null User ID or null if not found.
 */
function get_current_user_id()
{
    $session_data = get_session_data();
    return $session_data['user_id'] ?? null;
}

/**
 * Get current user email from session.
 *
 * @return string|null User email or null if not found.
 */
function get_current_user_email()
{
    $session_data = get_session_data();
    return $session_data['email'] ?? null;
}

/**
 * End current session.
 *
 * @return bool True if session ended successfully.
 */
function end_current_session()
{
    try {
        $session_data = get_session_data();
        if (!$session_data) {
            return true; // No session to end
        }

        $session_id = $session_data['session_id'] ?? null;
        if ($session_id) {
            // Call API to end session
            $core = Core::get_instance();
            $api = $core->api;
            $result = $api->end_session($session_id);

            if ($result !== null) {
                log_message("Session ended successfully via API for session ID: {$session_id}", 'info');
            } else {
                log_message("Failed to end session via API for session ID: {$session_id}", 'warning');
            }
        }

        // Clear session data
        if (!session_id()) {
            session_start();
        }
        unset($_SESSION['dit_session']);

        log_message("Session data cleared from PHP session", 'info');
        return true;
    } catch (\Exception $e) {
        log_message("Error ending session: " . $e->getMessage(), 'error');
        return false;
    }
}

/**
 * Record session transition.
 *
 * @param int $frame Frame number.
 * @param int $layer Layer number.
 * @param int $error Error code (optional, defaults to 0).
 * @return bool True if transition recorded successfully.
 */
function record_session_transition($frame, $layer, $error = 0)
{
    try {
        $session_id = get_current_session_id();
        if (!$session_id) {
            log_message("No active session found for recording transition", 'warning');
            return false;
        }

        $core = Core::get_instance();
        $api = $core->api;
        $result = $api->session_transition($session_id, $frame, $layer, $error);

        if ($result) {
            log_message("Session transition recorded successfully: Frame {$frame}, Layer {$layer}", 'info');
        } else {
            log_message("Failed to record session transition: Frame {$frame}, Layer {$layer}", 'warning');
        }

        return $result;
    } catch (\Exception $e) {
        log_message("Error recording session transition: " . $e->getMessage(), 'error');
        return false;
    }
}

/**
 * Get remaining session time.
 *
 * @return int|null Remaining seconds or null if not available.
 */
function get_remaining_session_time()
{
    $session_data = get_session_data();
    return $session_data['remaining_seconds'] ?? null;
}

/**
 * Check if session has time remaining.
 *
 * @return bool True if session has time remaining.
 */
function has_session_time_remaining()
{
    $remaining = get_remaining_session_time();
    return $remaining === null || $remaining > 0; // null means unlimited (metered license)
}

/**
 * Get session license type.
 *
 * @return int|null License type (0=metered, 1=time-based) or null if not found.
 */
function get_session_license_type()
{
    $session_data = get_session_data();
    return $session_data['license_type'] ?? null;
}

/**
 * Get session tool type.
 *
 * @return int|null Tool type (0=VFX, 1=DI, 2=Archive, 3=Production) or null if not found.
 */
function get_session_tool_type()
{
    $session_data = get_session_data();
    return $session_data['tool_type'] ?? null;
}

/**
 * Get tool type name.
 *
 * @param int $tool_type Tool type number.
 * @return string Tool type name.
 */
function get_tool_type_name($tool_type)
{
    $tool_types = [
        0 => 'VFX',
        1 => 'DI',
        2 => 'Archive',
        3 => 'Production'
    ];

    return $tool_types[$tool_type] ?? 'Unknown';
}

/**
 * Get license type name.
 *
 * @param int $license_type License type number.
 * @return string License type name.
 */
function get_license_type_name($license_type)
{
    $license_types = [
        0 => 'Metered',
        1 => 'Time-based'
    ];

    return $license_types[$license_type] ?? 'Unknown';
}

/**
 * Fix customer ID for a user by adding them to settings
 *
 * @param string $email User email
 * @param int $user_id User ID
 * @param string $first_name First name
 * @param string $last_name Last name
 * @param string $company Company name
 * @return array Result with success status and message
 */
function fix_customer_id($email, $user_id, $first_name = '', $last_name = '', $company = '')
{
    try {
        // Get current settings
        $settings = get_settings();
        $registered_users = $settings['registered_users'] ?? [];

        // Check if user already exists
        if (isset($registered_users[$user_id])) {
            return [
                'success' => true,
                'message' => 'User already exists in settings',
                'user_data' => $registered_users[$user_id]
            ];
        }

        // Add user to settings
        $settings['registered_users'][$user_id] = [
            'name' => trim($first_name . ' ' . $last_name),
            'customer_id' => $user_id,
            'registration_date' => current_time('mysql'),
            'last_updated' => current_time('mysql'),
            'aes_key_stored_in_cookie' => true,
            'first_name' => $first_name,
            'last_name' => $last_name,
            'company' => $company,
            'email' => $email
        ];

        // Save settings
        $result = update_option('dit_settings', $settings);

        if ($result) {
            log_message("User {$email} (ID: {$user_id}) successfully added to settings", 'info');
            return [
                'success' => true,
                'message' => "User successfully added to settings! Customer ID is now {$user_id}",
                'user_data' => $settings['registered_users'][$user_id]
            ];
        } else {
            log_message("Failed to save settings for user {$email}", 'error');
            return [
                'success' => false,
                'message' => 'Failed to save settings'
            ];
        }
    } catch (\Exception $e) {
        log_message("Error fixing customer ID for {$email}: " . $e->getMessage(), 'error');
        return [
            'success' => false,
            'message' => 'Error: ' . $e->getMessage()
        ];
    }
}

/**
 * Get users linked to a customer
 *
 * @param int $customer_id Customer ID
 * @return array Array of linked users
 */
function get_users_for_customer($customer_id)
{
    $settings = get_settings();
    $registered_users = $settings['registered_users'] ?? [];
    $linked_users = [];

    foreach ($registered_users as $user_id => $user_data) {
        if (isset($user_data['parent_customer_id']) && $user_data['parent_customer_id'] == $customer_id) {
            $linked_users[] = [
                'id' => $user_id,
                'name' => $user_data['name'] ?? '',
                'email' => $user_data['email'] ?? '',
                'first_name' => $user_data['first_name'] ?? '',
                'last_name' => $user_data['last_name'] ?? '',
                'company' => $user_data['company'] ?? '',
                'registration_date' => $user_data['registration_date'] ?? '',
                'role' => $user_data['role'] ?? 1
            ];
        }
    }

    return $linked_users;
}

/**
 * Get customer ID for a user
 *
 * @param int $user_id User ID
 * @return int|null Customer ID or null if not found
 */
function get_customer_id_for_user($user_id)
{
    $settings = get_settings();
    $registered_users = $settings['registered_users'] ?? [];

    if (isset($registered_users[$user_id])) {
        return $registered_users[$user_id]['parent_customer_id'] ?? null;
    }

    return null;
}

/**
 * Check if user is a customer
 *
 * @param int $user_id User ID
 * @return bool True if user is a customer
 */
function is_user_customer($user_id)
{
    $settings = get_settings();
    $registered_users = $settings['registered_users'] ?? [];

    if (isset($registered_users[$user_id])) {
        return ($registered_users[$user_id]['role'] ?? 0) === 2;
    }

    return false;
}

/**
 * Check if user is a regular user (not customer)
 *
 * @param int $user_id User ID
 * @return bool True if user is a regular user
 */
function is_user_regular_user($user_id)
{
    $settings = get_settings();
    $registered_users = $settings['registered_users'] ?? [];

    if (isset($registered_users[$user_id])) {
        return ($registered_users[$user_id]['role'] ?? 0) === 1;
    }

    return false;
}
