<?php

namespace DIT;

/**
 * Session Manager for DIT Integration
 * Handles user sessions, roles, and authentication state
 */
class Session_Manager
{
    /**
     * Session data structure
     */
    private $session_data = [
        'user_id' => null,
        'customer_id' => null,
        'email' => null,
        'role' => null, // Role ID (1=Administrator, 2=Customer, 3=User)
        'aes_key' => null,
        'session_id' => null,
        'license_type' => null,
        'tool_type' => null,
        'remaining_seconds' => null,
        'login_time' => null,
        'last_activity' => null
    ];

    /**
     * Constructor
     */
    public function __construct()
    {
        // Start session if not already started
        if (!session_id()) {
            session_start();
        }
    }

    /**
     * Initialize session after successful login
     *
     * @param array $login_result Login API response
     * @param array $user_data User data from form
     * @param array $session_result Session creation result
     * @return bool
     */
    public function init_session(array $login_result, array $user_data, ?array $session_result = null): bool
    {
        $core = Core::get_instance();
        $logger = $core->logger;

        try {
            // Determine user role and IDs
            $user_id = $login_result['UserId'] ?? $login_result['identifier'] ?? null;

            // Enhanced customer_id retrieval logic
            $customer_id = $this->get_customer_id_from_login_result($login_result, $user_data);

            // Determine role based on API response and user data
            $role = $this->determine_user_role($login_result, $user_data);

            // Check if user has a valid role
            if (!$role || $role <= 0) {
                $logger->log_api_interaction('Session Manager', [
                    'email' => $user_data['email'],
                    'role' => $role,
                    'step' => 'no_role_assigned'
                ], 'error', 'User has no valid role assigned');

                // Show access denied message
                $this->show_access_denied_message('У вас немає прав для доступу до цієї сторінки. Зверніться до адміністратора для отримання доступу.');

                return false;
            }

            // If role is customer but customer_id is not set, get it from saved data
            if ($role === 2 && (!$customer_id || $customer_id <= 0)) {
                $customer_id = \DIT\get_customer_id_by_email($user_data['email']);
                $logger->log_api_interaction('Session Manager', [
                    'email' => $user_data['email'],
                    'role' => $role,
                    'customer_id_fallback' => $customer_id,
                    'step' => 'customer_id_fallback'
                ], 'info', 'Customer ID retrieved from saved data: ' . $customer_id);
            }

            // Get AES key for this specific customer from session or cookies
            $aes_key = null;
            $is_steganography_key = false;
            $key_source = 'none';

            // ПРІОРИТЕТ 1: Перевіряємо новий AES ключ в сесії (найвищий пріоритет)
            if (isset($_SESSION['dit_aes_keys'][$customer_id])) {
                $session_key = $_SESSION['dit_aes_keys'][$customer_id];

                // Перевіряємо, чи це оригінальний AES ключ (32 байти)
                if (strlen($session_key) === 32) {
                    $aes_key = $session_key;
                    $key_source = 'new_session';

                    $logger->log_api_interaction('Session Manager', [
                        'email' => $user_data['email'],
                        'customer_id' => $customer_id,
                        'aes_key_found' => true,
                        'aes_key_source' => 'new_session',
                        'aes_key_length' => strlen($aes_key),
                        'aes_key_length_bytes' => mb_strlen($aes_key, '8bit'),
                        'aes_key_preview' => substr(bin2hex($aes_key), 0, 32) . '...',
                        'is_steganography_key' => false,
                        'key_format' => 'original_aes',
                        'key_origin' => 'new_login',
                        'step' => 'aes_key_from_new_session',
                        'note' => 'Found NEW original AES key (32 bytes) - HIGHEST PRIORITY'
                    ], 'info', 'NEW original AES key found in session for customer ' . $customer_id . ' (length: ' . strlen($aes_key) . ' bytes, format: original_aes, origin: new_login)');
                } elseif (ctype_xdigit($session_key) && strlen($session_key) === 128) {
                    // Це стеганографічний ключ - конвертуємо в оригінальний
                    $steganography = new \DIT\Steganography();
                    $original_aes_key = $steganography->extract_aes_key_from_steganography($session_key);

                    if ($original_aes_key) {
                        $aes_key = $original_aes_key;
                        $key_source = 'steganography_conversion';

                        $logger->log_api_interaction('Session Manager', [
                            'email' => $user_data['email'],
                            'customer_id' => $customer_id,
                            'aes_key_found' => true,
                            'aes_key_source' => 'steganography_conversion',
                            'aes_key_length' => strlen($aes_key),
                            'aes_key_length_bytes' => mb_strlen($aes_key, '8bit'),
                            'aes_key_preview' => substr(bin2hex($aes_key), 0, 32) . '...',
                            'is_steganography_key' => false,
                            'key_format' => 'converted_from_steganography',
                            'key_origin' => 'new_login',
                            'step' => 'aes_key_from_steganography_conversion',
                            'note' => 'Converted steganography key to original AES key'
                        ], 'info', 'Converted steganography key to original AES key for customer ' . $customer_id . ' (length: ' . strlen($aes_key) . ' bytes, format: converted_from_steganography, origin: new_login)');
                    }
                } else {
                    // Невідомий формат ключа
                    $logger->log_api_interaction('Session Manager', [
                        'email' => $user_data['email'],
                        'customer_id' => $customer_id,
                        'aes_key_found' => false,
                        'key_format' => 'unknown',
                        'key_length' => strlen($session_key),
                        'step' => 'unknown_key_format',
                        'note' => 'Unknown key format in session'
                    ], 'warning', 'Unknown key format in session for customer ' . $customer_id . ' (length: ' . strlen($session_key) . ' chars)');
                }
            }

            // ПРІОРИТЕТ 2: Перевіряємо cookies тільки якщо НЕ знайшли новий AES ключ
            if (!$aes_key) {
                $cookie_key = $this->get_aes_key_from_cookies($customer_id);
                if ($cookie_key) {
                    // Перевіряємо формат ключа з cookies
                    if (strlen($cookie_key) === 44) { // base64(32 bytes) = 44 chars
                        $decoded_key = base64_decode($cookie_key, true);
                        if ($decoded_key !== false && strlen($decoded_key) === 32) {
                            $aes_key = $decoded_key;
                            $key_source = 'cookies_base64';

                            $logger->log_api_interaction('Session Manager', [
                                'email' => $user_data['email'],
                                'customer_id' => $customer_id,
                                'aes_key_found' => true,
                                'aes_key_source' => 'cookies_base64',
                                'aes_key_length' => strlen($aes_key),
                                'aes_key_length_bytes' => mb_strlen($aes_key, '8bit'),
                                'aes_key_preview' => substr(bin2hex($aes_key), 0, 32) . '...',
                                'step' => 'aes_key_from_cookies_base64',
                                'note' => 'Found AES key in cookies (base64 format) - LEGACY FALLBACK'
                            ], 'info', 'AES key found in cookies (base64 format) for customer ' . $customer_id . ' (length: ' . strlen($aes_key) . ' bytes) - LEGACY FALLBACK');
                        }
                    } elseif (ctype_xdigit($cookie_key) && strlen($cookie_key) === 128) {
                        // Стеганографічний ключ в cookies - конвертуємо
                        $steganography = new \DIT\Steganography();
                        $original_aes_key = $steganography->extract_aes_key_from_steganography($cookie_key);

                        if ($original_aes_key) {
                            $aes_key = $original_aes_key;
                            $key_source = 'cookies_steganography';

                            $logger->log_api_interaction('Session Manager', [
                                'email' => $user_data['email'],
                                'customer_id' => $customer_id,
                                'aes_key_found' => true,
                                'aes_key_source' => 'cookies_steganography',
                                'aes_key_length' => strlen($aes_key),
                                'aes_key_length_bytes' => mb_strlen($aes_key, '8bit'),
                                'aes_key_preview' => substr(bin2hex($aes_key), 0, 32) . '...',
                                'step' => 'aes_key_from_cookies_steganography',
                                'note' => 'Converted steganography key from cookies to original AES key - LEGACY FALLBACK'
                            ], 'info', 'Converted steganography key from cookies to original AES key for customer ' . $customer_id . ' (length: ' . strlen($aes_key) . ' bytes) - LEGACY FALLBACK');
                        }
                    }
                }

                if (!$aes_key) {
                    $logger->log_api_interaction('Session Manager', [
                        'email' => $user_data['email'],
                        'customer_id' => $customer_id,
                        'aes_key_found' => false,
                        'step' => 'aes_key_not_found',
                        'note' => 'No valid AES key found in session or cookies'
                    ], 'warning', 'No AES key found for customer ' . $customer_id);
                }
            }

            // Логуємо фінальний результат
            if ($aes_key) {
                $logger->log_api_interaction('Session Manager', [
                    'email' => $user_data['email'],
                    'customer_id' => $customer_id,
                    'aes_key_found' => true,
                    'aes_key_source' => $key_source,
                    'aes_key_length' => strlen($aes_key),
                    'aes_key_length_bytes' => mb_strlen($aes_key, '8bit'),
                    'aes_key_preview' => substr(bin2hex($aes_key), 0, 32) . '...',
                    'key_source' => $key_source,
                    'step' => 'final_aes_key_selected',
                    'note' => 'Final AES key selected: ' . $key_source . ' (length: ' . strlen($aes_key) . ' bytes)'
                ], 'info', 'Final AES key selected for customer ' . $customer_id . ' (source: ' . $key_source . ', length: ' . strlen($aes_key) . ' bytes)');
            }

            // Log AES key details before storing in session data
            if ($aes_key) {
                $logger->log_api_interaction('Session Manager', [
                    'email' => $user_data['email'],
                    'customer_id' => $customer_id,
                    'step' => 'before_session_data_storage',
                    'aes_key_length' => strlen($aes_key),
                    'aes_key_length_bytes' => mb_strlen($aes_key, '8bit'),
                    'aes_key_preview' => substr(bin2hex($aes_key), 0, 32) . '...',
                    'note' => 'AES key before storing in session_data'
                ], 'info', 'AES key details before storing in session_data (length: ' . strlen($aes_key) . ' chars)');
            }

            // Prepare session data
            $this->session_data = [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'email' => $user_data['email'],
                'role' => $role,
                'aes_key' => $aes_key,
                'session_id' => $session_result['SessionId'] ?? null,
                'license_type' => $session_result['LicenseType'] ?? null,
                'tool_type' => $session_result['ToolType'] ?? null,
                'remaining_seconds' => $session_result['RemainingSeconds'] ?? null,
                'login_time' => time(),
                'last_activity' => time()
            ];

            // Log AES key details after storing in session data
            if ($aes_key && isset($this->session_data['aes_key'])) {
                $logger->log_api_interaction('Session Manager', [
                    'email' => $user_data['email'],
                    'customer_id' => $customer_id,
                    'step' => 'after_session_data_storage',
                    'aes_key_length' => strlen($this->session_data['aes_key']),
                    'aes_key_length_bytes' => mb_strlen($this->session_data['aes_key'], '8bit'),
                    'aes_key_preview' => substr(bin2hex($this->session_data['aes_key']), 0, 32) . '...',
                    'note' => 'AES key after storing in session_data'
                ], 'info', 'AES key details after storing in session_data (length: ' . strlen($this->session_data['aes_key']) . ' chars)');
            }

            // Store in PHP session
            $_SESSION['dit_user_session'] = $this->session_data;

            // Log AES key details after storing in PHP session
            if ($aes_key && isset($_SESSION['dit_user_session']['aes_key'])) {
                $logger->log_api_interaction('Session Manager', [
                    'email' => $user_data['email'],
                    'customer_id' => $customer_id,
                    'step' => 'after_php_session_storage',
                    'aes_key_length' => strlen($_SESSION['dit_user_session']['aes_key']),
                    'aes_key_length_bytes' => mb_strlen($_SESSION['dit_user_session']['aes_key'], '8bit'),
                    'aes_key_preview' => substr(bin2hex($_SESSION['dit_user_session']['aes_key']), 0, 32) . '...',
                    'note' => 'AES key after storing in PHP session'
                ], 'info', 'AES key details after storing in PHP session (length: ' . strlen($_SESSION['dit_user_session']['aes_key']) . ' chars)');
            }

            // Store in WordPress user meta if user exists
            $this->store_in_wordpress_user_meta($user_data['email']);

            // Store in secure cookies for client-side access
            $this->store_in_secure_cookies();

            // Update user data in database
            $db_user_data = [
                'user_id' => $user_id,
                'email' => $user_data['email'],
                'aes_key' => $aes_key,
                'first_name' => $user_data['first_name'] ?? '',
                'last_name' => $user_data['last_name'] ?? '',
                'company' => $user_data['company'] ?? '',
                'password' => hash('sha256', $user_data['password'])
            ];

            // Add tools only for non-admin roles
            if ($role !== 3) {
                $db_user_data['tools'] = $user_data['tools'] ?? [];
            }

            // Note: Database functionality has been removed
            $db_update_result = true; // Simulate success

            $logger->log_api_interaction('Session Manager', [
                'email' => $user_data['email'],
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'role' => $role,
                'session_id' => $this->session_data['session_id'],
                'has_aes_key' => !empty($aes_key),
                'db_update_success' => $db_update_result,
                'step' => 'session_initialized',
                'note' => 'Database functionality removed'
            ], 'success', 'User session initialized successfully (database update skipped)');

            return true;
        } catch (\Exception $e) {
            $logger->log_api_interaction('Session Manager', [
                'email' => $user_data['email'] ?? 'unknown',
                'error' => $e->getMessage(),
                'step' => 'session_init_error'
            ], 'error', 'Failed to initialize user session: ' . $e->getMessage());

            return false;
        }
    }

    /**
     * Determine user role based on login result and user data
     * Now returns numeric role values (1, 2, 3) instead of text values
     *
     * @param array $login_result Login API response
     * @param array $user_data User data from form
     * @return int Role ID (1=User, 2=Customer, 3=Administrator)
     */
    private function determine_user_role(array $login_result, array $user_data): int
    {
        $core = Core::get_instance();
        $logger = $core->logger;
        $email = $user_data['email'] ?? 'unknown';

        // Check if we have role_id in user_data (from form submission) - HIGHEST PRIORITY
        if (isset($user_data['role_id']) && is_numeric($user_data['role_id'])) {
            $role_id = (int)$user_data['role_id'];
            $logger->log_api_interaction('Session Manager', [
                'email' => $email,
                'role_id' => $role_id,
                'step' => 'role_from_user_data'
            ], 'info', 'User role determined from user data (form submission): ' . $role_id);

            return $role_id;
        }

        // Check if we have role_id in login_result (fallback)
        if (isset($login_result['role_id']) && is_numeric($login_result['role_id'])) {
            $role_id = (int)$login_result['role_id'];
            $logger->log_api_interaction('Session Manager', [
                'email' => $email,
                'role_id' => $role_id,
                'step' => 'role_from_login_result'
            ], 'info', 'User role determined from login result: ' . $role_id);

            return $role_id;
        }

        // 1. Check if we have customer_id in response (Customer role = 2)
        if (isset($login_result['custOrUserID']) && $login_result['custOrUserID'] > 0) {
            $logger->log_api_interaction('Session Manager', [
                'email' => $email,
                'customer_id' => $login_result['custOrUserID'],
                'step' => 'role_determined_customer'
            ], 'info', 'User role determined as Customer (2) based on custOrUserID');

            return 2; // Customer
        }

        // 2. Check if we have saved customer_id from registration (Customer role = 2)
        // This is the key fix - prioritize saved customer_id over user_id
        $saved_customer_id = \DIT\get_customer_id_by_email($email);
        if ($saved_customer_id && $saved_customer_id > 0) {
            $logger->log_api_interaction('Session Manager', [
                'email' => $email,
                'saved_customer_id' => $saved_customer_id,
                'step' => 'role_determined_customer_saved'
            ], 'info', 'User role determined as Customer (2) based on saved customer_id from registration');

            return 2; // Customer
        }

        // 3. If no customer_id, check if user_id exists (User role = 1)
        $user_id = $login_result['UserId'] ?? $login_result['identifier'] ?? null;
        if ($user_id && $user_id > 0) {
            $logger->log_api_interaction('Session Manager', [
                'email' => $email,
                'user_id' => $user_id,
                'step' => 'role_determined_user'
            ], 'info', 'User role determined as User (1) based on user_id');

            return 1; // User
        }

        // 4. Default to User (1) if we can't determine
        $logger->log_api_interaction('Session Manager', [
            'email' => $email,
            'login_result' => $login_result,
            'saved_customer_id' => $saved_customer_id,
            'step' => 'role_default_user'
        ], 'warning', 'Could not determine user role, defaulting to User (1)');

        return 1; // User
    }

    /**
     * Get AES key from cookies for specific customer
     * This method is now used as a fallback when no new AES key is found in session
     *
     * @param int $customer_id Customer ID
     * @return string|null AES key or null if not found
     */
    private function get_aes_key_from_cookies(int $customer_id): ?string
    {
        $cookie_name = 'dit_aes_key_' . $customer_id;
        if (isset($_COOKIE[$cookie_name])) {
            $key = $_COOKIE[$cookie_name];

            // Log key details from cookies
            error_log('DIT Session Manager: get_aes_key_from_cookies - Key details from cookies:');
            error_log('DIT Session Manager: - Customer ID: ' . $customer_id);
            error_log('DIT Session Manager: - Cookie name: ' . $cookie_name);
            error_log('DIT Session Manager: - Key length: ' . strlen($key) . ' chars');
            error_log('DIT Session Manager: - Key length (bytes): ' . mb_strlen($key, '8bit') . ' bytes');

            // ВАЖЛИВО: Не повертаємо ключ безпосередньо
            // Це тепер fallback метод, який викликається тільки якщо немає нового AES ключа
            error_log('DIT Session Manager: - NOTE: This is a LEGACY fallback method');
            error_log('DIT Session Manager: - NOTE: New AES key should have priority over this legacy key');

            // Повертаємо ключ як є - обробка буде в основному методі
            return $key;
        }
        return null;
    }

    /**
     * Store AES key and IV in session for specific customer
     *
     * @param int $customer_id Customer ID
     * @param string $key Base64 encoded AES key
     * @param string $iv Raw binary IV (16 bytes)
     * @return bool
     */
    public function store_aes_key_for_customer(int $customer_id, string $key, string $iv): bool
    {
        try {
            // Verify IV length
            if (mb_strlen($iv, '8bit') !== 16) {
                error_log('DIT Session Manager: Invalid IV length: ' . mb_strlen($iv, '8bit') . ' bytes');
                return false;
            }

            // Log key details before storage
            error_log('DIT Session Manager: store_aes_key_for_customer - Key details before storage:');
            error_log('DIT Session Manager: - Customer ID: ' . $customer_id);
            error_log('DIT Session Manager: - Key length: ' . strlen($key) . ' chars');
            error_log('DIT Session Manager: - Key length (bytes): ' . mb_strlen($key, '8bit') . ' bytes');
            error_log('DIT Session Manager: - Key preview: ' . substr(bin2hex($key), 0, 32) . '...');
            error_log('DIT Session Manager: - IV length: ' . mb_strlen($iv, '8bit') . ' bytes');

            // Initialize session array if needed
            if (!isset($_SESSION['dit_aes_keys'])) {
                $_SESSION['dit_aes_keys'] = [];
            }

            // Store in session for specific customer
            $_SESSION['dit_aes_keys'][$customer_id] = $key;
            $_SESSION['dit_aes_iv'] = $iv;

            // Log key details after storing in session
            error_log('DIT Session Manager: - Session dit_aes_keys[' . $customer_id . '] length: ' . strlen($_SESSION['dit_aes_keys'][$customer_id]) . ' chars');
            error_log('DIT Session Manager: - Session dit_aes_iv length: ' . strlen($_SESSION['dit_aes_iv']) . ' bytes');

            // Also update session data array
            $this->session_data['aes_key'] = $key;

            // Log key details after storing in session_data
            error_log('DIT Session Manager: - Session data aes_key length: ' . strlen($this->session_data['aes_key']) . ' chars');

            // Store in cookies for persistence
            $cookie_name = 'dit_aes_key_' . $customer_id;
            setcookie($cookie_name, $key, time() + (86400 * 30), '/'); // 30 днів

            error_log('DIT Session Manager: AES key stored successfully for customer ' . $customer_id);
            return true;
        } catch (\Exception $e) {
            error_log('DIT Session Manager: Failed to store AES key for customer ' . $customer_id . ': ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Store AES key and IV in session (legacy method)
     *
     * @param string $key Raw binary AES key (32 bytes)
     * @param string $iv Raw binary IV (16 bytes)
     * @return bool
     */
    public function store_aes_key(string $key, string $iv): bool
    {
        try {
            // Verify key and IV lengths
            if (mb_strlen($key, '8bit') !== 32) {
                error_log('DIT Session Manager: Invalid AES key length: ' . mb_strlen($key, '8bit') . ' bytes');
                return false;
            }

            if (mb_strlen($iv, '8bit') !== 16) {
                error_log('DIT Session Manager: Invalid IV length: ' . mb_strlen($iv, '8bit') . ' bytes');
                return false;
            }

            // Store in session
            $_SESSION['dit_aes_key'] = $key;
            $_SESSION['dit_aes_iv'] = $iv;

            // Also update session data array
            $this->session_data['aes_key'] = $key;

            error_log('DIT Session Manager: AES key stored successfully');
            return true;
        } catch (\Exception $e) {
            error_log('DIT Session Manager: Failed to store AES key: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Get stored AES key and IV from session for specific customer
     *
     * @param int $customer_id Customer ID
     * @return array|null Array with 'key' and 'iv' or null if not found
     */
    public function get_aes_key_and_iv_for_customer(int $customer_id): ?array
    {
        try {
            if (isset($_SESSION['dit_aes_keys'][$customer_id]) && isset($_SESSION['dit_aes_iv'])) {
                return [
                    'key' => $_SESSION['dit_aes_keys'][$customer_id],
                    'iv' => $_SESSION['dit_aes_iv']
                ];
            }

            return null;
        } catch (\Exception $e) {
            error_log('DIT Session Manager: Failed to get AES key for customer ' . $customer_id . ': ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Get stored AES key and IV from session (legacy method)
     *
     * @return array|null Array with 'key' and 'iv' or null if not found
     */
    public function get_aes_key_and_iv(): ?array
    {
        try {
            if (isset($_SESSION['dit_aes_key']) && isset($_SESSION['dit_aes_iv'])) {
                return [
                    'key' => $_SESSION['dit_aes_key'],
                    'iv' => $_SESSION['dit_aes_iv']
                ];
            }

            return null;
        } catch (\Exception $e) {
            error_log('DIT Session Manager: Failed to get AES key: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Clear stored AES key and IV from session for specific customer
     *
     * @param int $customer_id Customer ID
     * @return bool
     */
    public function clear_aes_key_for_customer(int $customer_id): bool
    {
        try {
            unset($_SESSION['dit_aes_keys'][$customer_id]);
            unset($_SESSION['dit_aes_iv']);

            // Also clear from session data array
            $this->session_data['aes_key'] = null;

            // Clear from cookies
            $cookie_name = 'dit_aes_key_' . $customer_id;
            setcookie($cookie_name, '', time() - 3600, '/');

            error_log('DIT Session Manager: AES key cleared successfully for customer ' . $customer_id);
            return true;
        } catch (\Exception $e) {
            error_log('DIT Session Manager: Failed to clear AES key for customer ' . $customer_id . ': ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Clear stored AES key and IV from session (legacy method)
     *
     * @return bool
     */
    public function clear_aes_key(): bool
    {
        try {
            unset($_SESSION['dit_aes_key']);
            unset($_SESSION['dit_aes_iv']);

            // Also clear from session data array
            $this->session_data['aes_key'] = null;

            error_log('DIT Session Manager: AES key cleared successfully');
            return true;
        } catch (\Exception $e) {
            error_log('DIT Session Manager: Failed to clear AES key: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Store session data in WordPress user meta
     *
     * @param string $email User email
     */
    private function store_in_wordpress_user_meta(string $email): void
    {
        $user = get_user_by('email', $email);
        if ($user) {
            update_user_meta($user->ID, 'dit_user_session', $this->session_data);
            update_user_meta($user->ID, 'dit_last_login', time());
        }
    }

    /**
     * Store critical data in secure cookies
     */
    private function store_in_secure_cookies(): void
    {
        // Store user ID and role in secure cookies
        if ($this->session_data['user_id']) {
            setcookie('dit_user_id', $this->session_data['user_id'], [
                'expires' => time() + (365 * 24 * 60 * 60), // 1 year
                'path' => '/',
                'secure' => true,
                'httponly' => true,
                'samesite' => 'Strict'
            ]);
        }

        if ($this->session_data['role']) {
            setcookie('dit_user_role', $this->session_data['role'], [
                'expires' => time() + (365 * 24 * 60 * 60), // 1 year
                'path' => '/',
                'secure' => true,
                'httponly' => true,
                'samesite' => 'Strict'
            ]);
        }
    }

    /**
     * Check if user is logged in
     *
     * @return bool
     */
    public function is_logged_in(): bool
    {
        return isset($_SESSION['dit_user_session']) &&
            !empty($_SESSION['dit_user_session']['user_id']) &&
            !empty($_SESSION['dit_user_session']['email']);
    }

    /**
     * Get current user session data
     *
     * @return array|null
     */
    public function get_session_data(): ?array
    {
        if ($this->is_logged_in()) {
            // Update last activity
            $_SESSION['dit_user_session']['last_activity'] = time();
            return $_SESSION['dit_user_session'];
        }
        return null;
    }

    /**
     * Get user role
     *
     * @return int|null Role ID (1=User, 2=Customer, 3=Administrator) or null
     */
    public function get_user_role(): ?int
    {
        $session_data = $this->get_session_data();
        if (!isset($session_data['role'])) {
            return null;
        }

        // Handle legacy text roles migration
        if (is_string($session_data['role'])) {
            $role_id = $this->migrate_legacy_role($session_data['role']);
            if ($role_id !== null) {
                // Update session with numeric role
                $this->update_session_data(['role' => $role_id]);
                return $role_id;
            }
        }

        return (int)$session_data['role'];
    }

    /**
     * Migrate legacy text role to numeric role ID
     *
     * @param string $legacy_role Legacy role string
     * @return int|null Numeric role ID or null if invalid
     */
    private function migrate_legacy_role(string $legacy_role): ?int
    {
        $core = Core::get_instance();
        $logger = $core->logger;

        $role_mapping = [
            'administrator' => 3,
            'admin' => 3,
            'customer' => 2,
            'user' => 1,
            'regular' => 1
        ];

        $normalized_role = strtolower(trim($legacy_role));
        $role_id = $role_mapping[$normalized_role] ?? null;

        if ($role_id !== null) {
            $logger->log_api_interaction('Session Manager', [
                'legacy_role' => $legacy_role,
                'migrated_role_id' => $role_id,
                'step' => 'legacy_role_migration'
            ], 'info', 'Legacy role migrated: ' . $legacy_role . ' -> ' . $role_id);
        } else {
            $logger->log_api_interaction('Session Manager', [
                'legacy_role' => $legacy_role,
                'step' => 'legacy_role_migration_failed'
            ], 'warning', 'Failed to migrate legacy role: ' . $legacy_role);
        }

        return $role_id;
    }

    /**
     * Check if user is customer
     *
     * @return bool
     */
    public function is_customer(): bool
    {
        return $this->get_user_role() === 2;
    }

    /**
     * Check if user is regular user
     *
     * @return bool
     */
    public function is_user(): bool
    {
        return $this->get_user_role() === 1;
    }

    /**
     * Check if user is administrator
     *
     * @return bool
     */
    public function is_administrator(): bool
    {
        return $this->get_user_role() === 3;
    }

    /**
     * Get user ID
     *
     * @return int|null
     */
    public function get_user_id(): ?int
    {
        $session_data = $this->get_session_data();
        return $session_data['user_id'] ?? null;
    }

    /**
     * Get customer ID
     *
     * @return int|null
     */
    public function get_customer_id(): ?int
    {
        $session_data = $this->get_session_data();
        return $session_data['customer_id'] ?? null;
    }

    /**
     * Get user email
     *
     * @return string|null
     */
    public function get_user_email(): ?string
    {
        $session_data = $this->get_session_data();
        return $session_data['email'] ?? null;
    }

    /**
     * Get AES key
     *
     * @return string|null
     */
    public function get_aes_key(): ?string
    {
        $customer_id = $this->get_customer_id();
        return $this->get_aes_key_for_customer($customer_id);
    }

    /**
     * Get stored AES key from session for specific customer
     *
     * @param int $customer_id Customer ID
     * @return string|null AES key or null if not found
     */
    public function get_aes_key_for_customer($customer_id = null): ?string
    {
        if (!$customer_id) {
            $customer_id = $this->get_customer_id();
        }

        if (!$customer_id) {
            return null;
        }

        error_log('DIT Session Manager: === GET AES KEY ===');
        error_log('DIT Session Manager: Customer ID: ' . $customer_id);

        // ПРІОРИТЕТ 1: Перевіряємо dit_aes_keys[customer_id] - оригінальний AES ключ
        if (isset($_SESSION['dit_aes_keys'][$customer_id])) {
            $key = $_SESSION['dit_aes_keys'][$customer_id];

            // Перевіряємо формат ключа
            if (strlen($key) === 32) {
                error_log('DIT Session Manager: - Found original AES key in dit_aes_keys[' . $customer_id . ']');
                error_log('DIT Session Manager: - Key length: ' . strlen($key) . ' bytes (original AES key)');
                error_log('DIT Session Manager: - Key preview: ' . bin2hex(substr($key, 0, 8)) . '...');

                // ВАЖЛИВО: Повертаємо оригінальний AES ключ (32 байти)
                return $key;
            } elseif (ctype_xdigit($key) && strlen($key) === 128) {
                error_log('DIT Session Manager: - WARNING: Found steganography key in dit_aes_keys[' . $customer_id . ']');
                error_log('DIT Session Manager: - Key length: ' . strlen($key) . ' chars (steganography format)');
                error_log('DIT Session Manager: - This should be the original AES key, not steganography key');

                // Конвертуємо стеганографічний ключ в оригінальний AES ключ
                $steganography = new \DIT\Steganography();
                $original_aes_key = $steganography->extract_aes_key_from_steganography($key);
                if ($original_aes_key) {
                    error_log('DIT Session Manager: - Converted steganography key to original AES key');
                    error_log('DIT Session Manager: - Converted key length: ' . strlen($original_aes_key) . ' bytes');
                    return $original_aes_key;
                }
            } else {
                error_log('DIT Session Manager: - WARNING: Key in dit_aes_keys[' . $customer_id . '] has unknown format');
                error_log('DIT Session Manager: - Key length: ' . strlen($key) . ' chars');
            }
        }

        // ПРІОРИТЕТ 2: Перевіряємо cookies
        if (isset($_COOKIE['dit_aes_key_' . $customer_id])) {
            $cookie_key = $_COOKIE['dit_aes_key_' . $customer_id];

            // Перевіряємо, чи це base64-кодований оригінальний AES ключ
            if (strlen($cookie_key) === 44) { // base64(32 bytes) = 44 chars
                $decoded_key = base64_decode($cookie_key, true);
                if ($decoded_key !== false && strlen($decoded_key) === 32) {
                    error_log('DIT Session Manager: - Found original AES key in cookies for customer_id ' . $customer_id);
                    error_log('DIT Session Manager: - Key length: ' . strlen($decoded_key) . ' bytes (decoded from base64)');
                    return $decoded_key;
                }
            }

            // Перевіряємо, чи це стеганографічний ключ
            if (ctype_xdigit($cookie_key) && strlen($cookie_key) === 128) {
                error_log('DIT Session Manager: - Found steganography key in cookies for customer_id ' . $customer_id);
                error_log('DIT Session Manager: - Converting steganography key to original AES key');

                $steganography = new \DIT\Steganography();
                $original_aes_key = $steganography->extract_aes_key_from_steganography($cookie_key);
                if ($original_aes_key) {
                    error_log('DIT Session Manager: - Converted steganography key to original AES key');
                    error_log('DIT Session Manager: - Converted key length: ' . strlen($original_aes_key) . ' bytes');
                    return $original_aes_key;
                }
            }
        }

        // ПРІОРИТЕТ 3: Legacy fallback - login_aes_key
        if (isset($_SESSION['login_aes_key'])) {
            $base64_key = $_SESSION['login_aes_key'];
            $binary_key = base64_decode($base64_key, true);

            if ($binary_key !== false && strlen($binary_key) === 32) {
                error_log('DIT Session Manager: - Found original AES key in login_aes_key (legacy)');
                error_log('DIT Session Manager: - Key length: ' . strlen($binary_key) . ' bytes');
                return $binary_key;
            }
        }

        // ПРІОРИТЕТ 4: Legacy fallback - cookies
        if (isset($_COOKIE['dit_login_aes_key'])) {
            $base64_key = $_COOKIE['dit_login_aes_key'];
            $binary_key = base64_decode($base64_key, true);

            if ($binary_key !== false && strlen($binary_key) === 32) {
                error_log('DIT Session Manager: - Found original AES key in dit_login_aes_key cookie (legacy)');
                error_log('DIT Session Manager: - Key length: ' . strlen($binary_key) . ' bytes');
                return $binary_key;
            }
        }

        error_log('DIT Session Manager: - No valid AES key found for customer_id ' . $customer_id);
        error_log('DIT Session Manager: === GET AES KEY COMPLETE ===');
        return null;
    }

    /**
     * Get session ID
     *
     * @return string|null
     */
    public function get_session_id(): ?string
    {
        $session_data = $this->get_session_data();
        return $session_data['session_id'] ?? null;
    }

    /**
     * Update session data
     *
     * @param array $new_data New session data
     * @return bool
     */
    public function update_session_data(array $new_data): bool
    {
        if (!$this->is_logged_in()) {
            return false;
        }

        $_SESSION['dit_user_session'] = array_merge($_SESSION['dit_user_session'], $new_data);
        $_SESSION['dit_user_session']['last_activity'] = time();

        return true;
    }

    /**
     * Logout user
     *
     * @return bool
     */
    public function logout(): bool
    {
        $core = Core::get_instance();
        $logger = $core->logger;

        try {
            $session_data = $this->get_session_data();
            $email = $session_data['email'] ?? 'unknown';

            // End session with API if session_id exists
            if (!empty($session_data['session_id'])) {
                $api = $core->api;
                $api->end_session($session_data['session_id']);
            }

            // Clear PHP session
            unset($_SESSION['dit_user_session']);
            session_destroy();

            // Clear secure cookies
            setcookie('dit_user_id', '', time() - 3600, '/');
            setcookie('dit_user_role', '', time() - 3600, '/');
            setcookie('dit_aes_key', '', time() - 3600, '/');
            setcookie('dit_customer_id', '', time() - 3600, '/');

            // Clear WordPress user meta
            if ($email !== 'unknown') {
                $user = get_user_by('email', $email);
                if ($user) {
                    delete_user_meta($user->ID, 'dit_user_session');
                }
            }

            $logger->log_api_interaction('Session Manager', [
                'email' => $email,
                'step' => 'logout_completed'
            ], 'info', 'User logged out successfully');

            return true;
        } catch (\Exception $e) {
            $logger->log_api_interaction('Session Manager', [
                'error' => $e->getMessage(),
                'step' => 'logout_error'
            ], 'error', 'Error during logout: ' . $e->getMessage());

            return false;
        }
    }

    /**
     * Check session timeout
     *
     * @param int $timeout_seconds Session timeout in seconds (default: 24 hours)
     * @return bool True if session is valid, false if timed out
     */
    public function check_session_timeout(int $timeout_seconds = 86400): bool
    {
        $session_data = $this->get_session_data();
        if (!$session_data) {
            return false;
        }

        $last_activity = $session_data['last_activity'] ?? 0;
        $time_since_activity = time() - $last_activity;

        if ($time_since_activity > $timeout_seconds) {
            $this->logout();
            return false;
        }

        return true;
    }

    /**
     * Refresh session activity
     */
    public function refresh_activity(): void
    {
        if ($this->is_logged_in()) {
            $_SESSION['dit_user_session']['last_activity'] = time();
        }
    }

    /**
     * Force update role in existing session
     * This method can be called to migrate legacy roles immediately
     *
     * @return bool True if role was updated, false otherwise
     */
    public function force_role_migration(): bool
    {
        if (!$this->is_logged_in()) {
            return false;
        }

        $session_data = $this->get_session_data();
        if (!isset($session_data['role'])) {
            return false;
        }

        // If role is already numeric, no migration needed
        if (is_numeric($session_data['role'])) {
            return false;
        }

        // Migrate the role
        $role_id = $this->migrate_legacy_role($session_data['role']);
        if ($role_id === null) {
            return false;
        }

        // Update session with new role
        $success = $this->update_session_data(['role' => $role_id]);

        $core = Core::get_instance();
        $logger = $core->logger;

        if ($success) {
            $logger->log_api_interaction('Session Manager', [
                'email' => $session_data['email'] ?? 'unknown',
                'old_role' => $session_data['role'],
                'new_role' => $role_id,
                'step' => 'force_role_migration_success'
            ], 'info', 'Role force migrated: ' . $session_data['role'] . ' -> ' . $role_id);
        } else {
            $logger->log_api_interaction('Session Manager', [
                'email' => $session_data['email'] ?? 'unknown',
                'old_role' => $session_data['role'],
                'new_role' => $role_id,
                'step' => 'force_role_migration_failed'
            ], 'error', 'Failed to force migrate role: ' . $session_data['role'] . ' -> ' . $role_id);
        }

        return $success;
    }

    /**
     * Show access denied message to user
     *
     * @param string $message Error message to display
     */
    private function show_access_denied_message(string $message): void
    {
        // Store error message in session for display
        if (!session_id()) {
            session_start();
        }

        $_SESSION['dit_access_denied_message'] = $message;

        // Log the access denied attempt
        $core = Core::get_instance();
        $logger = $core->logger;

        $logger->log_api_interaction('Session Manager', [
            'step' => 'access_denied',
            'message' => $message,
            'session_id' => session_id()
        ], 'error', 'Access denied - user has no valid role assigned');
    }

    /**
     * Enhanced customer ID retrieval from login result
     *
     * @param array $login_result Login API response
     * @param array $user_data User data from form
     * @return int|null Customer ID or null if not found
     */
    private function get_customer_id_from_login_result(array $login_result, array $user_data): ?int
    {
        $core = Core::get_instance();
        $logger = $core->logger;
        $email = $user_data['email'] ?? 'unknown';

        // Method 1: Direct from custOrUserID (original method)
        if (isset($login_result['custOrUserID']) && $login_result['custOrUserID'] > 0) {
            $logger->log_api_interaction('Session Manager', [
                'email' => $email,
                'customer_id' => $login_result['custOrUserID'],
                'source' => 'custOrUserID',
                'step' => 'customer_id_direct'
            ], 'info', 'Customer ID found in custOrUserID: ' . $login_result['custOrUserID']);
            return (int) $login_result['custOrUserID'];
        }

        // Method 2: Check other possible customer ID fields
        $possible_fields = ['customerId', 'CustomerId', 'customer_id', 'CustomerID', 'customerID'];
        foreach ($possible_fields as $field) {
            if (isset($login_result[$field]) && $login_result[$field] > 0) {
                $logger->log_api_interaction('Session Manager', [
                    'email' => $email,
                    'customer_id' => $login_result[$field],
                    'source' => $field,
                    'step' => 'customer_id_alternative'
                ], 'info', 'Customer ID found in ' . $field . ': ' . $login_result[$field]);
                return (int) $login_result[$field];
            }
        }

        // Method 3: Get from saved data by email
        $saved_customer_id = \DIT\get_customer_id_by_email($email);
        if ($saved_customer_id && $saved_customer_id > 0) {
            $logger->log_api_interaction('Session Manager', [
                'email' => $email,
                'customer_id' => $saved_customer_id,
                'source' => 'saved_data',
                'step' => 'customer_id_saved'
            ], 'info', 'Customer ID found in saved data: ' . $saved_customer_id);
            return $saved_customer_id;
        }

        // Method 4: Check if user_id is actually customer_id (for customers)
        $user_id = $login_result['UserId'] ?? $login_result['identifier'] ?? null;
        if ($user_id && $user_id > 0) {
            // Check if this user_id exists in our saved customer data
            $settings = \DIT\get_settings();
            $registered_users = $settings['registered_users'] ?? [];

            if (isset($registered_users[$user_id])) {
                $logger->log_api_interaction('Session Manager', [
                    'email' => $email,
                    'customer_id' => $user_id,
                    'source' => 'user_id_as_customer',
                    'step' => 'customer_id_user_id'
                ], 'info', 'User ID found in customer data, using as customer ID: ' . $user_id);
                return (int) $user_id;
            }

            // Method 5: Auto-add user to settings if role is customer and not found
            $role = $this->determine_user_role($login_result, $user_data);
            if ($role === 2) { // Customer role
                $logger->log_api_interaction('Session Manager', [
                    'email' => $email,
                    'user_id' => $user_id,
                    'step' => 'auto_add_customer'
                ], 'info', 'Auto-adding customer to settings: ' . $user_id);

                // Add user to settings
                $settings['registered_users'][$user_id] = [
                    'name' => $user_data['name'] ?? $user_data['first_name'] ?? 'Customer',
                    'customer_id' => $user_id,
                    'registration_date' => current_time('mysql'),
                    'last_updated' => current_time('mysql'),
                    'aes_key_stored_in_cookie' => true,
                    'first_name' => $user_data['first_name'] ?? '',
                    'last_name' => $user_data['last_name'] ?? '',
                    'company' => $user_data['company'] ?? '',
                    'email' => $email
                ];

                update_option('dit_settings', $settings);

                $logger->log_api_interaction('Session Manager', [
                    'email' => $email,
                    'customer_id' => $user_id,
                    'source' => 'auto_added_customer',
                    'step' => 'customer_id_auto_added'
                ], 'info', 'Customer auto-added to settings, using as customer ID: ' . $user_id);
                return (int) $user_id;
            }
        }

        $logger->log_api_interaction('Session Manager', [
            'email' => $email,
            'login_result_keys' => array_keys($login_result),
            'step' => 'customer_id_not_found'
        ], 'warning', 'Customer ID not found in any source');

        return null;
    }
}
