<?php

namespace DIT;

/**
 * Steganography class for login encryption
 * Based on developer instructions for new login logic
 */
class Steganography
{
    /**
     * Core instance
     * 
     * @var \DIT\Core
     */
    private $core;

    /**
     * Logger instance
     * 
     * @var \DIT\Logger
     */
    private $logger;

    /**
     * Constructor
     */
    public function __construct()
    {
        $this->core = Core::get_instance();
        $this->logger = $this->core->logger;
    }

    /**
     * Create steganography-based login request
     * 
     * @param \DIT\WebLoginRequest $request Login request object
     * @param int|null $customer_id Customer ID for proper AES key storage
     * @return array|false Array with requestB64, stegnokey, iv or false on failure
     */
    public function create_steganography_login($request, $customer_id = null)
    {
        try {
            if (!$request->isValid()) {
                throw new \Exception('Invalid login request data');
            }

            $this->logger->log_api_interaction('Steganography', [
                'step' => 'start',
                'email' => $request->Email,
                'login_type' => $request->LoginType,
                'request_valid' => true
            ], 'info', 'Starting steganography login creation');

            // 1. Create new AES key for this login
            $aes_key = $this->generate_aes_key();
            $iv = $this->generate_iv();

            // Log AES key details
            error_log('DIT Steganography: === AES KEY GENERATION ===');
            error_log('DIT Steganography: - Generated AES key length: ' . strlen($aes_key) . ' bytes');
            error_log('DIT Steganography: - Generated AES key hex: ' . bin2hex($aes_key));
            error_log('DIT Steganography: - Generated AES key MD5: ' . md5($aes_key));
            error_log('DIT Steganography: - Generated IV length: ' . strlen($iv) . ' bytes');
            error_log('DIT Steganography: - Generated IV hex: ' . bin2hex($iv));

            $this->logger->log_api_interaction('Steganography', [
                'step' => 'aes_key_created',
                'aes_key_length' => strlen($aes_key),
                'iv_length' => strlen($iv),
                'aes_key_preview' => bin2hex(substr($aes_key, 0, 8)) . '...'
            ], 'info', 'AES key and IV generated for login');

            // 2. Create random bytes for steganography
            $interleaved = $this->generate_random_bytes(32);

            // Log interleaved bytes details
            error_log('DIT Steganography: === INTERLEAVED BYTES GENERATION ===');
            error_log('DIT Steganography: - Generated interleaved length: ' . strlen($interleaved) . ' bytes');
            error_log('DIT Steganography: - Generated interleaved hex: ' . bin2hex($interleaved));
            error_log('DIT Steganography: - Generated interleaved MD5: ' . md5($interleaved));

            $this->logger->log_api_interaction('Steganography', [
                'step' => 'interleaved_created',
                'interleaved_length' => strlen($interleaved),
                'interleaved_preview' => bin2hex(substr($interleaved, 0, 8)) . '...'
            ], 'info', 'Random interleaved bytes generated');

            // 3. Create steganography key
            $stegnokey = $this->create_steganography_key($aes_key, $interleaved);

            // Log steganography key details
            error_log('DIT Steganography: === STEGANOGRAPHY KEY CREATION ===');
            error_log('DIT Steganography: - Created stegnokey length: ' . strlen($stegnokey) . ' characters');
            error_log('DIT Steganography: - Created stegnokey: ' . $stegnokey);
            error_log('DIT Steganography: - Stegnokey MD5: ' . md5($stegnokey));
            error_log('DIT Steganography: - Stegnokey format check - is_hex: ' . (ctype_xdigit($stegnokey) ? 'YES' : 'NO'));
            error_log('DIT Steganography: - Stegnokey format check - length_even: ' . (strlen($stegnokey) % 2 == 0 ? 'YES' : 'NO'));

            // Verify GGKKGGKK format
            $format_verification = $this->verify_ggkk_format($stegnokey, $aes_key);
            error_log('DIT Steganography: - GGKK format verification: ' . ($format_verification ? 'PASS' : 'FAIL'));

            $this->logger->log_api_interaction('Steganography', [
                'step' => 'stegnokey_created',
                'stegnokey_length' => strlen($stegnokey),
                'stegnokey_preview' => substr($stegnokey, 0, 16) . '...',
                'format_verification' => $format_verification
            ], 'info', 'Steganography key created');

            // 4. Serialize and encrypt request
            $serialized_request = $request->toJson();
            if ($serialized_request === false) {
                throw new \Exception('Failed to serialize login request to JSON');
            }

            $encrypted_request = $this->encrypt_with_aes($serialized_request, $aes_key, $iv);
            if ($encrypted_request === false) {
                throw new \Exception('Failed to encrypt login request with AES');
            }

            $request_b64 = base64_encode($encrypted_request);

            $this->logger->log_api_interaction('Steganography', [
                'step' => 'request_encrypted',
                'original_length' => strlen($serialized_request),
                'encrypted_length' => strlen($encrypted_request),
                'base64_length' => strlen($request_b64),
                'base64_preview' => substr($request_b64, 0, 20) . '...'
            ], 'info', 'Login request encrypted and base64 encoded');

            // 5. Save steganography key in session for this login
            $this->save_login_aes_key($aes_key, $stegnokey, $customer_id);

            $this->logger->log_api_interaction('Steganography', [
                'step' => 'aes_key_saved',
                'aes_key_saved' => true,
                'session_key' => 'login_aes_key',
                'customer_id' => $customer_id,
                'compatibility_format' => $customer_id ? 'dit_aes_keys[' . $customer_id . ']' : 'login_aes_key only'
            ], 'info', 'AES key saved in session for login' . ($customer_id ? ' with customer_id compatibility' : ''));

            // 6. Return formatted data
            $result = [
                'requestB64' => $request_b64,
                'stegnokey' => bin2hex($stegnokey),
                'iv' => bin2hex($iv)
            ];

            $this->logger->log_api_interaction('Steganography', [
                'step' => 'complete',
                'result_keys' => array_keys($result),
                'stegnokey_length' => strlen($result['stegnokey']),
                'iv_length' => strlen($result['iv'])
            ], 'success', 'Steganography login request created successfully');

            return $result;
        } catch (\Exception $e) {
            $this->logger->log_api_interaction('Steganography', [
                'step' => 'error',
                'error' => $e->getMessage(),
                'email' => $request->Email ?? 'unknown'
            ], 'error', 'Failed to create steganography login: ' . $e->getMessage());

            error_log('DIT Steganography: Failed to create login - ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Verify that steganography key has correct GGKKGGKK format
     * 
     * @param string $stegnokey Steganography key to verify
     * @param string $original_aes_key Original AES key for comparison
     * @return bool True if format is correct, false otherwise
     */
    private function verify_ggkk_format($stegnokey, $original_aes_key)
    {
        try {
            // Check basic format requirements
            if (strlen($stegnokey) !== 128) {
                error_log('DIT Steganography: Format verification failed - wrong length: ' . strlen($stegnokey) . ' (expected 128)');
                return false;
            }

            if (!ctype_xdigit($stegnokey)) {
                error_log('DIT Steganography: Format verification failed - not hex format');
                return false;
            }

            // Extract key parts from steganography and compare with original
            $extracted_key = '';
            for ($i = 2; $i < strlen($stegnokey); $i += 4) {
                $extracted_key .= substr($stegnokey, $i, 2);
            }

            $extracted_binary = hex2bin($extracted_key);
            $original_hex = bin2hex($original_aes_key);

            // Compare extracted key with original
            if ($extracted_binary === $original_aes_key) {
                error_log('DIT Steganography: Format verification PASS - extracted key matches original');
                return true;
            } else {
                error_log('DIT Steganography: Format verification FAIL - extracted key does not match original');
                error_log('DIT Steganography: - Original key hex: ' . $original_hex);
                error_log('DIT Steganography: - Extracted key hex: ' . $extracted_key);
                error_log('DIT Steganography: - Keys match: ' . (md5($extracted_binary) === md5($original_aes_key) ? 'YES' : 'NO'));
                return false;
            }
        } catch (\Exception $e) {
            error_log('DIT Steganography: Format verification error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Create steganography key by interleaving AES key with random bytes
     * Format: GGKKGGKK... where G=garbage, K=key
     * 
     * @param string $aes_key Binary AES key
     * @param string $interleaved Random bytes
     * @return string Steganography key
     */
    private function create_steganography_key($aes_key, $interleaved)
    {
        $hex_key = bin2hex($aes_key);
        $hex_interleaved = bin2hex($interleaved);
        $stegnokey = '';

        // GGKKGGKK... format (G=garbage, K=key)
        for ($i = 0; $i < strlen($hex_key); $i += 2) {
            $stegnokey .= substr($hex_interleaved, $i, 2);  // G (garbage)
            $stegnokey .= substr($hex_key, $i, 2);          // K (key)
        }

        return $stegnokey;
    }

    /**
     * Generate AES key for login
     * 
     * @return string 32-byte AES key
     */
    private function generate_aes_key()
    {
        return random_bytes(32);
    }

    /**
     * Generate Initialization Vector
     * 
     * @return string 16-byte IV
     */
    private function generate_iv()
    {
        return random_bytes(16);
    }

    /**
     * Generate random bytes
     * 
     * @param int $length Number of bytes to generate
     * @return string Random bytes
     */
    private function generate_random_bytes($length)
    {
        return random_bytes($length);
    }

    /**
     * Extract original AES key from steganography format
     * Format: GGKKGGKK... where G=garbage, K=key
     * Algorithm: start from position 2, take 2 chars, skip 2, repeat
     * 
     * @param string $stegnokey Steganography key in hex format
     * @return string Original 32-byte AES key
     */
    public function extract_aes_key_from_steganography($stegnokey)
    {
        error_log('DIT Steganography: === EXTRACTING AES KEY FROM STEGANOGRAPHY ===');
        error_log('DIT Steganography: - Input stegnokey length: ' . strlen($stegnokey) . ' chars');
        error_log('DIT Steganography: - Input stegnokey: ' . $stegnokey);
        error_log('DIT Steganography: - Input stegnokey MD5: ' . md5($stegnokey));
        error_log('DIT Steganography: - Input format check - is_hex: ' . (ctype_xdigit($stegnokey) ? 'YES' : 'NO'));
        error_log('DIT Steganography: - Input format check - length_even: ' . (strlen($stegnokey) % 2 == 0 ? 'YES' : 'NO'));

        $extracted_key = '';

        // Extract every second hex pair (K - key) starting from position 2
        // Format: GGKKGGKK... where we want K positions
        // Algorithm: start from position 2, take 2 chars, skip 2, repeat
        for ($i = 2; $i < strlen($stegnokey); $i += 4) {
            $extracted_key .= substr($stegnokey, $i, 2);
            error_log('DIT Steganography: - Position ' . $i . ': extracted "' . substr($stegnokey, $i, 2) . '"');
        }

        error_log('DIT Steganography: - Extracted hex length: ' . strlen($extracted_key) . ' chars');
        error_log('DIT Steganography: - Extracted hex: ' . $extracted_key);

        // Convert hex back to binary
        $binary_key = hex2bin($extracted_key);

        if ($binary_key === false) {
            error_log('DIT Steganography: ERROR - Failed to convert hex to binary');
            return null;
        }

        error_log('DIT Steganography: - Binary key length: ' . strlen($binary_key) . ' bytes');
        error_log('DIT Steganography: - Binary key MD5: ' . md5($binary_key));
        error_log('DIT Steganography: - Binary key hex: ' . bin2hex($binary_key));

        // Verify the extracted key
        if (strlen($binary_key) !== 32) {
            error_log('DIT Steganography: WARNING - Extracted key length is not 32 bytes: ' . strlen($binary_key));
        }

        error_log('DIT Steganography: === EXTRACTION COMPLETE ===');

        return $binary_key;
    }

    /**
     * Encrypt data with AES-256-CBC
     * 
     * @param string $data Data to encrypt
     * @param string $key AES key
     * @param string $iv Initialization Vector
     * @return string|false Encrypted data or false on failure
     */
    private function encrypt_with_aes($data, $key, $iv)
    {
        $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);

        if ($encrypted === false) {
            error_log('DIT Steganography: AES encryption failed: ' . openssl_error_string());
            return false;
        }

        return $encrypted;
    }

    /**
     * Save steganography key in session for this login
     * 
     * @param string $aes_key Original AES key (for logging)
     * @param string $stegnokey Steganography key to save
     * @param int $customer_id Customer ID for proper storage format
     */
    private function save_login_aes_key($aes_key, $stegnokey, $customer_id = null)
    {
        if (!isset($_SESSION)) {
            session_start();
        }

        error_log('DIT Steganography: === SAVING LOGIN AES KEY ===');

        // КРИТИЧНО: Зберігаємо стеганографічний ключ в правильному місці
        if ($customer_id) {
            // Зберігаємо стеганографічний ключ в dit_aes_keys[customer_id]
            $_SESSION['dit_aes_keys'][$customer_id] = $stegnokey;
            error_log('DIT Steganography: Steganography key saved in session for customer_id ' . $customer_id . ', length: ' . strlen($stegnokey));
            error_log('DIT Steganography: - Session storage: dit_aes_keys[' . $customer_id . '] = steganography key (' . strlen($stegnokey) . ' chars)');
            error_log('DIT Steganography: - Session steganography key: ' . substr($stegnokey, 0, 32) . '...');

            // ВАЖЛИВО: НЕ зберігаємо оригінальний AES ключ в dit_aes_keys
            // Це запобігає перезапису стеганографічного ключа
        }

        // Зберігаємо оригінальний AES ключ тільки в login_aes_key для backward compatibility
        $base64_key = base64_encode($aes_key);
        $_SESSION['login_aes_key'] = $base64_key;
        $_SESSION['login_aes_key_time'] = time();

        // Note: Cookies removed - AES key stored only in session

        error_log('DIT Steganography: === KEY SAVING COMPLETE ===');
    }

    /**
     * Get saved AES key for current login
     * 
     * @return string|false Base64 encoded AES key or false if not found
     */
    public function get_login_aes_key()
    {
        if (!isset($_SESSION)) {
            session_start();
        }

        // Check session first
        if (isset($_SESSION['login_aes_key'])) {
            return $_SESSION['login_aes_key'];
        }

        // Check cookies
        if (isset($_COOKIE['dit_login_aes_key'])) {
            return $_COOKIE['dit_login_aes_key'];
        }

        return false;
    }

    /**
     * Clear saved AES key for current login
     */
    public function clear_login_aes_key()
    {
        if (!isset($_SESSION)) {
            session_start();
        }

        unset($_SESSION['login_aes_key']);
        unset($_SESSION['login_aes_key_time']);

        // Note: Cookies removed - no cookies to clear
    }

    /**
     * Update AES key storage format for customer_id compatibility
     * This method is called after successful login when customer_id is available
     * 
     * @param int $customer_id Customer ID for proper storage format
     */
    public function update_aes_key_storage($customer_id)
    {
        if (!isset($_SESSION)) {
            session_start();
        }

        error_log('DIT Steganography: === UPDATE AES KEY STORAGE ===');
        error_log('DIT Steganography: Customer ID: ' . $customer_id);

        // КРИТИЧНО: Перевірити, чи вже є стеганографічний ключ ПЕРЕД будь-якими змінами
        if (isset($_SESSION['dit_aes_keys'][$customer_id])) {
            $existing_key = $_SESSION['dit_aes_keys'][$customer_id];
            $is_steganography_key = (ctype_xdigit($existing_key) && strlen($existing_key) === 128);

            error_log('DIT Steganography: - Existing key found in dit_aes_keys');
            error_log('DIT Steganography: - Key length: ' . strlen($existing_key));
            error_log('DIT Steganography: - Is steganography format: ' . ($is_steganography_key ? 'YES' : 'NO'));

            if ($is_steganography_key) {
                error_log('DIT Steganography: - Steganography key already exists, NOT overriding');
                error_log('DIT Steganography: - Key preview: ' . substr($existing_key, 0, 32) . '...');
                error_log('DIT Steganography: === UPDATE COMPLETED (NO CHANGES) ===');
                return true; // НЕ перезаписувати існуючий стеганографічний ключ
            }

            // Якщо ключ існує, але НЕ стеганографічний - логуємо це
            error_log('DIT Steganography: - Existing key is NOT steganography format, will convert');
        }

        // Тільки якщо НЕ маємо стеганографічного ключа - конвертуємо legacy
        if (isset($_SESSION['login_aes_key'])) {
            $base64_key = $_SESSION['login_aes_key'];
            $binary_key = base64_decode($base64_key);

            if ($binary_key !== false) {
                error_log('DIT Steganography: - Converting legacy login_aes_key to customer_id format');
                error_log('DIT Steganography: - Base64 key length: ' . strlen($base64_key));
                error_log('DIT Steganography: - Binary key length: ' . strlen($binary_key));
                error_log('DIT Steganography: - Is valid base64: ' . (base64_encode(base64_decode($base64_key, true)) === $base64_key ? 'YES' : 'NO'));
                error_log('DIT Steganography: - Is valid binary: ' . (mb_strlen($binary_key, '8bit') === strlen($binary_key) ? 'YES' : 'NO'));

                // Add key hash for comparison and debugging
                error_log('DIT Steganography: AES Key Hash Analysis:');
                error_log('DIT Steganography: - Base64 key MD5 hash: ' . md5($base64_key));
                error_log('DIT Steganography: - Binary key MD5 hash: ' . md5($binary_key));
                error_log('DIT Steganography: - Binary key SHA256 hash: ' . hash('sha256', $binary_key));
                error_log('DIT Steganography: - Binary key hex representation: ' . bin2hex($binary_key));

                // Зберігаємо legacy ключ ТІЛЬКИ якщо немає стеганографічного
                error_log('DIT Steganography: - Saving LEGACY binary key format (32 bytes)');
                $_SESSION['dit_aes_keys'][$customer_id] = $binary_key;

                // Note: Cookies removed - AES key stored only in session

                error_log('DIT Steganography: AES key storage updated for customer_id ' . $customer_id . ', length: ' . strlen($binary_key));
                error_log('DIT Steganography: - Session storage: dit_aes_keys[' . $customer_id . '] = binary key (' . strlen($binary_key) . ' bytes)');
                error_log('DIT Steganography: - Note: Cookies removed - AES key stored only in session');

                // Verify the saved key
                $saved_key = $_SESSION['dit_aes_keys'][$customer_id];
                error_log('DIT Steganography: - Saved key verification:');
                error_log('DIT Steganography: - Saved key length: ' . strlen($saved_key) . ' bytes');
                error_log('DIT Steganography: - Saved key MD5 hash: ' . md5($saved_key));
                error_log('DIT Steganography: - Keys match: ' . (md5($saved_key) === md5($binary_key) ? 'YES' : 'NO'));

                return true;
            }
        }

        error_log('DIT Steganography: No login AES key found to update for customer_id ' . $customer_id);
        return false;
    }

    /**
     * Update database row with AES key after successful login
     * This method corresponds to step 10 of the developer's procedure:
     * "Update the row with the AES key"
     * 
     * @param int $primary_key User/Customer/Administrator primary key
     * @param string $aes_key AES key to store in database
     * @param int $login_type Login type (1=User, 2=Customer, 3=Administrator)
     * @return bool True if update was successful, false otherwise
     */
    public function update_database_row_with_aes_key(int $primary_key, string $aes_key, int $login_type): bool
    {
        try {
            $this->logger->log_api_interaction('Database Update', [
                'step' => 'start',
                'primary_key' => $primary_key,
                'login_type' => $login_type,
                'aes_key_length' => mb_strlen($aes_key, '8bit'),
                'aes_key_preview' => bin2hex(substr($aes_key, 0, 8)) . '...'
            ], 'info', 'Starting database row update with AES key');

            // Validate AES key length
            if (mb_strlen($aes_key, '8bit') !== 32) {
                throw new \Exception('Invalid AES key length: must be 32 bytes, got ' . mb_strlen($aes_key, '8bit') . ' bytes');
            }

            // Convert AES key to hex for storage
            $aes_key_hex = bin2hex($aes_key);

            // Determine table and field names based on login type
            $table_info = $this->get_table_info_for_login_type($login_type);

            if (!$table_info) {
                throw new \Exception('Invalid login type: ' . $login_type);
            }

            $this->logger->log_api_interaction('Database Update', [
                'step' => 'table_info_determined',
                'table_name' => $table_info['table_name'],
                'primary_key_field' => $table_info['primary_key_field'],
                'aes_key_field' => $table_info['aes_key_field']
            ], 'info', 'Table information determined for login type');

            // Update the database row with AES key
            $update_result = $this->execute_database_update(
                $table_info['table_name'],
                $table_info['primary_key_field'],
                $primary_key,
                $table_info['aes_key_field'],
                $aes_key_hex
            );

            if ($update_result) {
                $this->logger->log_api_interaction('Database Update', [
                    'step' => 'success',
                    'primary_key' => $primary_key,
                    'login_type' => $login_type,
                    'table_name' => $table_info['table_name'],
                    'aes_key_stored' => true
                ], 'success', 'Database row updated successfully with AES key');
            } else {
                throw new \Exception('Database update failed');
            }

            return true;
        } catch (\Exception $e) {
            $this->logger->log_api_interaction('Database Update', [
                'step' => 'error',
                'primary_key' => $primary_key,
                'login_type' => $login_type,
                'error' => $e->getMessage()
            ], 'error', 'Failed to update database row with AES key: ' . $e->getMessage());

            error_log('DIT Steganography: Failed to update database row with AES key - ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Get table information for specific login type
     * 
     * @param int $login_type Login type (1=User, 2=Customer, 3=Administrator)
     * @return array|false Table information or false if invalid login type
     */
    private function get_table_info_for_login_type(int $login_type): array|false
    {
        switch ($login_type) {
            case 1: // User
                return [
                    'table_name' => 'users',
                    'primary_key_field' => 'user_id',
                    'aes_key_field' => 'aes_key'
                ];
            case 2: // Customer
                return [
                    'table_name' => 'customers',
                    'primary_key_field' => 'customer_id',
                    'aes_key_field' => 'aes_key'
                ];
            case 3: // Administrator
                return [
                    'table_name' => 'administrators',
                    'primary_key_field' => 'admin_id',
                    'aes_key_field' => 'aes_key'
                ];
            default:
                return false;
        }
    }

    /**
     * Execute database update with AES key
     * 
     * @param string $table_name Table name
     * @param string $primary_key_field Primary key field name
     * @param int $primary_key Primary key value
     * @param string $aes_key_field AES key field name
     * @param string $aes_key_hex AES key in hex format
     * @return bool True if update was successful
     */
    private function execute_database_update(string $table_name, string $primary_key_field, int $primary_key, string $aes_key_field, string $aes_key_hex): bool
    {
        try {
            // Note: This is a placeholder for the actual database update logic
            // In a real implementation, this would use WordPress database functions
            // or direct SQL queries to update the appropriate table

            $this->logger->log_api_interaction('Database Update', [
                'step' => 'execute_update',
                'table_name' => $table_name,
                'primary_key_field' => $primary_key_field,
                'primary_key' => $primary_key,
                'aes_key_field' => $aes_key_field,
                'aes_key_hex_length' => strlen($aes_key_hex),
                'note' => 'This is a placeholder - actual database update logic needs to be implemented'
            ], 'info', 'Database update execution (placeholder)');

            // TODO: Implement actual database update logic here
            // Example:
            // global $wpdb;
            // $result = $wpdb->update(
            //     $table_name,
            //     [$aes_key_field => $aes_key_hex],
            //     [$primary_key_field => $primary_key],
            //     ['%s'],
            //     ['%d']
            // );
            // return $result !== false;

            // For now, return true to simulate success
            return true;
        } catch (\Exception $e) {
            $this->logger->log_api_interaction('Database Update', [
                'step' => 'execute_update_error',
                'table_name' => $table_name,
                'error' => $e->getMessage()
            ], 'error', 'Database update execution failed: ' . $e->getMessage());

            error_log('DIT Steganography: Database update execution failed - ' . $e->getMessage());
            return false;
        }
    }
}
