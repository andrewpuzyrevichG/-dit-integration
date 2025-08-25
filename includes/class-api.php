<?php

/**
 * DIT API Integration Class
 *
 * @package DIT_Integration
 * @since 1.0.0
 */

namespace DIT;

use Exception;

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class API
 * Handles all API interactions with the Data Integrity Tool backend
 */
class API
{
    /**
     * Singleton instance
     *
     * @var API|null
     */
    private static $instance = null;

    /**
     * API base URL
     *
     * @var string
     */
    private $api_base_url;

    /**
     * Cached RSA key
     *
     * @var string|null
     */
    private $cached_rsa_key = null;

    /**
     * RSA key cache expiration time (24 hours)
     *
     * @var int
     */
    private $rsa_key_cache_time = 86400; // 24 hours

    /**
     * RSA key cache timestamp
     *
     * @var int
     */
    private $rsa_key_cache_timestamp = 0;

    /**
     * Transient key for RSA cache
     *
     * @var string
     */
    private $rsa_transient_key = 'dit_rsa_key_cache';

    /**
     * Constructor
     */
    private function __construct()
    {
        // Try to get API URL from settings first, fallback to hardcoded
        $settings = get_option('dit_settings', []);
        $this->api_base_url = $settings['dit_api_url'] ?? 'https://api.dataintegritytool.org:5001';

        $this->load_rsa_key_from_transient();
    }

    /**
     * Get singleton instance
     *
     * @return API
     */
    public static function get_instance(): API
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Load RSA key from WordPress transient
     */
    private function load_rsa_key_from_transient(): void
    {
        $cached_data = get_transient($this->rsa_transient_key);
        if ($cached_data && is_array($cached_data)) {
            $this->cached_rsa_key = $cached_data['key'] ?? null;
            $this->rsa_key_cache_timestamp = $cached_data['timestamp'] ?? 0;
        }
    }

    /**
     * Save RSA key to WordPress transient
     */
    private function save_rsa_key_to_transient(string $key): void
    {
        $cache_data = [
            'key' => $key,
            'timestamp' => time()
        ];
        set_transient($this->rsa_transient_key, $cache_data, $this->rsa_key_cache_time);
    }

    /**
     * Initialize the API
     */
    public function init()
    {
        // Add any initialization logic here
        // For example, we could verify the API connection
        // Note: RSA key will be fetched when needed, not during initialization
    }

    /**
     * Update API base URL from settings
     */
    public function update_api_url(): void
    {
        $settings = get_option('dit_settings', []);
        $new_url = $settings['dit_api_url'] ?? null;

        if ($new_url && $new_url !== $this->api_base_url) {
            $this->api_base_url = $new_url;

            $core = Core::get_instance();
            $logger = $core->logger;

            $logger->log_api_interaction('API URL Update', [
                'old_url' => $this->api_base_url,
                'new_url' => $new_url,
                'step' => 'url_updated'
            ], 'info', 'API base URL updated from settings');
        }
    }

    /**
     * Test API endpoint availability
     *
     * @param string $endpoint Endpoint to test (e.g., '/Customers/GetCustomer')
     * @return array Test results
     */
    public function test_endpoint(string $endpoint): array
    {
        $core = Core::get_instance();
        $logger = $core->logger;

        $test_url = $this->api_base_url . $endpoint;

        $logger->log_api_interaction('Endpoint Test', [
            'endpoint' => $endpoint,
            'test_url' => $test_url,
            'step' => 'test_start'
        ], 'info', 'Testing endpoint availability: ' . $endpoint);

        try {
            $response = wp_remote_get($test_url, [
                'timeout' => 10,
                'sslverify' => true,
                'headers' => [
                    'Accept' => '*/*',
                    'User-Agent' => 'WordPress/' . get_bloginfo('version') . '; ' . get_bloginfo('url')
                ]
            ]);

            if (is_wp_error($response)) {
                return [
                    'success' => false,
                    'error' => $response->get_error_message(),
                    'endpoint' => $endpoint,
                    'url' => $test_url
                ];
            }

            $response_code = wp_remote_retrieve_response_code($response);
            $body = wp_remote_retrieve_body($response);

            $result = [
                'success' => $response_code === 200,
                'response_code' => $response_code,
                'response_body' => $body,
                'endpoint' => $endpoint,
                'url' => $test_url
            ];

            $logger->log_api_interaction('Endpoint Test', [
                'endpoint' => $endpoint,
                'test_url' => $test_url,
                'result' => $result,
                'step' => 'test_completed'
            ], $result['success'] ? 'success' : 'error', 'Endpoint test completed: ' . $endpoint);

            return $result;
        } catch (Exception $e) {
            $logger->log_api_interaction('Endpoint Test', [
                'endpoint' => $endpoint,
                'test_url' => $test_url,
                'error' => $e->getMessage(),
                'step' => 'test_exception'
            ], 'error', 'Endpoint test failed with exception: ' . $endpoint);

            return [
                'success' => false,
                'error' => $e->getMessage(),
                'endpoint' => $endpoint,
                'url' => $test_url
            ];
        }
    }

    /**
     * Get server RSA public key
     *
     * @return string|null Base64 encoded RSA public key or null on failure
     */
    public function get_server_rsa_key(): ?string
    {
        // Check if we have a cached key that's still valid
        if (
            $this->cached_rsa_key !== null &&
            (time() - $this->rsa_key_cache_timestamp) < $this->rsa_key_cache_time
        ) {
            $core = Core::get_instance();
            $logger = $core->logger;

            $logger->log_api_interaction(
                'Get RSA Key',
                [
                    'key_length' => mb_strlen($this->cached_rsa_key, '8bit'),
                    'cached' => true,
                    'source' => 'memory_cache',
                    'cache_age' => time() - $this->rsa_key_cache_timestamp
                ],
                'success',
                'RSA key retrieved from memory cache'
            );

            return $this->cached_rsa_key;
        }

        $core = Core::get_instance();
        $logger = $core->logger;

        try {
            $response = wp_remote_get(
                $this->api_base_url . '/Cryptography/GetServerRSAPublicKey',
                [
                    'timeout' => 30,
                    'sslverify' => true
                ]
            );

            if (is_wp_error($response)) {
                throw new Exception('Failed to get RSA key: ' . $response->get_error_message());
            }

            $response_code = wp_remote_retrieve_response_code($response);
            $body = wp_remote_retrieve_body($response);

            if ($response_code !== 200) {
                throw new Exception('Failed to get RSA key: HTTP ' . $response_code);
            }

            // Cache the key in memory and transient
            $this->cached_rsa_key = $body;
            $this->rsa_key_cache_timestamp = time();
            $this->save_rsa_key_to_transient($body);

            $logger->log_api_interaction(
                'Get RSA Key',
                [
                    'response_code' => $response_code,
                    'key_length' => mb_strlen($body, '8bit'),
                    'cached' => true,
                    'source' => 'server_fresh',
                    'cache_duration' => $this->rsa_key_cache_time
                ],
                'success',
                'Successfully retrieved and cached RSA key from server'
            );

            return $body;
        } catch (Exception $e) {
            $logger->log_api_interaction(
                'Get RSA Key',
                ['error' => $e->getMessage()],
                'error',
                'Failed to get RSA key'
            );

            return null;
        }
    }

    /**
     * Register a new customer (main method)
     *
     * @param array $user_data User data to register
     * @return int|null Customer ID or null on failure
     */
    public function register_customer(array $user_data): ?int
    {
        return $this->register_customer_rsa($user_data);
    }

    /**
     * Register a new customer with RSA encryption
     *
     * @param array $user_data User data to register
     * @param string $encryption_method Ignored, kept for compatibility
     * @return int|null Customer ID or null on failure
     */
    public function register_customer_with_method(array $user_data, string $encryption_method = 'rsa'): ?int
    {
        $core = Core::get_instance();
        $logger = $core->logger;
        $encryption = $core->encryption;

        $logger->log_api_interaction('Register Customer', [
            'encryption_method' => 'rsa',
            'user_data_keys' => array_keys($user_data)
        ], 'info', 'Starting registration process with RSA encryption.');

        try {
            // 1. Create a temporary AES key: 256 bits, CBC Mode, PKCS7 padding
            $aes_data = $encryption->generate_aes_key();
            if (!is_array($aes_data) || !isset($aes_data['key'])) {
                throw new Exception('Failed to generate AES key: invalid format returned');
            }
            $aes_key = base64_encode($aes_data['key']); // 256-bit key, Base64 encoded
            $iv = base64_encode($aes_data['iv']); // 128-bit IV, Base64 encoded

            $logger->log_api_interaction('Register Customer', [
                'aes_key_generated' => true,
                'iv_generated' => true
            ], 'info', 'Generated temporary AES key and IV.');

            // 2. Call the server API GetServerRSAKey (URL)
            $rsa_key = $this->get_server_rsa_key();
            if (!$rsa_key) {
                throw new Exception('Failed to get server RSA public key for registration.');
            }

            // 3. Base64-decode this key to binary (done in encryption class)

            // 4. Create the RegisterCustomer request + JSON-serialize the request, including the temporary AES key
            $payload = [
                'AesKey' => $aes_key, // AES key, Base64
                'Name' => $user_data['name'] ?? '',
                'Description' => $user_data['description'] ?? '',
                'Email' => $user_data['email'] ?? '',
                'Password' => isset($user_data['password']) ? hash('sha256', $user_data['password']) : '',
                'Tools' => $user_data['tools'] ?? [],
                'Notes' => $user_data['notes'] ?? '',
                'NameFirst' => $user_data['first_name'] ?? '',
                'NameLast' => $user_data['last_name'] ?? '',
                'Company' => $user_data['company'] ?? '',
                'InitialUser' => true, // Create initial user with same credentials
                'MaxSeats' => 10 // Maximum number of seats for this customer
            ];

            $json_payload = json_encode($payload);
            if ($json_payload === false) {
                throw new Exception('Failed to encode registration payload to JSON: ' . json_last_error_msg());
            }

            // 5. Use the server RSA key to encrypt the serialized request
            $encrypted_payload = $encryption->encrypt_data_with_rsa($json_payload, $rsa_key);
            if (empty($encrypted_payload)) {
                throw new Exception('Failed to encrypt the registration JSON payload with RSA.');
            }

            // 6. Base64 encode the encrypted request
            $encoded_payload = $encrypted_payload; // Already base64 encoded

            $request_url = $this->api_base_url . '/Customers/RegisterCustomer';

            $logger->log_api_interaction('Register Customer', [
                'request_url' => $request_url,
                'method' => 'PUT',
                'json_payload' => $json_payload,
                'encrypted_payload' => $encrypted_payload,
                'payload_length' => strlen($encrypted_payload),
                'aes_key_included' => true,
                'iv_included' => true
            ], 'info', 'Sending registration request with RSA encrypted payload including AES key and IV.');

            // 7. Call RegisterCustomer with the encrypted payload
            $response = wp_remote_request($request_url, [
                'method' => 'PUT',
                'headers' => [
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/json'
                ],
                'body' => $encrypted_payload,
                'timeout' => 30
            ]);

            if (is_wp_error($response)) {
                throw new Exception('Registration request failed: ' . $response->get_error_message());
            }

            $response_code = wp_remote_retrieve_response_code($response);
            $response_body = wp_remote_retrieve_body($response);

            $logger->log_api_interaction('Register Customer', [
                'response_code' => $response_code,
                'response_body' => $response_body,
                'request_url_sent' => $request_url,
                'request_method_sent' => 'PUT',
                'encrypted_sent' => $encoded_payload
            ], $response_code === 200 ? 'success' : 'error', 'Registration response received.');

            if ($response_code !== 200) {
                throw new Exception('Registration failed: HTTP ' . $response_code . ' - ' . $response_body);
            }

            // 8. The response will be encrypted to the temporary AES key; decrypt it
            $response_data = json_decode($response_body, true);
            if (!$response_data) {
                throw new Exception('Invalid response format: not JSON');
            }

            // Check if response is encrypted
            if (isset($response_data['encryptedResponse'])) {
                // Decrypt the response using our temporary AES key
                $decrypted_response = $encryption->decrypt_with_aes(
                    $response_data['encryptedResponse'],
                    base64_decode($aes_key),
                    $iv
                );

                $response_data = json_decode($decrypted_response, true);
                if (!$response_data) {
                    throw new Exception('Failed to decode decrypted response');
                }
            }

            if (!isset($response_data['customerId'])) {
                throw new Exception('Invalid response format: missing customerId');
            }

            $customer_id = (int) $response_data['customerId'];
            $user_name = $user_data['name'] ?? '';
            $permanent_aes_key = $response_data['permanentAesKey'] ?? $response_data['aesKey'] ?? '';

            // Store additional user data if available in response
            $additional_user_data = [
                'first_name' => $response_data['firstName'] ?? $user_data['first_name'] ?? '',
                'last_name' => $response_data['lastName'] ?? $user_data['last_name'] ?? '',
                'company' => $response_data['company'] ?? $user_data['company'] ?? '',
                'email' => $response_data['email'] ?? $user_data['email'] ?? ''
            ];

            // Cache the username, CustomerId, and the returned AES key
            \DIT\save_user_data($user_name, $customer_id, $permanent_aes_key, $additional_user_data);

            // Note: Initial user is created automatically by API when InitialUser=true
            $logger->log_api_interaction('Register Customer', [
                'customer_id' => $customer_id,
                'initial_user_created' => true,
                'encryption_method' => 'rsa',
                'response_decrypted' => true,
                'user_first_name' => $additional_user_data['first_name'],
                'user_last_name' => $additional_user_data['last_name'],
                'user_company' => $additional_user_data['company'],
                'user_email' => $additional_user_data['email'],
                'max_seats' => 10
            ], 'success', 'Customer registered successfully with automatic initial user creation.');

            return $customer_id;
        } catch (Exception $e) {
            $logger->log_api_interaction('Register Customer', [
                'error' => $e->getMessage(),
                'encryption_method' => 'rsa'
            ], 'error', 'Registration failed with RSA encryption.');
            error_log('DIT Integration: Registration failed - ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Test different encryption methods for registration
     *
     * @param array $user_data User data to test with
     * @return array Test results
     */
    public function test_encryption_methods(array $user_data): array
    {
        $results = [];
        $methods = ['rsa', 'aes', 'hybrid'];

        foreach ($methods as $method) {
            $start_time = microtime(true);
            $customer_id = $this->register_customer_with_method($user_data, $method);
            $end_time = microtime(true);

            $results[$method] = [
                'success' => $customer_id !== null,
                'customer_id' => $customer_id,
                'execution_time' => round(($end_time - $start_time) * 1000, 2), // milliseconds
                'error' => $customer_id === null ? 'Registration failed' : null
            ];
        }

        return $results;
    }

    /**
     * Login user (updated according to API documentation)
     *
     * @param string $email User email
     * @param string $password Plain password (will be hashed as SHA256)
     * @return array|null Login response or null on failure
     */
    public function login(string $email, string $password, int $role = null): ?array
    {
        $core = Core::get_instance();
        $logger = $core->logger;

        $sha256_password = hash('sha256', $password);
        $url_params = [
            'email' => urlencode($email),
            'PasswordHash' => urlencode($sha256_password)
        ];

        // Add role parameter if provided
        if ($role !== null) {
            $url_params['role'] = $role;
        }

        $url = add_query_arg($url_params, $this->api_base_url . '/Session/Login');

        $logger->log_api_interaction('Login', [
            'email' => $email,
            'role' => $role,
            'password_length' => strlen($password),
            'sha256_password_length' => strlen($sha256_password),
            'sha256_password_preview' => substr($sha256_password, 0, 10) . '...',
            'url' => $url,
            'url_params' => $url_params,
            'step' => 'request_start'
        ], 'info', 'Starting login request');

        $response = wp_remote_get($url, [
            'timeout' => 30,
            'sslverify' => true
        ]);

        if (is_wp_error($response)) {
            $logger->log_api_interaction('Login', [
                'email' => $email,
                'error' => $response->get_error_message(),
                'step' => 'wp_error'
            ], 'error', 'Login failed with WordPress error');
            return null;
        }

        $response_code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        $headers = wp_remote_retrieve_headers($response);

        $logger->log_api_interaction('Login', [
            'email' => $email,
            'response_code' => $response_code,
            'response_body' => $body,
            'response_headers' => $headers,
            'body_length' => strlen($body),
            'step' => 'response_received'
        ], $response_code === 200 ? 'info' : 'error', 'Login response received');

        if ($response_code !== 200) {
            $logger->log_api_interaction('Login', [
                'email' => $email,
                'response_code' => $response_code,
                'response_body' => $body,
                'step' => 'http_error'
            ], 'error', 'Login failed with HTTP ' . $response_code);
            return null;
        }

        // Try to decode JSON response
        $data = json_decode($body, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            $logger->log_api_interaction('Login', [
                'email' => $email,
                'response_body' => $body,
                'json_error' => json_last_error_msg(),
                'step' => 'json_decode_error'
            ], 'error', 'Invalid JSON response from Login API');
            return null;
        }

        // Normalize the response to use 'UserId' field for consistency
        if (isset($data['identifier']) && !isset($data['UserId'])) {
            $data['UserId'] = $data['identifier'];
        }

        $logger->log_api_interaction('Login', [
            'email' => $email,
            'decoded_data' => $data,
            'data_type' => gettype($data),
            'is_array' => is_array($data),
            'user_id' => $data['UserId'] ?? null,
            'identifier' => $data['identifier'] ?? null,
            'cust_or_user_id' => $data['custOrUserID'] ?? null,
            'error_code' => $data['errorcode'] ?? null,
            'has_error_code' => isset($data['errorcode']),
            'step' => 'json_decoded'
        ], 'success', 'Login JSON decoded successfully');

        return $data;
    }

    /**
     * Login with WebLogin API using steganographic encryption
     * This method implements the developer's procedure exactly:
     * 1. Creating an AES key and IV + Generating 32 bytes of interleaving data
     * 2. Hex-encoding the IV, the key, and the throwaway data
     * 3. Interleaving the throwaway data with the key
     * 4. Populating the PHP equivalent of a WebLoginRequest
     * 5. Serializing, encrypting with the new key and IV, and base64 encoding the request
     * 6. Calling the WebLogin API with the encrypted request, interleaved hex string, and hex-encoded IV
     * 
     * @param string $email User email
     * @param string $password Plain text password (not hash)
     * @param int $roleId User role ID (1=User, 2=Customer, 3=Administrator)
     * @return array|null Login response or null on failure
     */
    public function login_with_steganography(string $email, string $password, int $roleId): ?array
    {
        $core = Core::get_instance();
        $logger = $core->logger;

        try {
            $logger->log_api_interaction('WebLogin API Login', [
                'step' => 'start',
                'email' => $email,
                'role_id' => $roleId,
                'password_length' => strlen($password),
                'note' => 'Using plain text password as per developer procedure'
            ], 'info', 'Starting WebLogin API login with steganographic encryption');

            // Step 1-5: Create WebLogin request according to developer's procedure
            $weblogin_data = $this->create_weblogin_request($email, $password, $roleId);

            $logger->log_api_interaction('WebLogin API Login', [
                'step' => 'weblogin_request_created',
                'requestB64_length' => strlen($weblogin_data['requestB64']),
                'keyInterleaved_length' => strlen($weblogin_data['keyInterleaved']),
                'hexIV_length' => strlen($weblogin_data['hexIV']),
                'note' => 'WebLogin request created successfully (steps 1-5 completed)'
            ], 'info', 'WebLogin request created according to developer procedure');

            // Step 6: Call the WebLogin API with the encrypted request, interleaved hex string, and hex-encoded IV
            $api_response = $this->call_weblogin_api(
                $weblogin_data['requestB64'],
                $weblogin_data['keyInterleaved'],
                $weblogin_data['hexIV']
            );

            if (!$api_response) {
                throw new Exception('WebLogin API call failed');
            }

            $logger->log_api_interaction('WebLogin API Login', [
                'step' => 'weblogin_api_response',
                'api_response' => $api_response,
                'identifier' => $api_response['identifier'] ?? null,
                'loginType' => $api_response['loginType'] ?? null,
                'errorcode' => $api_response['errorcode'] ?? null,
                'note' => 'WebLogin API response received (step 6 completed)'
            ], 'info', 'WebLogin API response received successfully');

            // Check for errors in response
            if (isset($api_response['errorcode']) && $api_response['errorcode'] !== 0) {
                throw new Exception('WebLogin API returned error code: ' . $api_response['errorcode']);
            }

            // Extract user identifier
            $identifier = $api_response['identifier'] ?? null;
            if (!$identifier) {
                throw new Exception('No user identifier returned from WebLogin API');
            }

            // Normalize the response to use 'UserId' field for consistency
            $api_response['UserId'] = $identifier;

            // ВИПРАВЛЕННЯ: Зберігаємо оригінальний AES ключ в сесії після успішного логіну
            $this->save_original_aes_key_to_session($weblogin_data['aes_key'], $weblogin_data['iv'], $identifier);

            $logger->log_api_interaction('WebLogin API Login', [
                'step' => 'success',
                'identifier' => $identifier,
                'login_type' => $api_response['loginType'] ?? $roleId,
                'errorcode' => $api_response['errorcode'] ?? 0,
                'note' => 'WebLogin API login successful - all developer procedure steps completed'
            ], 'success', 'WebLogin API login completed successfully');

            return $api_response;
        } catch (Exception $e) {
            $logger->log_api_interaction('WebLogin API Login', [
                'step' => 'error',
                'email' => $email,
                'role_id' => $roleId,
                'error' => $e->getMessage(),
                'note' => 'WebLogin API login failed'
            ], 'error', 'WebLogin API login failed: ' . $e->getMessage());

            error_log('DIT API: WebLogin API login failed - ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Save original AES key to session after successful login
     * This fixes the issue where steganography key was saved instead of original AES key
     * 
     * @param string $aes_key Original AES key (32 bytes)
     * @param string $iv Original IV (16 bytes)
     * @param int $user_id User ID from WebLogin API response
     */
    private function save_original_aes_key_to_session(string $aes_key, string $iv, int $user_id): void
    {
        if (!isset($_SESSION)) {
            session_start();
        }

        error_log('DIT API: === SAVING ORIGINAL AES KEY TO SESSION ===');
        error_log('DIT API: User ID: ' . $user_id);
        error_log('DIT API: AES key length: ' . strlen($aes_key) . ' bytes');
        error_log('DIT API: IV length: ' . strlen($iv) . ' bytes');

        // Initialize session arrays if needed
        if (!isset($_SESSION['dit_aes_keys'])) {
            $_SESSION['dit_aes_keys'] = [];
        }
        if (!isset($_SESSION['dit_aes_ivs'])) {
            $_SESSION['dit_aes_ivs'] = [];
        }

        // Зберігаємо оригінальний AES ключ (НЕ стеганографічний)
        $_SESSION['dit_aes_keys'][$user_id] = $aes_key;
        $_SESSION['dit_aes_ivs'][$user_id] = $iv;

        // Also save in login_aes_key for backward compatibility
        $_SESSION['login_aes_key'] = base64_encode($aes_key);
        $_SESSION['login_aes_key_time'] = time();

        // Save in cookies for persistence
        // Note: Cookies removed - AES key and IV stored only in session

        error_log('DIT API: Original AES key saved successfully (session only, no cookies):');
        error_log('DIT API: - Session: dit_aes_keys[' . $user_id . '] = ' . strlen($aes_key) . ' bytes');
        error_log('DIT API: - Session: dit_aes_ivs[' . $user_id . '] = ' . strlen($iv) . ' bytes');
        error_log('DIT API: - Session: login_aes_key = base64 encoded');
        error_log('DIT API: - Note: Cookies removed - AES key stored only in session');
        error_log('DIT API: === ORIGINAL AES KEY SAVED ===');
    }

    /**
     * Check if email exists in the system
     *
     * @param string $email Email to check
     * @return array|null Response data or null on failure
     */
    public function check_email(string $email): ?array
    {
        $core = Core::get_instance();
        $logger = $core->logger;

        $url = add_query_arg([
            'email' => urlencode($email)
        ], $this->api_base_url . '/Customers/CheckEmail');

        $logger->log_api_interaction('Check Email', [
            'email' => $email,
            'url' => $url,
            'step' => 'request_start'
        ], 'info', 'Starting email check request');

        $response = wp_remote_get($url, [
            'timeout' => 30,
            'sslverify' => true
        ]);

        if (is_wp_error($response)) {
            $logger->log_api_interaction('Check Email', [
                'email' => $email,
                'error' => $response->get_error_message(),
                'step' => 'wp_error'
            ], 'error', 'Email check failed with WordPress error');
            return null;
        }

        $response_code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        $headers = wp_remote_retrieve_headers($response);

        $logger->log_api_interaction('Check Email', [
            'email' => $email,
            'response_code' => $response_code,
            'response_body' => $body,
            'response_headers' => $headers,
            'body_length' => strlen($body),
            'step' => 'response_received'
        ], $response_code === 200 ? 'info' : 'error', 'Email check response received');

        if ($response_code !== 200) {
            $logger->log_api_interaction('Check Email', [
                'email' => $email,
                'response_code' => $response_code,
                'response_body' => $body,
                'step' => 'http_error'
            ], 'error', 'Email check failed with HTTP ' . $response_code);
            return null;
        }

        // Try to decode JSON response
        $data = json_decode($body, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            $logger->log_api_interaction('Check Email', [
                'email' => $email,
                'response_body' => $body,
                'json_error' => json_last_error_msg(),
                'step' => 'json_decode_error'
            ], 'error', 'Invalid JSON response from CheckEmail API');
            return null;
        }

        // Ensure data is an array
        if (!is_array($data)) {
            // Handle integer responses (Customer ID or status codes)
            if (is_int($data)) {
                if ($data > 0) {
                    // Positive integer = Customer ID (email exists)
                    $logger->log_api_interaction('Check Email', [
                        'email' => $email,
                        'customer_id' => $data,
                        'step' => 'customer_id_found'
                    ], 'success', 'Email exists with Customer ID: ' . $data);

                    return [
                        'CustomerId' => $data,
                        'Exists' => true,
                        'Email' => $email
                    ];
                } elseif ($data === 0) {
                    // Zero = Email not found
                    $logger->log_api_interaction('Check Email', [
                        'email' => $email,
                        'step' => 'email_not_found'
                    ], 'info', 'Email not found in system');

                    return [
                        'Exists' => false,
                        'Email' => $email
                    ];
                } else {
                    // Negative integer = Error code
                    $logger->log_api_interaction('Check Email', [
                        'email' => $email,
                        'error_code' => $data,
                        'step' => 'api_error'
                    ], 'error', 'API returned error code: ' . $data);

                    return null;
                }
            }

            // Handle other non-array responses (string, bool, etc.)
            $logger->log_api_interaction('Check Email', [
                'email' => $email,
                'response_body' => $body,
                'decoded_data' => $data,
                'data_type' => gettype($data),
                'data_value' => var_export($data, true),
                'step' => 'type_error'
            ], 'error', 'CheckEmail API returned unsupported data type: ' . gettype($data) . ' - Value: ' . var_export($data, true));
            return null;
        }

        $logger->log_api_interaction('Check Email', [
            'email' => $email,
            'decoded_data' => $data,
            'data_type' => gettype($data),
            'is_array' => is_array($data),
            'is_object' => is_object($data),
            'step' => 'json_decoded'
        ], 'success', 'Email check JSON decoded successfully');

        return $data;
    }

    /**
     * Allocate licenses for a customer
     *
     * @param int $customer_id Customer ID
     * @param int $metering_count Number of metering licenses
     * @param int $subscription_days Subscription duration in days
     * @return array|null License data or null on failure
     */
    public function allocate_licenses(int $customer_id, int $metering_count, int $subscription_days): ?array
    {
        $payload = [
            'CustomerId' => $customer_id,
            'MeteringCount' => $metering_count,
            'SubscriptionTime' => sprintf('%d.00:00:00', $subscription_days)
        ];

        $response = wp_remote_post($this->api_base_url . '/Licensing/AllocateLicenses', [
            'headers' => [
                'Content-Type' => 'application/json',
            ],
            'body' => json_encode($payload)
        ]);

        if (is_wp_error($response)) {
            error_log('DIT Integration: Failed to allocate licenses - ' . $response->get_error_message());
            return null;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (!is_array($data)) {
            error_log('DIT Integration: Invalid license allocation response');
            return null;
        }

        return $data;
    }

    /**
     * Send data to the API
     *
     * @param array $data Data to send
     * @return array|\WP_Error Response from API or WP_Error on failure
     */
    public function send_data($data)
    {
        $endpoint = $this->api_base_url . '/api/v1/submit';

        $response = wp_remote_post($endpoint, [
            'headers' => [
                'Content-Type' => 'application/json',
                'Accept' => 'application/json'
            ],
            'body' => wp_json_encode($data),
            'timeout' => 30
        ]);

        if (is_wp_error($response)) {
            return $response;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            return new \WP_Error('invalid_json', 'Invalid JSON response from API');
        }

        return $data;
    }

    /**
     * Clear RSA key cache
     */
    public function clear_rsa_key_cache(): void
    {
        $this->cached_rsa_key = null;
        $this->rsa_key_cache_timestamp = 0;
        delete_transient($this->rsa_transient_key);
        error_log('DIT Integration: RSA key cache cleared from memory and transient');
    }

    /**
     * Get RSA key cache status
     *
     * @return array Cache status information
     */
    public function get_rsa_key_cache_status(): array
    {
        $is_cached = $this->cached_rsa_key !== null;
        $cache_age = $is_cached ? (time() - $this->rsa_key_cache_timestamp) : 0;
        $is_valid = $is_cached && $cache_age < $this->rsa_key_cache_time;

        // Check transient cache
        $transient_data = get_transient($this->rsa_transient_key);
        $transient_exists = $transient_data !== false;
        $transient_age = $transient_exists ? (time() - ($transient_data['timestamp'] ?? 0)) : 0;

        return [
            'is_cached' => $is_cached,
            'cache_age' => $cache_age,
            'is_valid' => $is_valid,
            'cache_timeout' => $this->rsa_key_cache_time,
            'key_length' => $is_cached ? mb_strlen($this->cached_rsa_key, '8bit') : 0,
            'transient_exists' => $transient_exists,
            'transient_age' => $transient_age,
            'cache_source' => $is_cached ? 'memory' : ($transient_exists ? 'transient' : 'none')
        ];
    }

    /**
     * Test API connection
     *
     * @return array Test results
     */
    public function test_connection(): array
    {
        $results = [
            'api_base_url' => $this->api_base_url,
            'rsa_key_test' => false,
            'endpoint_tests' => [],
            'overall_status' => 'failed'
        ];

        // Test RSA key endpoint
        try {
            $rsa_key = $this->get_server_rsa_key();
            $results['rsa_key_test'] = $rsa_key !== null;
            $results['rsa_key_length'] = $rsa_key ? mb_strlen($rsa_key, '8bit') : 0;
        } catch (Exception $e) {
            $results['rsa_key_error'] = $e->getMessage();
        }

        // Test various endpoints
        $test_endpoints = [
            '/Cryptography/GetServerRSAPublicKey',
            '/Customers/RegisterCustomer',
            '/Customers/CheckEmail',
            '/Session/Login'
        ];

        foreach ($test_endpoints as $endpoint) {
            $url = $this->api_base_url . $endpoint;
            $response = wp_remote_get($url, [
                'timeout' => 10,
                'sslverify' => true
            ]);

            if (is_wp_error($response)) {
                $results['endpoint_tests'][$endpoint] = [
                    'status' => 'error',
                    'error' => $response->get_error_message()
                ];
            } else {
                $response_code = wp_remote_retrieve_response_code($response);
                $results['endpoint_tests'][$endpoint] = [
                    'status' => $response_code === 200 ? 'success' : 'error',
                    'response_code' => $response_code,
                    'response_length' => mb_strlen(wp_remote_retrieve_body($response), '8bit')
                ];
            }
        }

        // Determine overall status
        $successful_tests = 0;
        foreach ($results['endpoint_tests'] as $test) {
            if ($test['status'] === 'success') {
                $successful_tests++;
            }
        }

        if ($results['rsa_key_test'] && $successful_tests > 0) {
            $results['overall_status'] = 'success';
        } elseif ($results['rsa_key_test']) {
            $results['overall_status'] = 'partial';
        }

        return $results;
    }

    /**
     * Send HTTP request using cURL as fallback
     *
     * @param string $url Request URL
     * @param array $args Request arguments
     * @return array|\WP_Error Response array or WP_Error on failure
     */
    private function send_request_with_curl(string $url, array $args)
    {
        if (!function_exists('curl_init')) {
            return new \WP_Error('curl_not_available', 'cURL is not available');
        }

        $ch = curl_init();

        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $args['timeout'] ?? 30,
            CURLOPT_SSL_VERIFYPEER => $args['sslverify'] ?? true,
            CURLOPT_CUSTOMREQUEST => $args['method'] ?? 'GET',
            CURLOPT_POSTFIELDS => $args['body'] ?? null,
            CURLOPT_HTTPHEADER => $this->format_curl_headers($args['headers'] ?? []),
            CURLOPT_HEADER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5
        ]);

        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($response === false) {
            return new \WP_Error('curl_error', 'cURL error: ' . $error);
        }

        // Parse response
        $headers = substr($response, 0, $header_size);
        $body = substr($response, $header_size);

        return [
            'headers' => $this->parse_curl_headers($headers),
            'body' => $body,
            'response' => ['code' => $http_code],
            'http_response' => null
        ];
    }

    /**
     * Format headers for cURL
     *
     * @param array $headers Headers array
     * @return array Formatted headers
     */
    private function format_curl_headers(array $headers): array
    {
        $formatted = [];
        foreach ($headers as $key => $value) {
            $formatted[] = "$key: $value";
        }
        return $formatted;
    }

    /**
     * Parse cURL response headers
     *
     * @param string $headers Raw headers string
     * @return array Parsed headers
     */
    private function parse_curl_headers(string $headers): array
    {
        $parsed = [];
        $lines = explode("\n", $headers);

        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line)) continue;

            if (strpos($line, ':') !== false) {
                list($key, $value) = explode(':', $line, 2);
                $parsed[trim($key)] = trim($value);
            }
        }

        return $parsed;
    }

    /**
     * Get permanent AES key for a user
     *
     * @param int $customer_id Customer ID
     * @return string|null Permanent AES key or null if not found
     */
    public function get_user_permanent_aes_key(int $customer_id): ?string
    {
        return \DIT\get_user_permanent_aes_key($customer_id);
    }

    /**
     * Get user name by customer ID
     *
     * @param int $customer_id Customer ID
     * @return string|null User name or null if not found
     */
    public function get_user_name(int $customer_id): ?string
    {
        return \DIT\get_user_name($customer_id);
    }

    /**
     * Set user's permanent AES key as active for future operations
     *
     * @param int $customer_id Customer ID
     * @return bool True if key was set successfully, false if user not found
     */


    /**
     * Register a new customer using hybrid AES+RSA encryption
     *
     * @param array $user_data User data to register
     * @return int|null Customer ID or null on failure
     */
    public function register_customer_hybrid(array $user_data): ?int
    {
        $core = \DIT\Core::get_instance();
        $logger = $core->logger;
        $encryption = $core->encryption;

        $logger->log_api_interaction('Register Customer Hybrid', [
            'encryption_method' => 'hybrid'
        ], 'info', 'Starting hybrid registration process.');

        try {
            // 1. Get RSA public key
            $rsa_key = $this->get_server_rsa_key();
            if (!$rsa_key) {
                throw new \Exception('Failed to get server RSA public key for registration.');
            }

            // 2. Generate AES key and IV
            $aes_data = $encryption->generate_aes_key();
            if (!is_array($aes_data) || !isset($aes_data['key'])) {
                throw new \Exception('Failed to generate AES key: invalid format returned');
            }
            $aes_key = $aes_data['key']; // 32 bytes
            $iv = $aes_data['iv']; // 16 bytes

            // 3. Clean and validate Tools array
            $cleaned_tools = [];
            if (!empty($user_data['tools']) && is_array($user_data['tools'])) {
                foreach ($user_data['tools'] as $tool) {
                    // Remove newlines, tabs, and extra whitespace
                    $clean_tool = trim(str_replace(["\n", "\r", "\t"], ' ', $tool));
                    // Remove multiple spaces
                    $clean_tool = preg_replace('/\s+/', ' ', $clean_tool);
                    if (!empty($clean_tool)) {
                        $cleaned_tools[] = $clean_tool;
                    }
                }
            }

            // Log cleaned tools for debugging
            $logger->log_api_interaction('Register Customer Hybrid', [
                'step' => 'clean_tools',
                'original_tools' => $user_data['tools'] ?? [],
                'cleaned_tools' => $cleaned_tools
            ], 'info', 'Tools cleaned and validated');

            // 4. Prepare payload (повний, не обрізаний)
            $payload = [
                'name' => $user_data['name'] ?? '',
                'email' => $user_data['email'] ?? '',
                'password' => isset($user_data['password']) ? hash('sha256', $user_data['password']) : '',
                'tools' => $cleaned_tools,
                'ts' => time()
            ];
            $json_payload = json_encode($payload);
            if ($json_payload === false) {
                throw new \Exception('Failed to encode registration payload to JSON: ' . json_last_error_msg());
            }

            // 5. Encrypt payload with AES
            $payload_b64 = $encryption->encrypt_with_aes($json_payload, $aes_key, $iv);

            // 6. Encrypt AES key with RSA
            $encrypted_key_b64 = $encryption->encrypt_with_rsa($aes_key, $rsa_key);

            // 7. Prepare request body
            $request_body = json_encode([
                'encryptedKeyB64' => $encrypted_key_b64,
                'ivB64' => base64_encode($iv),
                'payloadB64' => $payload_b64
            ]);

            $request_url = $this->api_base_url . '/Customers/RegisterCustomerHybrid';

            $logger->log_api_interaction('Register Customer Hybrid', [
                'request_url' => $request_url,
                'request_body' => $request_body
            ], 'info', 'Sending hybrid registration request.');

            $response = wp_remote_request($request_url, [
                'method' => 'PUT',
                'timeout' => 30,
                'sslverify' => true,
                'headers' => [
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/json'
                ],
                'body' => $request_body
            ]);

            if (is_wp_error($response)) {
                throw new \Exception('Registration request failed: ' . $response->get_error_message());
            }

            $response_code = wp_remote_retrieve_response_code($response);
            $response_body = wp_remote_retrieve_body($response);

            $logger->log_api_interaction('Register Customer Hybrid', [
                'response_code' => $response_code,
                'response_body' => $response_body,
                'request_url_sent' => $request_url,
                'request_method_sent' => 'PUT',
                'request_body_sent' => $request_body
            ], $response_code === 200 ? 'success' : 'error', 'Hybrid registration response received.');

            if ($response_code !== 200) {
                throw new \Exception('Registration failed: HTTP ' . $response_code . ' - ' . $response_body);
            }

            $response_data = json_decode($response_body, true);
            if (!$response_data || !isset($response_data['customerId'])) {
                throw new \Exception('Invalid response format: missing customerId');
            }

            $customer_id = (int) $response_data['customerId'];
            $user_name = $user_data['name'] ?? '';
            $permanent_aes_key = $response_data['permanentAesKey'] ?? $response_data['aesKey'] ?? '';

            // Store additional user data if available in response
            $additional_user_data = [
                'first_name' => $response_data['firstName'] ?? $user_data['first_name'] ?? '',
                'last_name' => $response_data['lastName'] ?? $user_data['last_name'] ?? '',
                'company' => $response_data['company'] ?? $user_data['company'] ?? '',
                'email' => $response_data['email'] ?? $user_data['email'] ?? ''
            ];

            \DIT\save_user_data($user_name, $customer_id, $permanent_aes_key, $additional_user_data);

            // Automatically register a user with the same data
            $user_registration_data = [
                'name' => $user_data['name'] ?? '',
                'email' => $user_data['email'] ?? '',
                'password' => $user_data['password'] ?? '',
                'first_name' => $user_data['first_name'] ?? '',
                'last_name' => $user_data['last_name'] ?? '',
                'tools' => $user_data['tools'] ?? []
            ];

            // Note: Initial user is created automatically by API when InitialUser=true
            $logger->log_api_interaction('Register Customer Hybrid', [
                'customer_id' => $customer_id,
                'initial_user_created' => true,
                'user_first_name' => $additional_user_data['first_name'],
                'user_last_name' => $additional_user_data['last_name'],
                'user_company' => $additional_user_data['company'],
                'user_email' => $additional_user_data['email'],
                'max_seats' => 10
            ], 'success', 'Customer registered successfully with automatic initial user creation.');

            return $customer_id;
        } catch (\Exception $e) {
            $logger->log_api_interaction('Register Customer Hybrid', [
                'error' => $e->getMessage()
            ], 'error', 'Hybrid registration failed.');
            error_log('DIT Integration: Hybrid registration failed - ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Register a new customer using the new two-step process
     * Step 1: PrepareRegisterCustomerRequest - encrypts data locally with temporary AES key
     * Step 2: RegisterCustomer - sends encrypted data and receives permanent AES key
     *
     * @param array $user_data User data to register
     * @return int|null Customer ID or null on failure
     */
    public function register_customer_prepare(array $user_data): ?int
    {
        $core = Core::get_instance();
        $logger = $core->logger;
        $encryption = $core->encryption;

        $logger->log_api_interaction('Register Customer Two-Step', [
            'step' => 'start',
            'encryption_method' => 'rsa_two_step',
            'user_data_keys' => array_keys($user_data)
        ], 'info', 'Registration process started (step 1)');

        try {
            // STEP 1: Generate temporary AES key
            $aes_data = $encryption->generate_aes_key();
            if (!is_array($aes_data) || !isset($aes_data['key'])) {
                throw new Exception('Failed to generate AES key: invalid format returned');
            }
            $temporary_aes_key = base64_encode($aes_data['key']); // 256-bit temporary key, Base64 encoded
            $logger->log_api_interaction('Register Customer Two-Step', [
                'step' => 'generate_aes_key',
                'temporary_aes_key' => $temporary_aes_key
            ], 'info', 'Temporary AES key generated (step 2)');

            // STEP 2: Clean and validate Tools array
            $cleaned_tools = [];
            if (!empty($user_data['tools']) && is_array($user_data['tools'])) {
                foreach ($user_data['tools'] as $tool) {
                    // Remove newlines, tabs, and extra whitespace
                    $clean_tool = trim(str_replace(["\n", "\r", "\t"], ' ', $tool));
                    // Remove multiple spaces
                    $clean_tool = preg_replace('/\s+/', ' ', $clean_tool);
                    if (!empty($clean_tool)) {
                        $cleaned_tools[] = $clean_tool;
                    }
                }
            }

            // Log cleaned tools for debugging
            $logger->log_api_interaction('Register Customer Two-Step', [
                'step' => 'clean_tools',
                'original_tools' => $user_data['tools'] ?? [],
                'cleaned_tools' => $cleaned_tools
            ], 'info', 'Tools cleaned and validated (step 2.5)');

            // STEP 2.5: Prepare data for PrepareRegisterCustomerRequest
            $request_data = [
                'aesKey' => $temporary_aes_key,
                'nameFirst' => $user_data['first_name'] ?? '',
                'nameLast' => $user_data['last_name'] ?? '',
                'company' => $user_data['company'] ?? '',
                'email' => $user_data['email'] ?? '',
                'password' => $user_data['password'] ?? '',
                'tools' => $cleaned_tools,
                'notes' => $user_data['notes'] ?? '',
                'initialUser' => true,
                'subscriptionId' => 17
            ];
            $logger->log_api_interaction('Register Customer Two-Step', [
                'step' => 'prepare_request_data',
                'request_data' => $request_data
            ], 'info', 'Prepared data for PrepareRegisterCustomerRequest (step 3)');

            $json_request = json_encode($request_data);
            if ($json_request === false) {
                $logger->log_api_interaction('Register Customer Two-Step', [
                    'step' => 'json_encode_error',
                    'error' => json_last_error_msg()
                ], 'error', 'JSON encoding error (step 3)');
                throw new Exception('Failed to encode registration request to JSON: ' . json_last_error_msg());
            }

            // STEP 3: Send PrepareRegisterCustomerRequest
            $prepare_url = $this->api_base_url . '/Customers/PrepareRegisterCustomerRequest';
            $logger->log_api_interaction('Register Customer Two-Step', [
                'step' => 'send_prepare_request',
                'request_url' => $prepare_url,
                'json_payload' => $json_request
            ], 'info', 'Sending PrepareRegisterCustomerRequest (step 4)');

            $prepare_response = wp_remote_request($prepare_url, [
                'method' => 'PUT',
                'headers' => [
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/json'
                ],
                'body' => $json_request,
                'timeout' => 30
            ]);

            if (is_wp_error($prepare_response)) {
                $logger->log_api_interaction('Register Customer Two-Step', [
                    'step' => 'prepare_request_error',
                    'error' => $prepare_response->get_error_message()
                ], 'error', 'PrepareRegisterCustomerRequest sending error (step 4)');
                throw new Exception('Prepare request failed: ' . $prepare_response->get_error_message());
            }

            $prepare_code = wp_remote_retrieve_response_code($prepare_response);
            $prepare_body = wp_remote_retrieve_body($prepare_response);
            $logger->log_api_interaction('Register Customer Two-Step', [
                'step' => 'prepare_response',
                'response_code' => $prepare_code,
                'response_body' => $prepare_body
            ], $prepare_code === 200 ? 'success' : 'error', 'PrepareRegisterCustomerRequest response received (step 5)');

            if ($prepare_code !== 200) {
                throw new Exception('Prepare request failed: HTTP ' . $prepare_code . ' - ' . $prepare_body);
            }

            // STEP 4: Handle PrepareRegisterCustomerRequest response
            $permanent_aes_key = '';
            if (!empty($prepare_body)) {
                $prepare_data = json_decode($prepare_body, true);
                if ($prepare_data && isset($prepare_data['aesKey'])) {
                    $permanent_aes_key = $prepare_data['aesKey'];
                    $logger->log_api_interaction('Register Customer Two-Step', [
                        'step' => 'permanent_aes_key_received',
                        'permanent_aes_key' => $permanent_aes_key
                    ], 'success', 'Permanent AES key received (step 6)');
                } else {
                    $logger->log_api_interaction('Register Customer Two-Step', [
                        'step' => 'permanent_aes_key_missing',
                        'prepare_body' => $prepare_body
                    ], 'info', 'Permanent AES key missing in response (step 6)');
                }
            }

            // STEP 5: Get RSA key
            $rsa_key = $this->get_server_rsa_key();
            $logger->log_api_interaction('Register Customer Two-Step', [
                'step' => 'get_rsa_key',
                'rsa_key_length' => $rsa_key ? strlen($rsa_key) : 0
            ], $rsa_key ? 'info' : 'error', 'RSA key received (step 7)');
            if (!$rsa_key) {
                throw new Exception('Failed to get server RSA public key for final registration.');
            }

            // STEP 6: Prepare final registration data
            $final_request_data = [
                'aesKey' => $permanent_aes_key ?: $temporary_aes_key,
                'nameFirst' => $user_data['first_name'] ?? '',
                'nameLast' => $user_data['last_name'] ?? '',
                'company' => $user_data['company'] ?? '',
                'email' => $user_data['email'] ?? '',
                // FIX: Do not hash password, send as plain text
                'password' => $user_data['password'] ?? '',
                'tools' => $user_data['tools'] ?? [],
                'notes' => $user_data['notes'] ?? '',
                'initialUser' => true,
                'subscriptionId' => 17
            ];
            $logger->log_api_interaction('Register Customer Two-Step', [
                'step' => 'prepare_final_data',
                'final_request_data' => $final_request_data
            ], 'info', 'Prepared final registration data (step 8)');

            $final_json_payload = json_encode($final_request_data);
            if ($final_json_payload === false) {
                $logger->log_api_interaction('Register Customer Two-Step', [
                    'step' => 'final_json_encode_error',
                    'error' => json_last_error_msg()
                ], 'error', 'Final JSON encoding error (step 8)');
                throw new Exception('Failed to encode final registration payload to JSON: ' . json_last_error_msg());
            }

            // STEP 7: Encrypt final data
            // --- RSA key size check ---
            $public_key_pem = $encryption->convert_to_pem_format($rsa_key);
            $public_key_resource = openssl_pkey_get_public($public_key_pem);
            if ($public_key_resource === false) {
                throw new Exception('Failed to import RSA public key for size check');
            }
            $key_details = openssl_pkey_get_details($public_key_resource);
            if ($key_details === false || $key_details['type'] !== OPENSSL_KEYTYPE_RSA || $key_details['bits'] !== 4096) {
                throw new Exception('RSA public key must be 4096 bits');
            }
            // --- end RSA key size check ---
            $encrypted_final_payload = $encryption->encrypt_data_with_rsa($final_json_payload, $rsa_key);
            $logger->log_api_interaction('Register Customer Two-Step', [
                'step' => 'encrypt_final_payload',
                'encrypted_final_payload_length' => strlen($encrypted_final_payload)
            ], $encrypted_final_payload ? 'info' : 'error', 'Final data encrypted (step 9)');
            if (empty($encrypted_final_payload)) {
                throw new Exception('Failed to encrypt final registration payload with RSA.');
            }

            // STEP 8: Send RegisterCustomer
            $register_url = $this->api_base_url . '/Customers/RegisterCustomer';
            $logger->log_api_interaction('Register Customer Two-Step', [
                'step' => 'send_register_request',
                'register_url' => $register_url,
                'encrypted_final_payload_length' => strlen($encrypted_final_payload)
            ], 'info', 'Sending RegisterCustomer (step 10)');

            $register_response = wp_remote_request($register_url, [
                'method' => 'PUT',
                'headers' => [
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/json'
                ],
                'body' => json_encode(['registerCustomerB64' => $encrypted_final_payload]),
                'timeout' => 30
            ]);

            if (is_wp_error($register_response)) {
                $logger->log_api_interaction('Register Customer Two-Step', [
                    'step' => 'register_request_error',
                    'error' => $register_response->get_error_message()
                ], 'error', 'RegisterCustomer sending error (step 10)');
                throw new Exception('Registration request failed: ' . $register_response->get_error_message());
            }

            $register_code = wp_remote_retrieve_response_code($register_response);
            $register_body = wp_remote_retrieve_body($register_response);
            $logger->log_api_interaction('Register Customer Two-Step', [
                'step' => 'register_response',
                'response_code' => $register_code,
                'response_body' => $register_body
            ], $register_code === 200 ? 'success' : 'error', 'RegisterCustomer response received (step 11)');

            if ($register_code !== 200) {
                throw new Exception('Registration failed: HTTP ' . $register_code . ' - ' . $register_body);
            }

            // STEP 9: Handle RegisterCustomer response
            $response_data = json_decode($register_body, true);
            if (!$response_data) {
                $logger->log_api_interaction('Register Customer Two-Step', [
                    'step' => 'register_response_json_error',
                    'register_body' => $register_body
                ], 'error', 'RegisterCustomer response JSON decode error (step 12)');
                throw new Exception('Invalid response format: not JSON');
            }

            if (!isset($response_data['customerId'])) {
                $logger->log_api_interaction('Register Customer Two-Step', [
                    'step' => 'register_response_missing_customerId',
                    'response_data' => $response_data
                ], 'error', 'RegisterCustomer response missing customerId (step 12)');
                throw new Exception('Invalid response format: missing customerId');
            }

            $customer_id = (int) $response_data['customerId'];
            $user_name = $user_data['name'] ?? '';
            $permanent_aes_key = $response_data['permanentAesKey'] ?? $response_data['aesKey'] ?? '';

            // Store additional user data if available in response
            $additional_user_data = [
                'first_name' => $response_data['firstName'] ?? $user_data['first_name'] ?? '',
                'last_name' => $response_data['lastName'] ?? $user_data['last_name'] ?? '',
                'company' => $response_data['company'] ?? $user_data['company'] ?? '',
                'email' => $response_data['email'] ?? $user_data['email'] ?? ''
            ];

            // Cache the username, CustomerId, and the returned AES key
            \DIT\save_user_data($user_name, $customer_id, $permanent_aes_key, $additional_user_data);

            // Note: Initial user is created automatically by API when InitialUser=true
            $logger->log_api_interaction('Register Customer Two-Step', [
                'customer_id' => $customer_id,
                'initial_user_created' => true,
                'encryption_method' => 'rsa',
                'response_decrypted' => true,
                'user_first_name' => $additional_user_data['first_name'],
                'user_last_name' => $additional_user_data['last_name'],
                'user_company' => $additional_user_data['company'],
                'user_email' => $additional_user_data['email'],
                'max_seats' => 10
            ], 'success', 'Customer registered successfully with automatic initial user creation.');

            return $customer_id;
        } catch (Exception $e) {
            $logger->log_api_interaction('Register Customer Two-Step', [
                'step' => 'exception',
                'error' => $e->getMessage()
            ], 'error', 'Exception in registration process');
            error_log('DIT Integration: Registration failed - ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Reprovision customer credentials using the two-step process
     * Step 1: PrepareReprovisionCustomerRequest - encrypts data locally
     * Step 2: ReprovisionCustomer - sends encrypted data and retrieves credentials
     *
     * @param string $email Customer email
     * @param string $password Customer password
     * @return array|null Reprovision data or null on failure
     */
    public function reprovision_customer(string $email, string $password): ?array
    {
        $core = Core::get_instance();
        $logger = $core->logger;

        $logger->log_api_interaction('Reprovision Customer Two-Step', [
            'encryption_method' => 'rsa_two_step',
            'email' => $email
        ], 'info', 'Starting two-step reprovision process.');

        try {
            // Step 1: Prepare the reprovision request data
            $request_data = [
                'email' => $email,
                'password' => $password
            ];

            $json_request = json_encode($request_data);
            if ($json_request === false) {
                throw new Exception('Failed to encode reprovision request to JSON: ' . json_last_error_msg());
            }

            // Step 1: Call PrepareReprovisionCustomerRequest
            $prepare_url = $this->api_base_url . '/Customers/PrepareReprovisionCustomerRequest';

            $logger->log_api_interaction('Prepare Reprovision Customer', [
                'request_url' => $prepare_url,
                'method' => 'PUT',
                'json_request' => $json_request,
                'request_length' => strlen($json_request)
            ], 'info', 'Sending prepare reprovision request (data encrypted locally).');

            $prepare_response = wp_remote_request($prepare_url, [
                'method' => 'PUT',
                'headers' => [
                    'Accept' => '*/*',
                    'Content-Type' => 'application/json'
                ],
                'body' => $json_request,
                'timeout' => 30
            ]);

            if (is_wp_error($prepare_response)) {
                throw new Exception('Prepare reprovision request failed: ' . $prepare_response->get_error_message());
            }

            $prepare_code = wp_remote_retrieve_response_code($prepare_response);
            $prepare_body = wp_remote_retrieve_body($prepare_response);

            $logger->log_api_interaction('Prepare Reprovision Customer', [
                'response_code' => $prepare_code,
                'response_body' => $prepare_body
            ], $prepare_code === 200 ? 'success' : 'error', 'Prepare reprovision response received.');

            if ($prepare_code !== 200) {
                throw new Exception('Prepare reprovision request failed: HTTP ' . $prepare_code . ' - ' . $prepare_body);
            }

            // Step 2: Call ReprovisionCustomer to retrieve encrypted data
            $reprovision_url = $this->api_base_url . '/Customers/ReprovisionCustomer';

            $logger->log_api_interaction('Reprovision Customer', [
                'request_url' => $reprovision_url,
                'method' => 'PUT'
            ], 'info', 'Retrieving encrypted reprovision data.');

            $reprovision_response = wp_remote_request($reprovision_url, [
                'method' => 'PUT',
                'headers' => [
                    'Accept' => '*/*',
                    'Content-Type' => 'application/json'
                ],
                'body' => '', // Encrypted data is handled by server
                'timeout' => 30
            ]);

            if (is_wp_error($reprovision_response)) {
                throw new Exception('Reprovision request failed: ' . $reprovision_response->get_error_message());
            }

            $reprovision_code = wp_remote_retrieve_response_code($reprovision_response);
            $reprovision_body = wp_remote_retrieve_body($reprovision_response);

            $logger->log_api_interaction('Reprovision Customer', [
                'response_code' => $reprovision_code,
                'response_body' => $reprovision_body,
                'request_url_sent' => $reprovision_url,
                'request_method_sent' => 'PUT'
            ], $reprovision_code === 200 ? 'success' : 'error', 'Reprovision response received.');

            if ($reprovision_code !== 200) {
                throw new Exception('Reprovision failed: HTTP ' . $reprovision_code . ' - ' . $reprovision_body);
            }

            // Parse the response
            $response_data = json_decode($reprovision_body, true);
            if (!$response_data) {
                throw new Exception('Invalid response format: not JSON');
            }

            if (!isset($response_data['customerId'])) {
                throw new Exception('Invalid response format: missing customerId');
            }

            $customer_id = (int) $response_data['customerId'];
            $aes_key = $response_data['aesKey'] ?? '';
            $error_code = $response_data['error'] ?? 0;

            // Cache the customer data
            \DIT\save_user_data($email, $customer_id, $aes_key);

            $result = [
                'customerId' => $customer_id,
                'aesKey' => $aes_key,
                'error' => $error_code
            ];

            $logger->log_api_interaction('Reprovision Customer Two-Step', [
                'customer_id' => $customer_id,
                'encryption_method' => 'rsa_two_step',
                'error_code' => $error_code
            ], 'success', 'Customer reprovisioned successfully with two-step process.');

            return $result;
        } catch (Exception $e) {
            $logger->log_api_interaction('Reprovision Customer Two-Step', [
                'error' => $e->getMessage(),
                'encryption_method' => 'rsa_two_step'
            ], 'error', 'Reprovision failed with two-step process.');
            error_log('DIT Integration: Reprovision failed - ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Begin Session API - REMOVED
     * 
     * This API was removed from the login process as it's only needed for tools.
     * Developer confirmed that BeginSession is not required for basic login functionality.
     * 
     * @param int $user_id User ID
     * @param int $license_type License type (0 = Metered, 1 = Time-based)
     * @param int $tool_type Tool type (0 = VFX, 1 = DI, 2 = Archive, 3 = Production)
     * @return array|null Always returns null (API removed)
     */
    public function begin_session(int $user_id, int $license_type, int $tool_type): ?array
    {
        // BeginSession API removed from login process - only needed for tools
        // This method is kept for backward compatibility but always returns null
        return null;
    }

    /**
     * Get tool type name for logging
     *
     * @param int $tool_type Tool type number
     * @return string Tool type name
     */
    private function get_tool_type_name(int $tool_type): string
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
     * End a session
     *
     * @param int $session_id Session ID from begin_session
     * @return array|null Session end data or null on failure
     */
    public function end_session(int $session_id): ?array
    {
        $core = Core::get_instance();
        $logger = $core->logger;

        $url = add_query_arg([
            'SessionId' => $session_id
        ], $this->api_base_url . '/Session/EndSession');

        $logger->log_api_interaction('End Session', [
            'session_id' => $session_id,
            'url' => $url
        ], 'info', 'Ending session');

        $response = wp_remote_request($url, [
            'method' => 'PUT',
            'timeout' => 30,
            'sslverify' => true
        ]);

        if (is_wp_error($response)) {
            $logger->log_api_interaction('End Session', [
                'session_id' => $session_id,
                'error' => $response->get_error_message()
            ], 'error', 'Failed to end session');
            return null;
        }

        $response_code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);

        if ($response_code !== 200) {
            $logger->log_api_interaction('End Session', [
                'session_id' => $session_id,
                'response_code' => $response_code,
                'response_body' => $body
            ], 'error', 'End session failed with HTTP ' . $response_code);
            return null;
        }

        $data = json_decode($body, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            $logger->log_api_interaction('End Session', [
                'session_id' => $session_id,
                'response_body' => $body,
                'json_error' => json_last_error_msg()
            ], 'error', 'Invalid JSON response from EndSession API');
            return null;
        }

        $logger->log_api_interaction('End Session', [
            'session_id' => $session_id,
            'error_code' => $data['Error'] ?? null,
            'transitions_count' => isset($data['transitions']) ? count($data['transitions']) : 0
        ], 'success', 'Session ended successfully');

        return $data;
    }

    /**
     * Record session transition
     *
     * @param int $session_id Session ID
     * @param int $frame Frame number
     * @param int $layer Layer number
     * @param int $error Error code (optional, defaults to 0)
     * @return bool Success status
     */
    public function session_transition(int $session_id, int $frame, int $layer, int $error = 0): bool
    {
        $core = Core::get_instance();
        $logger = $core->logger;

        $url = add_query_arg([
            'SessionId' => $session_id,
            'Frame' => $frame,
            'Layer' => $layer,
            'Error' => $error
        ], $this->api_base_url . '/Session/SessionTransition');

        $logger->log_api_interaction('Session Transition', [
            'session_id' => $session_id,
            'frame' => $frame,
            'layer' => $layer,
            'error' => $error,
            'url' => $url
        ], 'info', 'Recording session transition');

        $response = wp_remote_request($url, [
            'method' => 'PUT',
            'timeout' => 30,
            'sslverify' => true
        ]);

        if (is_wp_error($response)) {
            $logger->log_api_interaction('Session Transition', [
                'session_id' => $session_id,
                'frame' => $frame,
                'layer' => $layer,
                'error' => $response->get_error_message()
            ], 'error', 'Failed to record session transition');
            return false;
        }

        $response_code = wp_remote_retrieve_response_code($response);

        if ($response_code !== 200) {
            $logger->log_api_interaction('Session Transition', [
                'session_id' => $session_id,
                'frame' => $frame,
                'layer' => $layer,
                'response_code' => $response_code
            ], 'error', 'Session transition failed with HTTP ' . $response_code);
            return false;
        }

        $logger->log_api_interaction('Session Transition', [
            'session_id' => $session_id,
            'frame' => $frame,
            'layer' => $layer
        ], 'success', 'Session transition recorded successfully');

        return true;
    }

    /**
     * Get available login roles for email
     * @param string $email
     * @return array|null
     */
    public function get_login_roles_for_email(string $email): ?array
    {
        $core = Core::get_instance();
        $logger = $core->logger;

        $url = add_query_arg([
            'Email' => urlencode($email)
        ], $this->api_base_url . '/Application/LoginRolesForEmail');

        $logger->log_api_interaction('Login Roles For Email', [
            'email' => $email,
            'url' => $url,
            'step' => 'request_start'
        ], 'info', 'Starting login roles for email request');

        $response = wp_remote_get($url, [
            'timeout' => 30,
            'sslverify' => true
        ]);

        if (is_wp_error($response)) {
            $logger->log_api_interaction('Login Roles For Email', [
                'email' => $email,
                'error' => $response->get_error_message(),
                'step' => 'wp_error'
            ], 'error', 'Login roles for email failed with WordPress error');
            return null;
        }

        $response_code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        $headers = wp_remote_retrieve_headers($response);

        $logger->log_api_interaction('Login Roles For Email', [
            'email' => $email,
            'response_code' => $response_code,
            'response_body' => $body,
            'response_headers' => $headers,
            'body_length' => strlen($body),
            'step' => 'response_received'
        ], $response_code === 200 ? 'info' : 'error', 'Login roles for email response received');

        if ($response_code !== 200) {
            $logger->log_api_interaction('Login Roles For Email', [
                'email' => $email,
                'response_code' => $response_code,
                'response_body' => $body,
                'step' => 'http_error'
            ], 'error', 'Login roles for email failed with HTTP ' . $response_code);
            return null;
        }

        // Try to decode JSON response
        $data = json_decode($body, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            $logger->log_api_interaction('Login Roles For Email', [
                'email' => $email,
                'response_body' => $body,
                'json_error' => json_last_error_msg(),
                'step' => 'json_decode_error'
            ], 'error', 'Invalid JSON response from LoginRolesForEmail API');
            return null;
        }

        // Ensure data is an array of integers
        if (!is_array($data)) {
            $logger->log_api_interaction('Login Roles For Email', [
                'email' => $email,
                'response_body' => $body,
                'decoded_data' => $data,
                'data_type' => gettype($data),
                'step' => 'type_error'
            ], 'error', 'LoginRolesForEmail API returned unsupported data type: ' . gettype($data));
            return null;
        }

        $logger->log_api_interaction('Login Roles For Email', [
            'email' => $email,
            'decoded_data' => $data,
            'data_type' => gettype($data),
            'is_array' => is_array($data),
            'step' => 'json_decoded'
        ], 'success', 'Login roles for email JSON decoded successfully');

        return $data;
    }

    /**
     * Get users for customer
     *
     * @param int $customer_id Customer ID
     * @return array|null Users array or null on failure
     */
    public function get_users_for_customer(int $customer_id): ?array
    {
        $core = Core::get_instance();
        $logger = $core->logger;
        $encryption = $core->encryption;

        // Генеруємо 16-байтовий IV
        $iv = random_bytes(16);
        $iv_hex = bin2hex($iv); // hex-encode the IV as per developer instructions

        // Формуємо GET-запит з новим ендпоінтом та параметрами
        $request_url = $this->api_base_url . '/Users/GetUsersForCustomer?customerId=' . $customer_id . '&hexAesIV=' . $iv_hex;

        // Get AES key directly from customer-specific storage (session/cookies/user_meta)
        // This is the correct way based on the new architecture where AES keys are stored per customer_id
        $logger->log_api_interaction('Get Users For Customer', [
            'user_id' => $customer_id,
            'step' => 'before_get_aes_key',
            'session_id' => session_id(),
            'session_status' => session_status() === PHP_SESSION_ACTIVE ? 'Active' : 'Inactive',
            'session_data_keys' => isset($_SESSION) ? array_keys($_SESSION) : [],
            'dit_aes_keys_exists' => isset($_SESSION['dit_aes_keys']),
            'dit_aes_keys_count' => isset($_SESSION['dit_aes_keys']) ? count($_SESSION['dit_aes_keys']) : 0,
            'dit_aes_keys_customer_exists' => isset($_SESSION['dit_aes_keys'][$customer_id]),
            'login_aes_key_exists' => isset($_SESSION['login_aes_key']),
            'login_aes_key_length' => isset($_SESSION['login_aes_key']) ? strlen($_SESSION['login_aes_key']) : 0,
            'note' => 'Cookies removed - AES keys stored only in session'
        ], 'info', 'About to retrieve AES key for customer ' . $customer_id . ' (GetUsersForCustomer, cookies disabled)');

        $aes_key = $this->get_user_permanent_aes_key($customer_id);

        if (empty($aes_key)) {
            $logger->log_api_interaction('Get Users For Customer', [
                'user_id' => $customer_id,
                'aes_key_found' => false,
                'aes_key_source' => 'get_user_permanent_aes_key',
                'step' => 'aes_key_not_found'
            ], 'error', 'No AES key found for customer ' . $customer_id . ' - cannot decrypt response');
            throw new Exception('No AES key available for customer ' . $customer_id . ' - decryption impossible');
        }

        $logger->log_api_interaction('Get Users For Customer', [
            'user_id' => $customer_id,
            'aes_key_found' => true,
            'aes_key_source' => 'get_user_permanent_aes_key',
            'aes_key_length' => strlen($aes_key),
            'aes_key_type' => (ctype_xdigit($aes_key) ? 'hex' : 'binary'),
            'aes_key_preview' => (strlen($aes_key) <= 32 ? bin2hex(substr($aes_key, 0, 8)) . '...' : substr($aes_key, 0, 20) . '...'),
            'step' => 'aes_key_retrieved'
        ], 'info', 'AES key retrieved successfully for customer ' . $customer_id);

        $logger->log_api_interaction('Get Users For Customer', [
            'user_id' => $customer_id,
            'url' => $request_url,
            'has_aes_key' => !empty($aes_key),
            'aes_key_length' => $aes_key ? strlen($aes_key) : 0,
            'iv_hex' => $iv_hex,
            'iv_base64_for_decryption' => base64_encode(hex2bin($iv_hex)),
            'parameter_name' => 'hexAesIV',
            'step' => 'request_start'
        ], 'info', 'Starting get users for customer request (new endpoint: GetUsersForCustomer with hexAesIV)');

        try {
            $response = wp_remote_get($request_url, [
                'timeout' => 30,
                'sslverify' => true,
                'headers' => [
                    'User-Agent' => 'WordPress/' . get_bloginfo('version') . '; ' . get_bloginfo('url')
                ]
            ]);

            if (is_wp_error($response)) {
                $logger->log_api_interaction('Get Users For Customer', [
                    'user_id' => $customer_id,
                    'error' => $response->get_error_message(),
                    'step' => 'wp_error'
                ], 'error', 'Get users for customer failed with WordPress error');
                throw new Exception('Failed to get users: ' . $response->get_error_message());
            }

            $response_code = wp_remote_retrieve_response_code($response);
            $body = wp_remote_retrieve_body($response);
            $headers = wp_remote_retrieve_headers($response);

            $logger->log_api_interaction('Get Users For Customer', [
                'user_id' => $customer_id,
                'response_code' => $response_code,
                'response_body' => $body,
                'response_headers' => $headers,
                'body_length' => strlen($body),
                'step' => 'response_received'
            ], $response_code === 200 ? 'info' : 'error', 'Get users for customer response received');

            if ($response_code !== 200) {
                $logger->log_api_interaction('Get Users For Customer', [
                    'user_id' => $customer_id,
                    'response_code' => $response_code,
                    'response_body' => $body,
                    'step' => 'http_error'
                ], 'error', 'Get users for customer failed with HTTP ' . $response_code);
                throw new Exception('Failed to get users: HTTP ' . $response_code);
            }

            // Дешифрування: передаємо IV у handle_encrypted_response_with_headers
            $headers_array = [];
            $headers_type = gettype($headers);
            $headers_class = is_object($headers) ? get_class($headers) : 'not_object';

            if (is_object($headers) && method_exists($headers, 'getAll')) {
                $headers_array = $headers->getAll();
            } elseif (is_array($headers)) {
                $headers_array = $headers;
            }

            // Передаємо IV та AES ключ у контекст дешифрування (конвертуємо hex назад в base64 для дешифрування)
            $iv_base64_for_decryption = base64_encode(hex2bin($iv_hex));
            $data = $this->handle_encrypted_response_with_headers($body, $headers_array, 'Get Users For Customer', [
                'user_id' => $customer_id,
                'aes_iv' => $iv_base64_for_decryption,
                'aes_key' => $aes_key
            ]);

            if (!is_array($data)) {
                $logger->log_api_interaction('Get Users For Customer', [
                    'user_id' => $customer_id,
                    'response_body' => $body,
                    'decoded_data' => $data,
                    'data_type' => gettype($data),
                    'step' => 'type_error'
                ], 'error', 'GetUsers API returned unsupported data type: ' . gettype($data));
                throw new Exception('Invalid response format: expected array, got ' . gettype($data));
            }

            $logger->log_api_interaction('Get Users For Customer', [
                'user_id' => $customer_id,
                'decoded_data' => $data,
                'users_count' => count($data),
                'data_type' => gettype($data),
                'is_array' => is_array($data),
                'step' => 'json_decoded'
            ], 'success', 'Get users for customer JSON decoded successfully');

            return $data;
        } catch (Exception $e) {
            $logger->log_api_interaction('Get Users For Customer', [
                'user_id' => $customer_id,
                'error' => $e->getMessage(),
                'step' => 'exception'
            ], 'error', 'Failed to get users for customer: ' . $e->getMessage());
            error_log('DIT Integration: Failed to get users for customer ' . $customer_id . ' - ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Universal method to handle encrypted API responses
     *
     * @param string $response_body Raw response body from API
     * @param string $operation_name Name of the operation for logging
     * @param array $context Additional context data for logging
     * @return array|null Decrypted and parsed data or null on failure
     */
    private function handle_encrypted_response(string $response_body, string $operation_name, array $context = []): ?array
    {
        $core = Core::get_instance();
        $logger = $core->logger;

        // First, try to parse as regular JSON
        $data = json_decode($response_body, true);
        if ($data !== null) {
            $logger->log_api_interaction($operation_name, array_merge($context, [
                'response_type' => 'json',
                'step' => 'json_parsed_successfully'
            ]), 'success', 'Response parsed as JSON successfully');
            return $data;
        }

        // If JSON parsing failed, check if it's encrypted
        $logger->log_api_interaction($operation_name, array_merge($context, [
            'response_body' => $response_body,
            'json_error' => json_last_error_msg(),
            'step' => 'json_decode_failed_trying_decrypt'
        ]), 'info', 'JSON decode failed, attempting to decrypt response');

        // Check if response looks like encrypted data (base64 string with or without quotes)
        $is_quoted = preg_match('/^"[A-Za-z0-9+\/]+={0,2}"$/', $response_body);
        $is_unquoted = preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $response_body);

        $logger->log_api_interaction($operation_name, array_merge($context, [
            'response_body_preview' => substr($response_body, 0, 50) . '...',
            'is_quoted' => $is_quoted,
            'is_unquoted' => $is_unquoted,
            'step' => 'encrypted_format_check'
        ]), 'info', 'Checking if response is in encrypted format');

        if (!$is_quoted && !$is_unquoted) {
            $logger->log_api_interaction($operation_name, array_merge($context, [
                'response_body' => $response_body,
                'is_quoted' => $is_quoted,
                'is_unquoted' => $is_unquoted,
                'step' => 'not_encrypted_format'
            ]), 'error', 'Response is not in encrypted format');
            return null;
        }

        // Remove quotes if present to get the encrypted data
        $encrypted_data = $is_quoted ? trim($response_body, '"') : $response_body;

        // Get AES key from multiple sources
        $aes_key = $this->get_aes_key_for_decryption();
        if (!$aes_key) {
            $logger->log_api_interaction($operation_name, array_merge($context, [
                'step' => 'no_aes_key_available'
            ]), 'error', 'No AES key available for decryption');
            return null;
        }

        // Try to decrypt with different IV strategies
        $decrypted_data = $this->attempt_decryption_with_multiple_ivs($encrypted_data, $aes_key, $operation_name, $context);
        if (!$decrypted_data) {
            return null;
        }

        // Try to parse decrypted data as JSON
        $data = json_decode($decrypted_data, true);
        if ($data === null) {
            $logger->log_api_interaction($operation_name, array_merge($context, [
                'decrypted_data' => $decrypted_data,
                'json_error' => json_last_error_msg(),
                'step' => 'decrypted_but_not_json'
            ]), 'error', 'Decryption successful but result is not valid JSON');
            return null;
        }

        $logger->log_api_interaction($operation_name, array_merge($context, [
            'response_type' => 'encrypted_json',
            'decrypted_data_length' => strlen($decrypted_data),
            'parsed_data_type' => gettype($data),
            'step' => 'decryption_and_parsing_successful'
        ]), 'success', 'Successfully decrypted and parsed encrypted JSON response');

        return $data;
    }

    /**
     * Get AES key for decryption from multiple sources
     *
     * @return string|null AES key or null if not found
     */
    private function get_aes_key_for_decryption(int $customer_id = null): ?string
    {
        $core = Core::get_instance();
        $logger = $core->logger;

        $logger->log_api_interaction('AES Key Retrieval', [
            'step' => 'starting_aes_key_retrieval'
        ], 'info', 'Starting AES key retrieval from multiple sources');



        $aes_key = null;

        try {
            // Simplified AES key retrieval: directly get customer-specific key
            if ($customer_id) {
                $aes_key = $this->get_user_permanent_aes_key($customer_id);

                if ($aes_key) {
                    $logger->log_api_interaction('AES Key Retrieval', [
                        'source' => 'customer_specific_direct',
                        'customer_id' => $customer_id,
                        'key_found' => true,
                        'key_length' => strlen($aes_key),
                        'key_preview' => substr($aes_key, 0, 20) . '...',
                        'step' => 'customer_specific_direct'
                    ], 'success', 'Customer-specific AES key found directly');
                } else {
                    $logger->log_api_interaction('AES Key Retrieval', [
                        'source' => 'customer_specific_direct',
                        'customer_id' => $customer_id,
                        'key_found' => false,
                        'step' => 'customer_specific_direct'
                    ], 'error', 'No AES key found for customer ' . $customer_id);
                }
            }

            // Simplified key comparison - we only use customer-specific key now
            if ($customer_id && $aes_key) {
                $logger->log_api_interaction('AES Key Status', [
                    'customer_id' => $customer_id,
                    'key_found' => true,
                    'key_length' => strlen($aes_key),
                    'key_source' => 'customer_specific_direct',
                    'step' => 'key_status_confirmed'
                ], 'info', 'Customer-specific AES key confirmed for customer ' . $customer_id);
            }

            // Final summary
            $logger->log_api_interaction('AES Key Retrieval', [
                'final_key_found' => !empty($aes_key),
                'key_length' => $aes_key ? strlen($aes_key) : 0,
                'key_source' => $customer_id ? 'customer_specific_direct' : 'none',
                'step' => 'final_summary'
            ], !empty($aes_key) ? 'success' : 'error', 'AES key retrieval completed');

            if ($aes_key) {
                $logger->log_api_interaction('AES Key Retrieval', [
                    'final_key_returned' => true,
                    'final_key_length' => strlen($aes_key),
                    'final_key_preview' => substr($aes_key, 0, 20) . '...',
                    'step' => 'returning_final_key'
                ], 'success', 'Returning AES key for decryption');
            }

            return $aes_key;
        } catch (\Exception $e) {
            $logger->log_api_interaction('AES Key Retrieval', [
                'error' => $e->getMessage(),
                'step' => 'exception'
            ], 'error', 'Exception during AES key retrieval: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Attempt decryption with multiple IV strategies
     *
     * @param string $encrypted_data Base64 encoded encrypted data
     * @param string $aes_key AES key for decryption
     * @param string $operation_name Name of the operation for logging
     * @param array $context Additional context data for logging
     * @return string|null Decrypted data or null on failure
     */
    private function attempt_decryption_with_multiple_ivs(string $encrypted_data, string $aes_key, string $operation_name, array $context = []): ?string
    {
        $core = Core::get_instance();
        $logger = $core->logger;
        $encryption = $core->encryption;

        // Extract AES key from steganography format if needed
        $binary_aes_key = $aes_key;
        $original_length = strlen($aes_key);
        $binary_length = mb_strlen($aes_key, '8bit');

        // If key is steganography format (128 hex characters), extract real AES key
        if (ctype_xdigit($aes_key) && $original_length === 128) {
            $steganography = $core->steganography;
            $binary_aes_key = $steganography->extract_aes_key_from_steganography($aes_key);
            if ($binary_aes_key === null) {
                $logger->log_api_interaction($operation_name, array_merge($context, [
                    'error' => 'Failed to extract AES key from steganography',
                    'step' => 'steganography_extract_failed'
                ]), 'error', 'Failed to extract AES key from steganography');
                return null;
            }

            $logger->log_api_interaction($operation_name, array_merge($context, [
                'original_key_length' => $original_length,
                'binary_key_length' => mb_strlen($binary_aes_key, '8bit'),
                'step' => 'aes_key_extracted_from_steganography'
            ]), 'info', 'AES key extracted from steganography format');
        }
        // If key is base64 encoded (44 characters), decode it to binary
        elseif ($original_length === 44 && $binary_length === 44) {
            $binary_aes_key = base64_decode($aes_key);
            if ($binary_aes_key === false) {
                $logger->log_api_interaction($operation_name, array_merge($context, [
                    'error' => 'Failed to decode base64 key',
                    'step' => 'base64_decode_failed'
                ]), 'error', 'Failed to decode base64 AES key');
                return null;
            }

            $logger->log_api_interaction($operation_name, array_merge($context, [
                'original_key_length' => $original_length,
                'binary_key_length' => mb_strlen($binary_aes_key, '8bit'),
                'step' => 'aes_key_base64_decoded'
            ]), 'info', 'AES key converted from base64 to binary');
        }

        $logger->log_api_interaction($operation_name, array_merge($context, [
            'encrypted_data_length' => strlen($encrypted_data),
            'aes_key_length' => strlen($binary_aes_key),
            'step' => 'starting_multiple_iv_decryption'
        ]), 'info', 'Starting decryption with multiple IV strategies');

        // Define IV strategies to try
        $iv_strategies = [
            'zero_iv' => base64_encode(str_repeat("\x00", 16)), // 16 bytes of zeros
            'one_iv' => base64_encode(str_repeat("\x01", 16)),  // 16 bytes of ones
            'random_iv' => base64_encode(random_bytes(16)),     // Random IV (unlikely to work)
        ];

        foreach ($iv_strategies as $strategy_name => $iv) {
            try {
                $logger->log_api_interaction($operation_name, array_merge($context, [
                    'iv_strategy' => $strategy_name,
                    'iv_value' => $iv,
                    'step' => 'attempting_decryption_with_' . $strategy_name
                ]), 'info', 'Attempting decryption with ' . $strategy_name . ' IV');

                $decrypted_data = $encryption->decrypt_with_aes($encrypted_data, $binary_aes_key, $iv);

                $logger->log_api_interaction($operation_name, array_merge($context, [
                    'iv_strategy' => $strategy_name,
                    'decrypted_data_length' => strlen($decrypted_data),
                    'decrypted_data_preview' => substr($decrypted_data, 0, 100) . '...',
                    'is_valid_json_start' => $this->is_valid_json_start($decrypted_data),
                    'step' => 'decryption_completed_with_' . $strategy_name
                ]), 'info', 'Decryption completed with ' . $strategy_name . ' IV');

                // Check if decrypted data looks like valid JSON
                if ($this->is_valid_json_start($decrypted_data)) {
                    $logger->log_api_interaction($operation_name, array_merge($context, [
                        'iv_strategy' => $strategy_name,
                        'decrypted_data_preview' => substr($decrypted_data, 0, 100) . '...',
                        'step' => 'decryption_successful_with_' . $strategy_name
                    ]), 'success', 'Successfully decrypted with ' . $strategy_name . ' IV');
                    return $decrypted_data;
                } else {
                    $logger->log_api_interaction($operation_name, array_merge($context, [
                        'iv_strategy' => $strategy_name,
                        'decrypted_data_preview' => substr($decrypted_data, 0, 100) . '...',
                        'step' => 'decryption_failed_invalid_json_with_' . $strategy_name
                    ]), 'warning', 'Decryption with ' . $strategy_name . ' IV produced invalid JSON');
                }
            } catch (Exception $e) {
                $logger->log_api_interaction($operation_name, array_merge($context, [
                    'iv_strategy' => $strategy_name,
                    'decrypt_error' => $e->getMessage(),
                    'step' => 'decryption_exception_with_' . $strategy_name
                ]), 'warning', 'Decryption with ' . $strategy_name . ' IV failed: ' . $e->getMessage());
            }
        }

        $logger->log_api_interaction($operation_name, array_merge($context, [
            'iv_strategies_tried' => array_keys($iv_strategies),
            'step' => 'all_decryption_attempts_failed'
        ]), 'error', 'All decryption attempts failed with different IV strategies');

        return null;
    }

    /**
     * Check if string starts with valid JSON
     *
     * @param string $data String to check
     * @return bool True if string starts with valid JSON
     */
    private function is_valid_json_start(string $data): bool
    {
        $trimmed = trim($data);
        return (strpos($trimmed, '{') === 0 || strpos($trimmed, '[') === 0);
    }

    /**
     * Handle encrypted response with IV in headers
     *
     * @param string $response_body Raw response body from API
     * @param array $response_headers Response headers
     * @param string $operation_name Name of the operation for logging
     * @param array $context Additional context data for logging
     * @return array|null Decrypted and parsed data or null on failure
     */
    private function handle_encrypted_response_with_headers(string $response_body, array $response_headers, string $operation_name, array $context = []): ?array
    {
        $core = Core::get_instance();
        $logger = $core->logger;

        // Log the start of processing
        $logger->log_api_interaction($operation_name, array_merge($context, [
            'response_body' => $response_body,
            'response_headers' => $response_headers,
            'step' => 'encrypted_response_handler_start'
        ]), 'info', 'Starting encrypted response handler');

        // First, try to parse as regular JSON
        $data = json_decode($response_body, true);
        if ($data !== null) {
            $logger->log_api_interaction($operation_name, array_merge($context, [
                'response_type' => 'json',
                'step' => 'json_parsed_successfully'
            ]), 'success', 'Response parsed as JSON successfully');

            // Check if the parsed data is a string that looks like encrypted data
            if (is_string($data) && preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $data)) {
                $logger->log_api_interaction($operation_name, array_merge($context, [
                    'parsed_data' => $data,
                    'step' => 'json_parsed_but_appears_encrypted'
                ]), 'info', 'JSON parsed but appears to be encrypted data, continuing with decryption');

                // Use the parsed string as encrypted data and continue with decryption
                $encrypted_data = $data;
            } else {
                // Return the data only if it's not a string that looks like encrypted data
                return $data;
            }
        } else {
            // If JSON parsing failed, check if it's encrypted
            $logger->log_api_interaction($operation_name, array_merge($context, [
                'response_body' => $response_body,
                'json_error' => json_last_error_msg(),
                'step' => 'json_decode_failed_trying_decrypt'
            ]), 'info', 'JSON decode failed, attempting to decrypt response');

            // Check if response looks like encrypted data (base64 string with or without quotes)
            $is_quoted = preg_match('/^"[A-Za-z0-9+\/]+={0,2}"$/', $response_body);
            $is_unquoted = preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $response_body);

            $logger->log_api_interaction($operation_name, array_merge($context, [
                'response_body_preview' => substr($response_body, 0, 50) . '...',
                'is_quoted' => $is_quoted,
                'is_unquoted' => $is_unquoted,
                'step' => 'encrypted_format_check'
            ]), 'info', 'Checking if response is in encrypted format');

            if (!$is_quoted && !$is_unquoted) {
                $logger->log_api_interaction($operation_name, array_merge($context, [
                    'response_body' => $response_body,
                    'is_quoted' => $is_quoted,
                    'is_unquoted' => $is_unquoted,
                    'step' => 'not_encrypted_format'
                ]), 'error', 'Response is not in encrypted format');
                return null;
            }

            // Remove quotes if present to get the encrypted data
            $encrypted_data = $is_quoted ? trim($response_body, '"') : $response_body;
        }

        $logger->log_api_interaction($operation_name, array_merge($context, [
            'encrypted_data' => $encrypted_data,
            'encrypted_data_length' => strlen($encrypted_data),
            'step' => 'extracted_encrypted_data'
        ]), 'info', 'Extracted encrypted data from response');

        // Get AES key - if not provided in context, get from multiple sources
        $customer_id = $context['customer_id'] ?? null;
        $aes_key = $context['aes_key'] ?? null;

        $logger->log_api_interaction($operation_name, array_merge($context, [
            'aes_key_from_context' => !empty($aes_key),
            'aes_key_length_from_context' => $aes_key ? strlen($aes_key) : 0,
            'step' => 'aes_key_check'
        ]), 'info', 'Checking AES key from context');

        if (!$aes_key) {
            $logger->log_api_interaction($operation_name, array_merge($context, [
                'step' => 'aes_key_not_in_context_trying_sources'
            ]), 'info', 'AES key not in context, trying multiple sources');

            $aes_key = $this->get_aes_key_for_decryption($customer_id);
            if (!$aes_key) {
                $logger->log_api_interaction($operation_name, array_merge($context, [
                    'step' => 'no_aes_key_available'
                ]), 'error', 'No AES key available for decryption');
                return null;
            }
        }

        $logger->log_api_interaction($operation_name, array_merge($context, [
            'aes_key_found' => true,
            'aes_key_length' => strlen($aes_key),
            'aes_key_preview' => substr($aes_key, 0, 20) . '...',
            'step' => 'aes_key_obtained_for_decryption'
        ]), 'info', 'AES key obtained for decryption');

        // Test decryption with working key and analyze parameters
        if (!empty($context['encrypted_data'] ?? null) && !empty($context['aes_iv'] ?? null)) {
            $this->test_decryption_with_working_key($context['encrypted_data'], $context['aes_iv'], $customer_id);
            $this->compare_decryption_parameters($operation_name, $context, $aes_key, $context['encrypted_data'], $context['aes_iv']);
        }

        // Also analyze parameters directly in the decryption method
        if (!empty($context['aes_iv'])) {
            $this->compare_decryption_parameters($operation_name, $context, $aes_key, $context['encrypted_data'] ?? '', $context['aes_iv']);
        }

        if (!empty($context['aes_iv'])) {
            $logger->log_api_interaction($operation_name, array_merge($context, [
                'iv_source' => 'context_aes_iv',
                'iv_value' => $context['aes_iv'],
                'step' => 'attempting_decryption_with_context_iv'
            ]), 'info', 'Attempting decryption with IV from context (AesIV param)');

            try {
                $encryption = $core->encryption;



                // Extract AES key from steganography format if needed
                $binary_aes_key = $aes_key;
                if (ctype_xdigit($aes_key) && strlen($aes_key) === 128) {
                    // Steganography format - extract real AES key using GGKK method
                    $steganography = $core->steganography;
                    $binary_aes_key = $steganography->extract_aes_key_from_steganography($aes_key);
                    $logger->log_api_interaction($operation_name, array_merge($context, [
                        'original_key_length' => strlen($aes_key),
                        'binary_key_length' => strlen($binary_aes_key),
                        'key_converted' => true,
                        'step' => 'aes_key_extracted_from_steganography'
                    ]), 'info', 'AES key extracted from steganography format');
                } elseif (preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $aes_key)) {
                    // Base64 format - decode to binary
                    $binary_aes_key = base64_decode($aes_key);
                    $logger->log_api_interaction($operation_name, array_merge($context, [
                        'original_key_length' => strlen($aes_key),
                        'binary_key_length' => strlen($binary_aes_key),
                        'key_converted' => true,
                        'step' => 'aes_key_base64_decoded'
                    ]), 'info', 'AES key converted from base64 to binary');
                }

                $decrypted_data = $encryption->decrypt_with_aes($encrypted_data, $binary_aes_key, $context['aes_iv']);

                // Логування raw дешифрованих даних для діагностики
                $logger->log_api_interaction($operation_name, array_merge($context, [
                    'iv_source' => 'context_aes_iv',
                    'decrypted_data_raw' => $decrypted_data,
                    'step' => 'decryption_attempted_with_context_iv'
                ]), 'info', 'Decrypted data (raw, before JSON decode)');

                if ($this->is_valid_json_start($decrypted_data)) {
                    $data = json_decode($decrypted_data, true);
                    if ($data !== null) {
                        $logger->log_api_interaction($operation_name, array_merge($context, [
                            'iv_source' => 'context_aes_iv',
                            'decrypted_data_length' => strlen($decrypted_data),
                            'decrypted_data_preview' => substr($decrypted_data, 0, 100) . '...',
                            'step' => 'decryption_successful_with_context_iv'
                        ]), 'success', 'Successfully decrypted with IV from context (AesIV param)');
                        return $data;
                    }
                }
            } catch (Exception $e) {
                $logger->log_api_interaction($operation_name, array_merge($context, [
                    'iv_source' => 'context_aes_iv',
                    'decrypt_error' => $e->getMessage(),
                    'step' => 'decryption_failed_with_context_iv'
                ]), 'warning', 'Decryption with context IV failed: ' . $e->getMessage());
            }
        }

        $logger->log_api_interaction($operation_name, array_merge($context, [
            'aes_key_found' => true,
            'aes_key_length' => strlen($aes_key),
            'aes_key_preview' => substr($aes_key, 0, 20) . '...',
            'step' => 'aes_key_obtained'
        ]), 'info', 'AES key obtained for decryption');

        // Try to get IV from headers first
        $iv_from_headers = $this->extract_iv_from_headers($response_headers);
        if ($iv_from_headers) {
            $logger->log_api_interaction($operation_name, array_merge($context, [
                'iv_source' => 'headers',
                'iv_value' => $iv_from_headers,
                'step' => 'attempting_decryption_with_header_iv'
            ]), 'info', 'Attempting decryption with IV from headers');

            try {
                $encryption = $core->encryption;

                // Extract AES key from steganography format if needed
                $binary_aes_key = $aes_key;
                if (ctype_xdigit($aes_key) && strlen($aes_key) === 128) {
                    // Steganography format - extract real AES key using GGKK method
                    $steganography = $core->steganography;
                    $binary_aes_key = $steganography->extract_aes_key_from_steganography($aes_key);
                    $logger->log_api_interaction($operation_name, array_merge($context, [
                        'original_key_length' => strlen($aes_key),
                        'binary_key_length' => strlen($binary_aes_key),
                        'key_converted' => true,
                        'step' => 'aes_key_extracted_from_steganography_header_iv'
                    ]), 'info', 'AES key extracted from steganography format for header IV');
                } elseif (preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $aes_key)) {
                    // Base64 format - decode to binary
                    $binary_aes_key = base64_decode($aes_key);
                    $logger->log_api_interaction($operation_name, array_merge($context, [
                        'original_key_length' => strlen($aes_key),
                        'binary_key_length' => strlen($binary_aes_key),
                        'key_converted' => true,
                        'step' => 'aes_key_base64_decoded_header_iv'
                    ]), 'info', 'AES key converted from base64 to binary for header IV');
                }

                $decrypted_data = $encryption->decrypt_with_aes($encrypted_data, $binary_aes_key, $iv_from_headers);

                if ($this->is_valid_json_start($decrypted_data)) {
                    $data = json_decode($decrypted_data, true);
                    if ($data !== null) {
                        $logger->log_api_interaction($operation_name, array_merge($context, [
                            'iv_source' => 'headers',
                            'decrypted_data_length' => strlen($decrypted_data),
                            'decrypted_data_preview' => substr($decrypted_data, 0, 100) . '...',
                            'step' => 'decryption_successful_with_header_iv'
                        ]), 'success', 'Successfully decrypted with IV from headers');
                        return $data;
                    }
                }
            } catch (Exception $e) {
                $logger->log_api_interaction($operation_name, array_merge($context, [
                    'iv_source' => 'headers',
                    'decrypt_error' => $e->getMessage(),
                    'step' => 'decryption_failed_with_header_iv'
                ]), 'warning', 'Decryption with header IV failed: ' . $e->getMessage());
            }
        } else {
            $logger->log_api_interaction($operation_name, array_merge($context, [
                'step' => 'no_iv_in_headers'
            ]), 'info', 'No IV found in headers, trying multiple IV strategies');
        }

        // If header IV failed, try multiple IV strategies
        $decrypted_data = $this->attempt_decryption_with_multiple_ivs($encrypted_data, $aes_key, $operation_name, $context);
        if (!$decrypted_data) {
            $logger->log_api_interaction($operation_name, array_merge($context, [
                'step' => 'all_decryption_attempts_failed'
            ]), 'error', 'All decryption attempts failed');
            return null;
        }

        // Try to parse decrypted data as JSON
        $data = json_decode($decrypted_data, true);
        if ($data === null) {
            $logger->log_api_interaction($operation_name, array_merge($context, [
                'decrypted_data' => $decrypted_data,
                'json_error' => json_last_error_msg(),
                'step' => 'decrypted_but_not_json'
            ]), 'error', 'Decryption successful but result is not valid JSON');
            return null;
        }

        $logger->log_api_interaction($operation_name, array_merge($context, [
            'response_type' => 'encrypted_json',
            'decrypted_data_length' => strlen($decrypted_data),
            'parsed_data_type' => gettype($data),
            'step' => 'decryption_and_parsing_successful'
        ]), 'success', 'Successfully decrypted and parsed encrypted JSON response');

        return $data;
    }

    /**
     * Extract IV from response headers
     *
     * @param array $headers Response headers
     * @return string|null Base64 encoded IV or null if not found
     */
    private function extract_iv_from_headers(array $headers): ?string
    {
        // Check for common IV header names
        $iv_header_names = [
            'X-Encryption-IV',
            'X-AES-IV',
            'X-IV',
            'Encryption-IV',
            'AES-IV',
            'IV'
        ];

        foreach ($iv_header_names as $header_name) {
            if (isset($headers[$header_name])) {
                return $headers[$header_name];
            }
        }

        return null;
    }

    /**
     * Store AES key in multiple locations for redundancy
     *
     * @param string $aes_key AES key to store
     * @param int $user_id User ID for WordPress user meta
     * @return bool True if key was stored successfully
     */
    private function store_aes_key_redundantly(string $aes_key, int $user_id = 0): bool
    {
        $core = Core::get_instance();
        $logger = $core->logger;

        $storage_results = [];

        // 1. Store in session manager
        try {
            $session_manager = new \DIT\Session_Manager();
            $session_manager->update_session_data(['aes_key' => $aes_key]);
            $storage_results['session'] = true;
        } catch (Exception $e) {
            $storage_results['session'] = false;
            $logger->log_api_interaction('AES Key Storage', [
                'location' => 'session',
                'error' => $e->getMessage()
            ], 'warning', 'Failed to store AES key in session');
        }

        // 2. Note: AES key is no longer stored in encryption class
        $storage_results['encryption_class'] = true; // Skipped - no longer needed

        // 3. Store in cookies
        try {
            $customer_id = \DIT\get_customer_id_from_cookies();
            if ($customer_id) {
                \DIT\save_customer_data_to_cookies($customer_id, $aes_key);
                $storage_results['cookies'] = true;
            } else {
                $storage_results['cookies'] = false;
            }
        } catch (Exception $e) {
            $storage_results['cookies'] = false;
            $logger->log_api_interaction('AES Key Storage', [
                'location' => 'cookies',
                'error' => $e->getMessage()
            ], 'warning', 'Failed to store AES key in cookies');
        }

        // 4. Store in WordPress user meta if user ID provided
        if ($user_id > 0) {
            try {
                update_user_meta($user_id, 'dit_aes_key', $aes_key);
                $storage_results['user_meta'] = true;
            } catch (Exception $e) {
                $storage_results['user_meta'] = false;
                $logger->log_api_interaction('AES Key Storage', [
                    'location' => 'user_meta',
                    'user_id' => $user_id,
                    'error' => $e->getMessage()
                ], 'warning', 'Failed to store AES key in user meta');
            }
        } else {
            $storage_results['user_meta'] = false;
        }

        // Log overall storage results
        $successful_storages = array_filter($storage_results);
        $total_storages = count($storage_results);
        $success_rate = count($successful_storages) / $total_storages;

        $logger->log_api_interaction(
            'AES Key Storage',
            [
                'storage_results' => $storage_results,
                'successful_storages' => count($successful_storages),
                'total_storages' => $total_storages,
                'success_rate' => $success_rate,
                'user_id' => $user_id
            ],
            $success_rate > 0.5 ? 'success' : 'warning',
            'AES key storage completed with ' . count($successful_storages) . '/' . $total_storages . ' successful storages'
        );

        return $success_rate > 0.5; // Return true if at least half of storages succeeded
    }

    /**
     * Clear AES key from all storage locations
     *
     * @param int $user_id User ID for WordPress user meta
     * @return bool True if key was cleared successfully
     */
    private function clear_aes_key_from_all_locations(int $user_id = 0): bool
    {
        $core = Core::get_instance();
        $logger = $core->logger;

        $clear_results = [];

        // 1. Clear from session manager
        try {
            $session_manager = new \DIT\Session_Manager();
            $session_manager->update_session_data(['aes_key' => null]);
            $clear_results['session'] = true;
        } catch (Exception $e) {
            $clear_results['session'] = false;
        }

        // 2. Note: AES key is no longer stored in encryption class
        $clear_results['encryption_class'] = true; // Skipped - no longer needed

        // 3. Clear from cookies
        try {
            \DIT\delete_customer_data_from_cookies();
            $clear_results['cookies'] = true;
        } catch (Exception $e) {
            $clear_results['cookies'] = false;
        }

        // 4. Clear from WordPress user meta
        if ($user_id > 0) {
            try {
                delete_user_meta($user_id, 'dit_aes_key');
                $clear_results['user_meta'] = true;
            } catch (Exception $e) {
                $clear_results['user_meta'] = false;
            }
        } else {
            $clear_results['user_meta'] = false;
        }

        $successful_clears = array_filter($clear_results);
        $logger->log_api_interaction('AES Key Clear', [
            'clear_results' => $clear_results,
            'successful_clears' => count($successful_clears),
            'user_id' => $user_id
        ], 'info', 'AES key cleared from ' . count($successful_clears) . ' locations');

        return count($successful_clears) > 0;
    }

    /**
     * Convert subscription time string to seconds
     *
     * @param string $subscription_time Subscription time string (e.g., "365 days", "30 days")
     * @return int Number of seconds
     */
    private function convert_subscription_time_to_seconds(string $subscription_time): int
    {
        $parts = explode(' ', strtolower(trim($subscription_time)));
        if (count($parts) !== 2) {
            return 31536000; // Default: 365 days in seconds
        }

        $value = (int) $parts[0];
        $unit = $parts[1];

        switch ($unit) {
            case 'days':
            case 'day':
                return $value * 24 * 60 * 60;
            case 'hours':
            case 'hour':
                return $value * 60 * 60;
            case 'minutes':
            case 'minute':
                return $value * 60;
            case 'seconds':
            case 'second':
                return $value;
            default:
                return 31536000; // Default: 365 days in seconds
        }
    }

    /**
     * Register a new user (different from customer)
     *
     * @param array $user_data User data to register
     * @param int $customer_id Customer ID that this user belongs to
     * @return int|null User ID or null on failure
     */
    public function register_user(array $user_data, int $customer_id): ?int
    {
        $core = Core::get_instance();
        $logger = $core->logger;
        $encryption = $core->encryption;

        $logger->log_api_interaction('Register User', [
            'customer_id' => $customer_id,
            'user_data_keys' => array_keys($user_data),
            'email' => $user_data['email'] ?? 'not_provided'
        ], 'info', 'Starting user registration process.');

        try {
            // Get RSA key for encryption
            $rsa_key = $this->get_server_rsa_key();
            if (!$rsa_key) {
                throw new Exception('Failed to get server RSA public key for user registration.');
            }

            // Prepare user registration payload
            $payload = [
                'CustomerId' => $customer_id,
                'Name' => $user_data['name'] ?? '',
                'Email' => $user_data['email'] ?? '',
                'Password' => isset($user_data['password']) ? hash('sha256', $user_data['password']) : '',
                'Tools' => $user_data['tools'] ?? [],
                'NameFirst' => $user_data['first_name'] ?? '',
                'NameLast' => $user_data['last_name'] ?? '',
                'Active' => true
            ];

            $json_payload = json_encode($payload);
            if ($json_payload === false) {
                throw new Exception('Failed to encode user registration payload to JSON: ' . json_last_error_msg());
            }

            // Encrypt payload with RSA
            $encrypted_payload = $encryption->encrypt_data_with_rsa($json_payload, $rsa_key);
            if (empty($encrypted_payload)) {
                throw new Exception('Failed to encrypt user registration payload with RSA.');
            }

            $request_url = $this->api_base_url . '/Users/RegisterUser';

            $logger->log_api_interaction('Register User', [
                'request_url' => $request_url,
                'method' => 'PUT',
                'customer_id' => $customer_id,
                'payload_length' => strlen($encrypted_payload)
            ], 'info', 'Sending user registration request.');

            $response = wp_remote_request($request_url, [
                'method' => 'PUT',
                'headers' => [
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/json'
                ],
                'body' => $encrypted_payload,
                'timeout' => 30
            ]);

            if (is_wp_error($response)) {
                throw new Exception('User registration request failed: ' . $response->get_error_message());
            }

            $response_code = wp_remote_retrieve_response_code($response);
            $response_body = wp_remote_retrieve_body($response);

            $logger->log_api_interaction('Register User', [
                'response_code' => $response_code,
                'response_body' => $response_body,
                'customer_id' => $customer_id
            ], $response_code === 200 ? 'success' : 'error', 'User registration response received.');

            if ($response_code !== 200) {
                throw new Exception('User registration failed: HTTP ' . $response_code . ' - ' . $response_body);
            }

            // Parse response
            $response_data = json_decode($response_body, true);
            if (!$response_data) {
                throw new Exception('Invalid user registration response format: not JSON');
            }

            // Check if response is encrypted
            if (isset($response_data['encryptedResponse'])) {
                // Get AES key for decryption directly from customer data
                $aes_key = $this->get_user_permanent_aes_key($customer_id);

                if ($aes_key) {
                    $decrypted_response = $encryption->decrypt_with_aes(
                        $response_data['encryptedResponse'],
                        base64_decode($aes_key),
                        str_repeat("\0", 16) // Default IV
                    );

                    $response_data = json_decode($decrypted_response, true);
                    if (!$response_data) {
                        throw new Exception('Failed to decode decrypted user registration response');
                    }
                }
            }

            if (!isset($response_data['userId'])) {
                throw new Exception('Invalid user registration response format: missing userId');
            }

            $user_id = (int) $response_data['userId'];

            $logger->log_api_interaction('Register User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'email' => $user_data['email'] ?? 'not_provided'
            ], 'success', 'User registered successfully.');

            return $user_id;
        } catch (Exception $e) {
            $logger->log_api_interaction('Register User', [
                'error' => $e->getMessage(),
                'customer_id' => $customer_id,
                'email' => $user_data['email'] ?? 'not_provided'
            ], 'error', 'User registration failed.');
            error_log('DIT Integration: User registration failed - ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Register customer using RSA (новий спрощений підхід)
     * @param array $user_data
     * @return int|null Customer ID or null on failure
     */
    public function register_customer_rsa(array $user_data): ?int
    {
        // ANTI-DUPLICATE PROTECTION: Prevent multiple simultaneous processing of the same email
        static $processing_emails = [];
        $email = $user_data['email'] ?? '';

        if (in_array($email, $processing_emails)) {
            $core = Core::get_instance();
            $logger = $core->logger;

            $logger->log_api_interaction('Register Customer RSA', [
                'step' => 'duplicate_prevented',
                'email' => $email
            ], 'warning', 'Duplicate registration prevented');
            return null;
        }

        $processing_emails[] = $email;

        $core = Core::get_instance();
        $logger = $core->logger;
        $encryption = $core->encryption;

        $logger->log_api_interaction('Register Customer RSA', [
            'step' => 'start',
            'encryption_method' => 'rsa',
            'user_data_keys' => array_keys($user_data)
        ], 'info', 'Registration process started (RSA, single step)');

        try {
            // 1. Generate permanent AES key (256-bit)
            $aes_data = $encryption->generate_aes_key();
            if (!is_array($aes_data) || !isset($aes_data['key'])) {
                throw new Exception('Failed to generate AES key: invalid format returned');
            }
            // Конвертуємо AES-ключ у hex
            $permanent_aes_key_hex = bin2hex($aes_data['key']);
            $logger->log_api_interaction('Register Customer RSA', [
                'step' => 'generate_aes_key',
                'permanent_aes_key_b64' => base64_encode($aes_data['key']),
                'permanent_aes_key_hex' => $permanent_aes_key_hex
            ], 'info', 'Permanent AES key generated (hex)');

            // 2. Clean and validate Tools array
            $cleaned_tools = [];
            if (!empty($user_data['tools']) && is_array($user_data['tools'])) {
                foreach ($user_data['tools'] as $tool) {
                    // Remove newlines, tabs, and extra whitespace
                    $clean_tool = trim(str_replace(["\n", "\r", "\t"], ' ', $tool));
                    // Remove multiple spaces
                    $clean_tool = preg_replace('/\s+/', ' ', $clean_tool);
                    if (!empty($clean_tool)) {
                        $cleaned_tools[] = $clean_tool;
                    }
                }
            }

            // Log cleaned tools for debugging
            $logger->log_api_interaction('Register Customer RSA', [
                'step' => 'clean_tools',
                'original_tools' => $user_data['tools'] ?? [],
                'cleaned_tools' => $cleaned_tools
            ], 'info', 'Tools cleaned and validated');

            // 3. Prepare registration data
            $request_data = [
                'AesKey' => $permanent_aes_key_hex,
                'NameFirst' => $user_data['first_name'] ?? '',
                'NameLast' => $user_data['last_name'] ?? '',
                'Company' => $user_data['company'] ?? '',
                'Email' => $user_data['email'] ?? '',
                'Password' => $user_data['password'] ?? '', // plain text
                'Tools' => $cleaned_tools,
                'Notes' => $user_data['notes'] ?? '',
                'InitialUser' => true,
                'SubscriptionId' => 17
            ];
            $logger->log_api_interaction('Register Customer RSA', [
                'step' => 'prepare_request_data',
                'request_data' => $request_data
            ], 'info', 'Prepared registration data');

            $json_payload = json_encode($request_data);
            if ($json_payload === false) {
                $logger->log_api_interaction('Register Customer RSA', [
                    'step' => 'json_encode_error',
                    'error' => json_last_error_msg()
                ], 'error', 'JSON encoding error');
                throw new Exception('Failed to encode registration request to JSON: ' . json_last_error_msg());
            }

            // 4. Get RSA key
            $rsa_key = $this->get_server_rsa_key();
            if (!$rsa_key) {
                throw new Exception('Failed to get server RSA public key for registration.');
            }
            $logger->log_api_interaction('Register Customer RSA', [
                'step' => 'get_rsa_key',
                'rsa_key_length' => strlen($rsa_key)
            ], 'info', 'RSA key received');

            // 5. Encrypt JSON payload with RSA
            $encrypted_payload = $encryption->encrypt_data_with_rsa($json_payload, $rsa_key);
            if (empty($encrypted_payload)) {
                throw new Exception('Failed to encrypt registration payload with RSA.');
            }

            $logger->log_api_interaction('Register Customer RSA', [
                'step' => 'encrypt_payload',
                'encrypted_payload_length' => strlen($encrypted_payload)
            ], 'info', 'Payload encrypted');

            // Додаємо логування Base64-рядка
            error_log('DIT Integration: Encrypted payload (Base64) for API: ' . $encrypted_payload);

            // Додаткове логування raw body перед відправкою
            error_log('DIT Integration: RAW BODY to RegisterCustomerRSA: ' . $encrypted_payload);

            // 6. Send RegisterCustomerRSA (PUT)
            $register_url = $this->api_base_url . '/Customers/RegisterCustomerRSA';
            $logger->log_api_interaction('Register Customer RSA', [
                'step' => 'send_register_request',
                'register_url' => $register_url,
                'encrypted_payload_length' => strlen($encrypted_payload)
            ], 'info', 'Sending RegisterCustomerRSA');

            $register_response = wp_remote_request($register_url, [
                'method' => 'PUT',
                'headers' => [
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/json'
                ],
                'body' => json_encode($encrypted_payload),
                'timeout' => 30
            ]);

            if (is_wp_error($register_response)) {
                $logger->log_api_interaction('Register Customer RSA', [
                    'step' => 'register_request_error',
                    'error' => $register_response->get_error_message()
                ], 'error', 'RegisterCustomerRSA sending error');
                throw new Exception('Registration request failed: ' . $register_response->get_error_message());
            }

            $register_code = wp_remote_retrieve_response_code($register_response);
            $register_body = wp_remote_retrieve_body($register_response);
            $register_headers = wp_remote_retrieve_headers($register_response);

            // Детальне логування відповіді сервера API
            $logger->log_api_interaction('Register Customer RSA', [
                'step' => 'register_response_received',
                'response_code' => $register_code,
                'response_body' => $register_body,
                'response_body_length' => strlen($register_body),
                'response_headers' => $register_headers,
                'response_success' => $register_code === 200,
                'request_url' => $register_url,
                'request_method' => 'PUT',
                'encrypted_payload_length' => strlen($encrypted_payload)
            ], $register_code === 200 ? 'success' : 'error', 'RegisterCustomerRSA response received from server API');

            // Додаткове логування в error_log для детального аналізу
            error_log('DIT API: === REGISTER CUSTOMER RSA RESPONSE ===');
            error_log('DIT API: Response Code: ' . $register_code);
            error_log('DIT API: Response Body: ' . $register_body);
            error_log('DIT API: Response Body Length: ' . strlen($register_body));
            error_log('DIT API: Response Headers: ' . print_r($register_headers, true));
            error_log('DIT API: Request URL: ' . $register_url);
            error_log('DIT API: Request Method: PUT');
            error_log('DIT API: Encrypted Payload Length: ' . strlen($encrypted_payload));
            error_log('DIT API: === END RESPONSE LOG ===');

            if ($register_code !== 200) {
                // Логування помилки з детальною інформацією про відповідь сервера
                $logger->log_api_interaction('Register Customer RSA', [
                    'step' => 'registration_failed',
                    'response_code' => $register_code,
                    'response_body' => $register_body,
                    'response_body_length' => strlen($register_body),
                    'response_headers' => $register_headers,
                    'request_url' => $register_url,
                    'request_method' => 'PUT',
                    'encrypted_payload_length' => strlen($encrypted_payload),
                    'error_message' => 'HTTP ' . $register_code . ' - ' . $register_body
                ], 'error', 'Customer registration failed with HTTP ' . $register_code);

                error_log('DIT API: === REGISTER CUSTOMER RSA FAILED ===');
                error_log('DIT API: HTTP Error Code: ' . $register_code);
                error_log('DIT API: Error Response Body: ' . $register_body);
                error_log('DIT API: Request URL: ' . $register_url);
                error_log('DIT API: === END ERROR LOG ===');

                throw new Exception('Registration failed: HTTP ' . $register_code . ' - ' . $register_body);
            }

            // 6. Parse response (очікуємо customerId)
            $response_data = json_decode($register_body, true);
            if (is_string($response_data)) {
                $response_data = json_decode($response_data, true);
            }
            if (!isset($response_data['CustomerId'])) {
                $logger->log_api_interaction('Register Customer RSA', [
                    'step' => 'register_response_missing_customerId',
                    'response_data' => $response_data
                ], 'error', 'RegisterCustomerRSA response missing customerId');
                throw new Exception('Invalid response format: missing customerId');
            }

            $customer_id = (int)$response_data['CustomerId'];
            $user_name = $user_data['name'] ?? '';
            $additional_user_data = [
                'first_name' => $user_data['first_name'] ?? '',
                'last_name' => $user_data['last_name'] ?? '',
                'company' => $user_data['company'] ?? '',
                'email' => $user_data['email'] ?? ''
            ];

            // Логування успішної відповіді сервера API
            $logger->log_api_interaction('Register Customer RSA', [
                'step' => 'registration_success',
                'customer_id' => $customer_id,
                'response_data' => $response_data,
                'response_data_keys' => array_keys($response_data),
                'response_body_original' => $register_body,
                'response_body_length' => strlen($register_body),
                'response_headers' => $register_headers,
                'request_url' => $register_url,
                'request_method' => 'PUT',
                'encrypted_payload_length' => strlen($encrypted_payload),
                'user_email' => $user_data['email'] ?? 'not_provided'
            ], 'success', 'Customer registration successful - response parsed from server API');

            error_log('DIT API: === REGISTER CUSTOMER RSA SUCCESS ===');
            error_log('DIT API: Customer ID: ' . $customer_id);
            error_log('DIT API: Response Data: ' . print_r($response_data, true));
            error_log('DIT API: Response Data Keys: ' . implode(', ', array_keys($response_data)));
            error_log('DIT API: Original Response Body: ' . $register_body);
            error_log('DIT API: User Email: ' . ($user_data['email'] ?? 'not_provided'));
            error_log('DIT API: === END SUCCESS LOG ===');

            // Зберігаємо AES-ключ в сесії замість WordPress settings
            if (!isset($_SESSION['dit_aes_keys'])) {
                $_SESSION['dit_aes_keys'] = [];
            }
            $_SESSION['dit_aes_keys'][$customer_id] = base64_encode($aes_data['key']);

            // Note: Cookies removed - AES key stored only in session

            $logger->log_api_interaction('Register Customer RSA', [
                'step' => 'aes_key_saved_to_session',
                'customer_id' => $customer_id,
                'aes_key_saved' => true,
                'session_keys_count' => count($_SESSION['dit_aes_keys']),
                'cookie_set' => false
            ], 'info', 'AES key saved to session only (cookies removed)');

            $logger->log_api_interaction('Register Customer RSA', [
                'customer_id' => $customer_id,
                'encryption_method' => 'rsa',
                'response_decrypted' => true,
                'user_first_name' => $additional_user_data['first_name'],
                'user_last_name' => $additional_user_data['last_name'],
                'user_company' => $additional_user_data['company'],
                'user_email' => $additional_user_data['email'],
                'aes_key_saved_to_session' => true,
                'session_keys_count' => count($_SESSION['dit_aes_keys'])
            ], 'success', 'Customer registered and AES key saved to session');

            // Логування довжини та частини base64-рядка перед відправкою
            $logger->log_api_interaction('Register Customer RSA', [
                'step' => 'pre_send_base64',
                'base64_length' => strlen($encrypted_payload),
                'base64_start' => substr($encrypted_payload, 0, 50),
                'base64_end' => substr($encrypted_payload, -50),
            ], 'info', 'Base64 payload preview before sending');

            // Додаємо логування Base64-рядка через логер
            $logger->log_api_interaction('Register Customer RSA', [
                'step' => 'base64_payload',
                'encrypted_payload_base64' => $encrypted_payload,
                'base64_length' => strlen($encrypted_payload),
                'base64_preview_start' => substr($encrypted_payload, 0, 50),
                'base64_preview_end' => substr($encrypted_payload, -50)
            ], 'info', 'Base64 payload for API (full)');

            return $customer_id;
        } catch (\Exception $e) {
            $logger->log_api_interaction('Register Customer RSA', [
                'step' => 'exception',
                'error' => $e->getMessage()
            ], 'error', 'Failed to register customer: ' . $e->getMessage());
            error_log('DIT Integration: Failed to register customer - ' . $e->getMessage());
            return null;
        } finally {
            // ANTI-DUPLICATE CLEANUP: Remove email from processing array
            $key = array_search($email, $processing_emails);
            if ($key !== false) {
                unset($processing_emails[$key]);
            }
        }
    }

    /**
     * Register user using RSA 
     * @param array $user_data
     * @param int $customer_id
     * @return int|null User ID or null on failure
     */
    public function register_user_rsa(array $user_data, int $customer_id): ?int
    {
        $core = Core::get_instance();
        $logger = $core->logger;
        $encryption = $core->encryption;

        $logger->log_api_interaction('Register User RSA', [
            'customer_id' => $customer_id,
            'user_data_keys' => array_keys($user_data),
            'email' => $user_data['email'] ?? 'not_provided',
            'step' => 'start'
        ], 'info', 'Starting user registration process (RSA)');

        try {
            // Get RSA key for encryption
            $rsa_key = $this->get_server_rsa_key();
            if (!$rsa_key) {
                throw new \Exception('Failed to get server RSA public key for user registration.');
            }

            // Prepare user registration payload
            $payload = [
                'CustomerId' => $customer_id,
                'NameFirst' => $user_data['first_name'] ?? '',
                'NameLast' => $user_data['last_name'] ?? '',
                'Email' => $user_data['email'] ?? '',
                'Password' => $user_data['password'] ?? '', // plain text
                'AesKey' => $user_data['aes_key'] ?? '',
                'Tools' => $user_data['tools'] ?? []
            ];

            $json_payload = json_encode($payload);
            if ($json_payload === false) {
                throw new \Exception('Failed to encode user registration payload to JSON: ' . json_last_error_msg());
            }

            // Encrypt payload with RSA
            $encrypted_payload = $encryption->encrypt_data_with_rsa($json_payload, $rsa_key);
            if (empty($encrypted_payload)) {
                throw new \Exception('Failed to encrypt user registration payload with RSA.');
            }

            $request_url = $this->api_base_url . '/Users/RegisterUserRSA';

            // Send encrypted payload as JSON string (same as customer registration)
            $request_body = json_encode($encrypted_payload);

            $logger->log_api_interaction('Register User RSA', [
                'request_url' => $request_url,
                'method' => 'PUT',
                'customer_id' => $customer_id,
                'payload_length' => strlen($encrypted_payload),
                'request_body_length' => strlen($request_body),
                'request_body_preview' => substr($request_body, 0, 100) . '...',
                'content_type' => 'application/json'
            ], 'info', 'Sending user registration request (RSA) - JSON string format');

            $response = wp_remote_request($request_url, [
                'method' => 'PUT',
                'headers' => [
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/json'
                ],
                'body' => $request_body,
                'timeout' => 30
            ]);

            if (is_wp_error($response)) {
                throw new \Exception('User registration request failed: ' . $response->get_error_message());
            }

            $response_code = wp_remote_retrieve_response_code($response);
            $response_body = wp_remote_retrieve_body($response);
            $response_headers = wp_remote_retrieve_headers($response);

            // Детальне логування відповіді сервера API при реєстрації User
            $logger->log_api_interaction('Register User RSA', [
                'step' => 'user_registration_response_received',
                'response_code' => $response_code,
                'response_body' => $response_body,
                'response_body_length' => strlen($response_body),
                'response_headers' => $response_headers,
                'response_success' => $response_code === 200,
                'request_url' => $request_url,
                'request_method' => 'PUT',
                'encrypted_payload' => $encrypted_payload,
                'encrypted_payload_length' => strlen($encrypted_payload),
                'request_body' => $request_body,
                'request_body_length' => strlen($request_body),
                'customer_id' => $customer_id,
                'user_email' => $user_data['email'] ?? 'not_provided'
            ], $response_code === 200 ? 'success' : 'error', 'User registration response received from server API (RSA)');

            // Додаткове логування в error_log для детального аналізу
            error_log('DIT API: === REGISTER USER RSA RESPONSE ===');
            error_log('DIT API: Response Code: ' . $response_code);
            error_log('DIT API: Response Body: ' . $response_body);
            error_log('DIT API: Response Body Length: ' . strlen($response_body));
            error_log('DIT API: Response Headers: ' . print_r($response_headers, true));
            error_log('DIT API: Request URL: ' . $request_url);
            error_log('DIT API: Request Method: PUT');
            error_log('DIT API: Encrypted Payload Length: ' . strlen($encrypted_payload));
            error_log('DIT API: Request Body Length: ' . strlen($request_body));
            error_log('DIT API: Customer ID: ' . $customer_id);
            error_log('DIT API: User Email: ' . ($user_data['email'] ?? 'not_provided'));
            error_log('DIT API: === END RESPONSE LOG ===');

            if ($response_code !== 200) {
                // Логування помилки з детальною інформацією про відповідь сервера
                $logger->log_api_interaction('Register User RSA', [
                    'step' => 'user_registration_failed',
                    'response_code' => $response_code,
                    'response_body' => $response_body,
                    'response_body_length' => strlen($response_body),
                    'response_headers' => $response_headers,
                    'request_url' => $request_url,
                    'request_method' => 'PUT',
                    'encrypted_payload_length' => strlen($encrypted_payload),
                    'request_body_length' => strlen($request_body),
                    'customer_id' => $customer_id,
                    'user_email' => $user_data['email'] ?? 'not_provided',
                    'error_message' => 'HTTP ' . $response_code . ' - ' . $response_body
                ], 'error', 'User registration failed with HTTP ' . $response_code);

                error_log('DIT API: === REGISTER USER RSA FAILED ===');
                error_log('DIT API: HTTP Error Code: ' . $response_code);
                error_log('DIT API: Error Response Body: ' . $response_body);
                error_log('DIT API: Request URL: ' . $request_url);
                error_log('DIT API: Customer ID: ' . $customer_id);
                error_log('DIT API: User Email: ' . ($user_data['email'] ?? 'not_provided'));
                error_log('DIT API: === END ERROR LOG ===');

                throw new \Exception('User registration failed: HTTP ' . $response_code . ' - ' . $response_body);
            }

            // Parse response (handle doubly-encoded JSON like in customer registration)
            $response_data = json_decode($response_body, true);
            if (is_string($response_data)) {
                $response_data = json_decode($response_data, true);
            }

            if (!$response_data || !isset($response_data['UserId'])) {
                $logger->log_api_interaction('Register User RSA', [
                    'step' => 'response_parsing_error',
                    'response_data' => $response_data,
                    'response_body' => $response_body,
                    'response_keys' => array_keys($response_data ?? [])
                ], 'error', 'Invalid response format: missing UserId');
                throw new \Exception('Invalid response format: missing UserId');
            }

            $user_id = (int) $response_data['UserId'];

            // Логування успішної відповіді сервера API
            $logger->log_api_interaction('Register User RSA', [
                'step' => 'user_registration_success',
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'email' => $user_data['email'] ?? '',
                'response_data' => $response_data,
                'response_data_keys' => array_keys($response_data),
                'response_body_original' => $response_body,
                'response_body_length' => strlen($response_body),
                'response_headers' => $response_headers,
                'request_url' => $request_url,
                'request_method' => 'PUT',
                'encrypted_payload_length' => strlen($encrypted_payload),
                'request_body_length' => strlen($request_body)
            ], 'success', 'User registered successfully - response parsed from server API (RSA)');

            error_log('DIT API: === REGISTER USER RSA SUCCESS ===');
            error_log('DIT API: User ID: ' . $user_id);
            error_log('DIT API: Customer ID: ' . $customer_id);
            error_log('DIT API: Response Data: ' . print_r($response_data, true));
            error_log('DIT API: Response Data Keys: ' . implode(', ', array_keys($response_data)));
            error_log('DIT API: Original Response Body: ' . $response_body);
            error_log('DIT API: User Email: ' . ($user_data['email'] ?? 'not_provided'));
            error_log('DIT API: === END SUCCESS LOG ===');

            return $user_id;
        } catch (\Exception $e) {
            $logger->log_api_interaction('Register User RSA', [
                'customer_id' => $customer_id,
                'email' => $user_data['email'] ?? '',
                'error' => $e->getMessage(),
                'step' => 'exception'
            ], 'error', 'Failed to register user (RSA): ' . $e->getMessage());
            error_log('DIT Integration: User registration failed (RSA) - ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Get user data from API
     *
     * @param int $user_id User ID to retrieve
     * @param int $customer_id Customer ID (PrimaryKey)
     * @return array|null User data or null on failure
     */
    public function get_user(int $user_id, int $customer_id): ?array
    {
        $core = Core::get_instance();
        $logger = $core->logger;
        $encryption = $core->encryption;

        try {
            // Generate 16-byte IV for this request
            $iv = random_bytes(16);
            $iv_hex = bin2hex($iv); // hex-encode the IV as per developer instructions

            // Validate hex string
            if (!ctype_xdigit($iv_hex)) {
                throw new Exception('Generated IV contains non-hex characters: ' . $iv_hex);
            }

            // Form GET request with new CustomerGetUser endpoint - URL encode to ensure proper formatting
            $request_url = $this->api_base_url . '/Users/CustomerGetUser?UserIdSought=' . urlencode($user_id) . '&CustomerIdSeeker=' . urlencode($customer_id) . '&AesIVHex=' . urlencode($iv_hex);

            $logger->log_api_interaction('Get User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'url' => $request_url,
                'iv_hex' => $iv_hex,
                'iv_hex_length' => strlen($iv_hex),
                'iv_hex_valid' => ctype_xdigit($iv_hex),
                'iv_base64_for_decryption' => base64_encode(hex2bin($iv_hex)),
                'endpoint' => 'CustomerGetUser',
                'user_id_sought' => $user_id,
                'customer_id_seeker' => $customer_id,
                'step' => 'request_start'
            ], 'info', 'Starting get user request with new CustomerGetUser endpoint');

            // Get AES key directly from customer-specific storage (session/cookies/user_meta)
            // This is the correct way based on the new architecture where AES keys are stored per customer_id
            $aes_key = $this->get_user_permanent_aes_key($customer_id);

            if (!$aes_key) {
                $logger->log_api_interaction('Get User', [
                    'user_id' => $user_id,
                    'customer_id' => $customer_id,
                    'aes_key_found' => false,
                    'step' => 'customer_aes_key_not_found'
                ], 'error', 'Customer AES key not found for decryption');
                return null;
            }

            $logger->log_api_interaction('Get User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'aes_key_found' => true,
                'aes_key_length' => strlen($aes_key),
                'aes_key_preview' => substr($aes_key, 0, 20) . '...',
                'step' => 'customer_aes_key_obtained'
            ], 'info', 'Customer AES key obtained for decryption');

            $response = wp_remote_get($request_url, [
                'timeout' => 30,
                'sslverify' => true,
                'headers' => [
                    'User-Agent' => 'WordPress/' . get_bloginfo('version') . '; ' . get_bloginfo('url')
                ]
            ]);

            if (is_wp_error($response)) {
                $logger->log_api_interaction('Get User', [
                    'user_id' => $user_id,
                    'customer_id' => $customer_id,
                    'error' => $response->get_error_message(),
                    'step' => 'wp_error'
                ], 'error', 'Get user failed with WordPress error');
                throw new Exception('Failed to get user: ' . $response->get_error_message());
            }

            $response_code = wp_remote_retrieve_response_code($response);
            $body = wp_remote_retrieve_body($response);
            $headers = wp_remote_retrieve_headers($response);

            $logger->log_api_interaction('Get User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'response_code' => $response_code,
                'response_body' => $body,
                'response_headers' => $headers,
                'body_length' => strlen($body),
                'step' => 'response_received'
            ], $response_code === 200 ? 'info' : 'error', 'Get user response received');

            if ($response_code !== 200) {
                $logger->log_api_interaction('Get User', [
                    'user_id' => $user_id,
                    'customer_id' => $customer_id,
                    'response_code' => $response_code,
                    'response_body' => $body,
                    'step' => 'http_error'
                ], 'error', 'Get user failed with HTTP ' . $response_code);
                throw new Exception('Failed to get user: HTTP ' . $response_code);
            }

            // Convert headers to array
            $headers_array = [];
            if (is_object($headers) && method_exists($headers, 'getAll')) {
                $headers_array = $headers->getAll();
            } elseif (is_array($headers)) {
                $headers_array = $headers;
            }

            // Дешифрування: передаємо IV та AES ключ у handle_encrypted_response_with_headers
            $iv_base64_for_decryption = base64_encode(hex2bin($iv_hex));
            $data = $this->handle_encrypted_response_with_headers($body, $headers_array, 'Get User', [
                'user_id' => $customer_id,
                'aes_iv' => $iv_base64_for_decryption,
                'aes_key' => $aes_key
            ]);

            if (!is_array($data)) {
                $logger->log_api_interaction('Get User', [
                    'user_id' => $user_id,
                    'customer_id' => $customer_id,
                    'response_body' => $body,
                    'decoded_data' => $data,
                    'data_type' => gettype($data),
                    'step' => 'type_error'
                ], 'error', 'GetUser API returned unsupported data type: ' . gettype($data));
                throw new Exception('Invalid response format: expected array, got ' . gettype($data));
            }

            $logger->log_api_interaction('Get User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'data_keys' => array_keys($data),
                'step' => 'success'
            ], 'success', 'Successfully retrieved user data');

            return $data;
        } catch (\Exception $e) {
            $logger->log_api_interaction('Get User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'error' => $e->getMessage(),
                'step' => 'exception'
            ], 'error', 'Failed to get user: ' . $e->getMessage());
            error_log('DIT Integration: Get user failed - ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Handle encrypted response using a specific user's AES key
     *
     * @param string $response_body Response body
     * @param array $response_headers Response headers
     * @param string $user_aes_key User's AES key
     * @param string $operation_name Operation name for logging
     * @param array $context Additional context for logging
     * @return array|null Decrypted data or null on failure
     */
    private function handle_encrypted_response_with_user_key(string $response_body, array $response_headers, string $user_aes_key, string $operation_name, array $context = []): ?array
    {
        $core = Core::get_instance();
        $logger = $core->logger;
        $encryption = $core->encryption;

        $logger->log_api_interaction($operation_name, array_merge($context, [
            'response_body' => $response_body,
            'response_headers' => $response_headers,
            'step' => 'encrypted_response_handler_start'
        ]), 'info', 'Starting encrypted response handler with user key');

        // Try to decode as JSON first
        $decoded_data = json_decode($response_body, true);
        if (json_last_error() === JSON_ERROR_NONE && is_array($decoded_data)) {
            $logger->log_api_interaction($operation_name, array_merge($context, [
                'decoded_data' => $decoded_data,
                'step' => 'json_decoded_directly'
            ]), 'success', 'Response was valid JSON, no decryption needed');
            return $decoded_data;
        }

        $logger->log_api_interaction($operation_name, array_merge($context, [
            'json_error' => json_last_error_msg(),
            'step' => 'json_decode_failed_trying_decrypt'
        ]), 'info', 'JSON decode failed, attempting to decrypt response');

        // Check if response looks like encrypted data (base64 string with or without quotes)
        $is_quoted = preg_match('/^"[A-Za-z0-9+\/]+={0,2}"$/', $response_body);
        $is_unquoted = preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $response_body);

        $logger->log_api_interaction($operation_name, array_merge($context, [
            'response_body_preview' => substr($response_body, 0, 50) . '...',
            'is_quoted' => $is_quoted,
            'is_unquoted' => $is_unquoted,
            'step' => 'encrypted_format_check'
        ]), 'info', 'Checking if response is in encrypted format');

        if (!$is_quoted && !$is_unquoted) {
            $logger->log_api_interaction($operation_name, array_merge($context, [
                'response_body' => $response_body,
                'step' => 'invalid_encrypted_format'
            ]), 'error', 'Response does not appear to be encrypted data');
            return null;
        }

        // Remove quotes if present to get the encrypted data
        $encrypted_data = $is_quoted ? trim($response_body, '"') : $response_body;

        $logger->log_api_interaction($operation_name, array_merge($context, [
            'encrypted_data' => $encrypted_data,
            'encrypted_data_length' => strlen($encrypted_data),
            'step' => 'extracted_encrypted_data'
        ]), 'info', 'Extracted encrypted data from response');

        // Get IV from context or try to extract from headers
        $iv = $context['aes_iv'] ?? null;
        if (!$iv) {
            $iv = $this->extract_iv_from_headers($response_headers);
        }

        if ($iv) {
            $logger->log_api_interaction($operation_name, array_merge($context, [
                'aes_iv' => $iv,
                'iv_source' => isset($context['aes_iv']) ? 'context_aes_iv' : 'headers',
                'iv_value' => $iv,
                'iv_length' => strlen($iv),
                'iv_decoded_length' => strlen(base64_decode($iv)),
                'step' => 'attempting_decryption_with_context_iv'
            ]), 'info', 'Attempting decryption with IV from context');

            try {
                // Convert Base64 AES key to binary format
                $binary_aes_key = base64_decode($user_aes_key);
                $logger->log_api_interaction($operation_name, array_merge($context, [
                    'aes_iv' => $iv,
                    'iv_source' => isset($context['aes_iv']) ? 'context_aes_iv' : 'headers',
                    'original_key_length' => strlen($user_aes_key),
                    'binary_key_length' => strlen($binary_aes_key),
                    'original_key_preview' => substr($user_aes_key, 0, 20) . '...',
                    'binary_key_hex' => bin2hex($binary_aes_key),
                    'step' => 'aes_key_converted_to_binary'
                ]), 'info', 'AES key converted from Base64 to binary format');

                // Verify binary key length
                if (strlen($binary_aes_key) !== 32) {
                    throw new \Exception('Binary AES key length is ' . strlen($binary_aes_key) . ' bytes, expected 32 bytes');
                }

                // decrypt_with_aes always expects Base64 IV, so we pass the original Base64 IV
                $logger->log_api_interaction($operation_name, array_merge($context, [
                    'aes_iv' => $iv,
                    'iv_source' => isset($context['aes_iv']) ? 'context_aes_iv' : 'headers',
                    'encrypted_data_length' => strlen($encrypted_data),
                    'binary_key_length' => strlen($binary_aes_key),
                    'iv_length' => strlen($iv),
                    'step' => 'calling_decrypt_with_aes'
                ]), 'info', 'Calling decrypt_with_aes with Base64 IV');

                $decrypted_data = $encryption->decrypt_with_aes($encrypted_data, $binary_aes_key, $iv);
                if ($decrypted_data) {
                    $logger->log_api_interaction($operation_name, array_merge($context, [
                        'aes_iv' => $iv,
                        'iv_source' => isset($context['aes_iv']) ? 'context_aes_iv' : 'headers',
                        'decrypted_data_length' => strlen($decrypted_data),
                        'decrypted_data_preview' => substr($decrypted_data, 0, 100) . '...',
                        'step' => 'decryption_successful_with_context_iv'
                    ]), 'success', 'Successfully decrypted with IV from context');

                    $decoded_data = json_decode($decrypted_data, true);
                    if (json_last_error() === JSON_ERROR_NONE) {
                        $logger->log_api_interaction($operation_name, array_merge($context, [
                            'decoded_data' => $decoded_data,
                            'step' => 'json_decoded'
                        ]), 'success', $operation_name . ' JSON decoded successfully');
                        return $decoded_data;
                    } else {
                        $logger->log_api_interaction($operation_name, array_merge($context, [
                            'decrypted_data' => $decrypted_data,
                            'json_error' => json_last_error_msg(),
                            'step' => 'json_decode_failed_after_decryption'
                        ]), 'error', 'Failed to decode decrypted data as JSON');
                    }
                }
            } catch (\Exception $e) {
                $logger->log_api_interaction($operation_name, array_merge($context, [
                    'aes_iv' => $iv,
                    'iv_source' => isset($context['aes_iv']) ? 'context_aes_iv' : 'headers',
                    'decrypt_error' => $e->getMessage(),
                    'step' => 'decryption_failed_with_context_iv'
                ]), 'warning', 'Decryption with context IV failed: ' . $e->getMessage());
            }
        }

        $logger->log_api_interaction($operation_name, array_merge($context, [
            'step' => 'decryption_failed'
        ]), 'error', 'All decryption attempts failed');

        return null;
    }

    /**
     * Get AES key for a specific user
     *
     * @param int $user_id User ID
     * @param int $customer_id Customer ID
     * @return string|null AES key or null if not found
     */
    private function get_user_aes_key(int $user_id, int $customer_id): ?string
    {
        $core = Core::get_instance();
        $logger = $core->logger;

        try {
            // Get user data from the list of users for this customer
            $users = $this->get_users_for_customer($customer_id);

            if (is_array($users)) {
                foreach ($users as $user) {
                    if (isset($user['Id']) && $user['Id'] == $user_id && isset($user['AesKey'])) {
                        $logger->log_api_interaction('Get User AES Key', [
                            'user_id' => $user_id,
                            'customer_id' => $customer_id,
                            'aes_key_found' => true,
                            'aes_key_length' => strlen($user['AesKey']),
                            'source' => 'users_list',
                            'step' => 'found_in_users_list'
                        ], 'info', 'Found user AES key in users list');
                        return $user['AesKey'];
                    }
                }
            }

            // If not found in users list, try to get from user meta or other sources
            $logger->log_api_interaction('Get User AES Key', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'aes_key_found' => false,
                'source' => 'users_list',
                'step' => 'not_found_in_users_list'
            ], 'warning', 'User AES key not found in users list');

            return null;
        } catch (\Exception $e) {
            $logger->log_api_interaction('Get User AES Key', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'error' => $e->getMessage(),
                'step' => 'exception'
            ], 'error', 'Failed to get user AES key: ' . $e->getMessage());
            return null;
        }
    }

    // --- DEPRECATED: Use register_user_rsa instead ---
    /*
    public function register_user(array $user_data, int $customer_id): ?int { throw new \Exception('Deprecated: use register_user_rsa'); }
    */

    private function compare_with_working_aes_key(int $customer_id, string $current_key): void
    {
        $core = Core::get_instance();
        $logger = $core->logger;

        try {
            // Get the working AES key directly from customer data
            $working_aes_key = $this->get_user_permanent_aes_key($customer_id);

            // Log comparison
            $logger->log_api_interaction('AES Key Comparison with Working Key', [
                'customer_id' => $customer_id,
                'current_key_found' => !empty($current_key),
                'current_key_length' => strlen($current_key),
                'current_key_preview' => substr($current_key, 0, 20) . '...',
                'working_key_found' => !empty($working_aes_key),
                'working_key_length' => $working_aes_key ? strlen($working_aes_key) : 0,
                'working_key_preview' => $working_aes_key ? substr($working_aes_key, 0, 20) . '...' : null,
                'keys_identical' => $current_key === $working_aes_key,
                'keys_same_length' => strlen($current_key) === ($working_aes_key ? strlen($working_aes_key) : 0),
                'current_key_base64_valid' => base64_decode($current_key, true) !== false,
                'working_key_base64_valid' => $working_aes_key ? (base64_decode($working_aes_key, true) !== false) : false,
                'current_key_binary_length' => strlen(base64_decode($current_key, true)),
                'working_key_binary_length' => $working_aes_key ? strlen(base64_decode($working_aes_key, true)) : 0,
                'step' => 'working_key_comparison'
            ], 'info', 'Comparing current AES key with working key from GetUsersForCustomer');

            // Test decryption with working key if different
            if ($working_aes_key && $current_key !== $working_aes_key) {
                $logger->log_api_interaction('AES Key Comparison with Working Key', [
                    'customer_id' => $customer_id,
                    'message' => 'Keys are different - working key available for testing',
                    'step' => 'different_keys_detected'
                ], 'warning', 'Current key differs from working key - potential issue identified');
            }
        } catch (\Exception $e) {
            $logger->log_api_interaction('AES Key Comparison with Working Key', [
                'customer_id' => $customer_id,
                'error' => $e->getMessage(),
                'step' => 'comparison_exception'
            ], 'error', 'Exception during working key comparison: ' . $e->getMessage());
        }
    }



    private function compare_decryption_parameters(string $operation_name, array $context, string $aes_key, string $encrypted_data, string $iv_base64): void
    {
        $core = Core::get_instance();
        $logger = $core->logger;

        try {
            // Log detailed decryption parameters
            $logger->log_api_interaction('Decryption Parameters Analysis', [
                'operation_name' => $operation_name,
                'customer_id' => $context['customer_id'] ?? null,
                'user_id' => $context['user_id'] ?? null,
                'aes_key_length' => strlen($aes_key),
                'aes_key_preview' => substr($aes_key, 0, 20) . '...',
                'aes_key_binary_length' => (ctype_xdigit($aes_key) && strlen($aes_key) === 128) ? 32 : strlen(base64_decode($aes_key, true)),
                'encrypted_data_length' => strlen($encrypted_data),
                'encrypted_data_preview' => substr($encrypted_data, 0, 50) . '...',
                'iv_base64_length' => strlen($iv_base64),
                'iv_binary_length' => strlen(base64_decode($iv_base64, true)),
                'iv_preview' => substr($iv_base64, 0, 20) . '...',
                'openssl_cipher_methods' => openssl_get_cipher_methods(),
                'openssl_available' => function_exists('openssl_decrypt'),
                'step' => 'decryption_parameters_analysis'
            ], 'info', 'Analyzing decryption parameters for ' . $operation_name);

            // Test different decryption approaches
            $this->test_decryption_approaches($operation_name, $context, $aes_key, $encrypted_data, $iv_base64);
        } catch (\Exception $e) {
            $logger->log_api_interaction('Decryption Parameters Analysis', [
                'operation_name' => $operation_name,
                'error' => $e->getMessage(),
                'step' => 'analysis_exception'
            ], 'error', 'Exception during decryption parameters analysis: ' . $e->getMessage());
        }
    }

    private function test_decryption_approaches(string $operation_name, array $context, string $aes_key, string $encrypted_data, string $iv_base64): void
    {
        $core = Core::get_instance();
        $logger = $core->logger;

        try {
            // Extract AES key properly based on format
            if (ctype_xdigit($aes_key) && strlen($aes_key) === 128) {
                // Steganography format - extract real AES key
                $steganography = $core->steganography;
                $aes_key_binary = $steganography->extract_aes_key_from_steganography($aes_key);
            } else {
                // Base64 format
                $aes_key_binary = base64_decode($aes_key, true);
            }
            $iv_binary = base64_decode($iv_base64, true);

            // Test 1: Standard AES-256-CBC
            $decrypted1 = openssl_decrypt(
                $encrypted_data,
                'AES-256-CBC',
                $aes_key_binary,
                OPENSSL_RAW_DATA,
                $iv_binary
            );

            // Test 2: AES-256-CBC with zero padding (GetUser uses this)
            $decrypted2 = openssl_decrypt(
                $encrypted_data,
                'AES-256-CBC',
                $aes_key_binary,
                OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
                $iv_binary
            );

            // Test 3: AES-256-CBC (in case it's actually 256-bit)
            $decrypted3 = openssl_decrypt(
                $encrypted_data,
                'AES-256-CBC',
                substr($aes_key_binary, 0, 16),
                OPENSSL_RAW_DATA,
                $iv_binary
            );

            // Test 4: AES-256-CBC with zero padding
            $decrypted4 = openssl_decrypt(
                $encrypted_data,
                'AES-256-CBC',
                substr($aes_key_binary, 0, 16),
                OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
                $iv_binary
            );

            $logger->log_api_interaction('Decryption Approaches Test', [
                'operation_name' => $operation_name,
                'customer_id' => $context['customer_id'] ?? null,
                'test1_aes256cbc_success' => $decrypted1 !== false,
                'test1_result_length' => $decrypted1 !== false ? strlen($decrypted1) : 0,
                'test1_result_preview' => $decrypted1 !== false ? substr($decrypted1, 0, 50) . '...' : null,
                'test2_aes256cbc_zeropadding_success' => $decrypted2 !== false,
                'test2_result_length' => $decrypted2 !== false ? strlen($decrypted2) : 0,
                'test2_result_preview' => $decrypted2 !== false ? substr($decrypted2, 0, 50) . '...' : null,
                'test3_aes128cbc_success' => $decrypted3 !== false,
                'test3_result_length' => $decrypted3 !== false ? strlen($decrypted3) : 0,
                'test4_aes128cbc_zeropadding_success' => $decrypted4 !== false,
                'test4_result_length' => $decrypted4 !== false ? strlen($decrypted4) : 0,
                'step' => 'decryption_approaches_test'
            ], 'info', 'Testing different decryption approaches for ' . $operation_name);
        } catch (\Exception $e) {
            $logger->log_api_interaction('Decryption Approaches Test', [
                'operation_name' => $operation_name,
                'error' => $e->getMessage(),
                'step' => 'test_exception'
            ], 'error', 'Exception during decryption approaches test: ' . $e->getMessage());
        }
    }

    private function test_decryption_with_working_key(string $encrypted_data, string $iv_base64, int $customer_id): bool
    {
        $core = Core::get_instance();
        $logger = $core->logger;

        try {
            // Get the working AES key directly from customer data
            $working_aes_key = $this->get_user_permanent_aes_key($customer_id);

            if (!$working_aes_key) {
                $logger->log_api_interaction('Test Decryption with Working Key', [
                    'customer_id' => $customer_id,
                    'working_key_found' => false,
                    'step' => 'no_working_key_available'
                ], 'warning', 'No working AES key available for testing');
                return false;
            }

            // Extract AES key from steganography format if needed
            $working_key_binary = $working_aes_key;
            if (ctype_xdigit($working_aes_key) && strlen($working_aes_key) === 128) {
                // Steganography format - extract real AES key
                $steganography = $core->steganography;
                $working_key_binary = $steganography->extract_aes_key_from_steganography($working_aes_key);
                if ($working_key_binary === null) {
                    $logger->log_api_interaction('Test Decryption with Working Key', [
                        'customer_id' => $customer_id,
                        'working_key_extract_failed' => true,
                        'step' => 'working_key_extract_failed'
                    ], 'error', 'Failed to extract AES key from steganography');
                    return false;
                }
            } elseif (preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $working_aes_key)) {
                // Base64 format - decode to binary
                $working_key_binary = base64_decode($working_aes_key, true);
                if ($working_key_binary === false) {
                    $logger->log_api_interaction('Test Decryption with Working Key', [
                        'customer_id' => $customer_id,
                        'working_key_invalid_base64' => true,
                        'step' => 'working_key_invalid_base64'
                    ], 'error', 'Working key is not valid base64');
                    return false;
                }
            }

            // Convert IV from base64 to binary
            $iv_binary = base64_decode($iv_base64, true);
            if ($iv_binary === false) {
                $logger->log_api_interaction('Test Decryption with Working Key', [
                    'customer_id' => $customer_id,
                    'iv_invalid_base64' => true,
                    'step' => 'iv_invalid_base64'
                ], 'error', 'IV is not valid base64');
                return false;
            }

            // Attempt decryption with working key
            $decrypted = openssl_decrypt(
                $encrypted_data,
                'AES-256-CBC',
                $working_key_binary,
                OPENSSL_RAW_DATA,
                $iv_binary
            );

            $success = $decrypted !== false;

            $logger->log_api_interaction('Test Decryption with Working Key', [
                'customer_id' => $customer_id,
                'working_key_length' => strlen($working_aes_key),
                'working_key_binary_length' => strlen($working_key_binary),
                'working_key_preview' => substr($working_aes_key, 0, 20) . '...',
                'iv_length' => strlen($iv_base64),
                'iv_binary_length' => strlen($iv_binary),
                'encrypted_data_length' => strlen($encrypted_data),
                'decryption_success' => $success,
                'decrypted_length' => $success ? strlen($decrypted) : 0,
                'decrypted_preview' => $success ? substr($decrypted, 0, 50) . '...' : null,
                'step' => 'working_key_decryption_test'
            ], $success ? 'success' : 'error', 'Test decryption with working key ' . ($success ? 'SUCCEEDED' : 'FAILED'));

            return $success;
        } catch (\Exception $e) {
            $logger->log_api_interaction('Test Decryption with Working Key', [
                'customer_id' => $customer_id,
                'error' => $e->getMessage(),
                'step' => 'test_exception'
            ], 'error', 'Exception during working key decryption test: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Update user data via API
     *
     * @param int $user_id User ID to update
     * @param int $customer_id Customer ID
     * @param array $user_data User data to update
     * @return array|null Updated user data or null on failure
     */
    public function update_user(int $user_id, int $customer_id, array $user_data): ?array
    {
        $core = Core::get_instance();
        $logger = $core->logger;
        $encryption = $core->encryption;

        try {
            // Generate 16-byte IV for this request
            $iv = random_bytes(16);
            $iv_hex = bin2hex($iv);

            // Validate hex string
            if (!ctype_xdigit($iv_hex)) {
                throw new Exception('Generated IV contains non-hex characters: ' . $iv_hex);
            }

            // Prepare user data for encryption
            $data_to_encrypt = [
                'UserId' => $user_id,
                'NameFirst' => $user_data['first_name'] ?? '',
                'NameLast' => $user_data['last_name'] ?? '',
                'Email' => $user_data['email'] ?? '',
                'Tools' => array_map('intval', $user_data['tools'] ?? [])
            ];

            // Add password only if provided
            if (!empty($user_data['password'])) {
                $data_to_encrypt['Password'] = $user_data['password'];
            }

            $logger->log_api_interaction('Update User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'data_to_encrypt' => $data_to_encrypt,
                'data_keys' => array_keys($data_to_encrypt),
                'password_included' => !empty($user_data['password']),
                'step' => 'data_prepared'
            ], 'info', 'User data prepared for encryption');

            // Convert to JSON
            $json_data = json_encode($data_to_encrypt);
            $json_error = json_last_error();
            $json_error_msg = json_last_error_msg();

            if ($json_error !== JSON_ERROR_NONE) {
                throw new Exception('Failed to encode user data to JSON: ' . $json_error_msg);
            }

            $logger->log_api_interaction('Update User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'json_data' => $json_data,
                'json_error' => $json_error,
                'json_error_msg' => $json_error_msg,
                'json_length' => strlen($json_data),
                'step' => 'json_encoded'
            ], 'info', 'User data encoded to JSON');

            // Get AES key directly from customer-specific storage
            $logger->log_api_interaction('Update User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'step' => 'before_get_aes_key',
                'session_id' => session_id(),
                'session_status' => session_status() === PHP_SESSION_ACTIVE ? 'Active' : 'Inactive',
                'session_data_keys' => isset($_SESSION) ? array_keys($_SESSION) : [],
                'dit_aes_keys_exists' => isset($_SESSION['dit_aes_keys']),
                'dit_aes_keys_count' => isset($_SESSION['dit_aes_keys']) ? count($_SESSION['dit_aes_keys']) : 0,
                'dit_aes_keys_customer_exists' => isset($_SESSION['dit_aes_keys'][$customer_id]),
                'login_aes_key_exists' => isset($_SESSION['login_aes_key']),
                'login_aes_key_length' => isset($_SESSION['login_aes_key']) ? strlen($_SESSION['login_aes_key']) : 0,
                'note' => 'Cookies removed - AES keys stored only in session'
            ], 'info', 'About to retrieve AES key for customer ' . $customer_id . ' (cookies disabled)');

            $aes_key = $this->get_user_permanent_aes_key($customer_id);

            if (!$aes_key) {
                $logger->log_api_interaction('Update User', [
                    'user_id' => $user_id,
                    'customer_id' => $customer_id,
                    'aes_key_found' => false,
                    'aes_key_source' => 'get_user_permanent_aes_key',
                    'step' => 'aes_key_not_found'
                ], 'error', 'No AES key found for customer ' . $customer_id);
            } else {
                $logger->log_api_interaction('Update User', [
                    'user_id' => $user_id,
                    'customer_id' => $customer_id,
                    'aes_key_found' => true,
                    'aes_key_source' => 'get_user_permanent_aes_key',
                    'aes_key_length' => strlen($aes_key),
                    'aes_key_type' => (ctype_xdigit($aes_key) ? 'hex' : 'binary'),
                    'aes_key_preview' => (strlen($aes_key) <= 32 ? bin2hex(substr($aes_key, 0, 8)) . '...' : substr($aes_key, 0, 20) . '...'),
                    'step' => 'aes_key_retrieved'
                ], 'info', 'AES key retrieved for customer ' . $customer_id);
            }

            if (!$aes_key) {
                $logger->log_api_interaction('Update User', [
                    'user_id' => $user_id,
                    'customer_id' => $customer_id,
                    'aes_key_found' => false,
                    'step' => 'customer_aes_key_not_found'
                ], 'error', 'Customer AES key not found for encryption');
                return null;
            }

            // Convert base64 AES key to binary if needed
            $aes_key_original_length = strlen($aes_key);
            $aes_key_binary_length = mb_strlen($aes_key, '8bit');

            $logger->log_api_interaction('Update User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'aes_key_original_length' => $aes_key_original_length,
                'aes_key_binary_length' => $aes_key_binary_length,
                'aes_key_preview' => substr($aes_key, 0, 20) . '...',
                'step' => 'aes_key_analysis'
            ], 'info', 'AES key analysis before conversion');

            // If key is base64 encoded (44 characters), decode it to binary
            if ($aes_key_original_length === 44 && $aes_key_binary_length === 44) {
                $aes_key_binary = base64_decode($aes_key);
                if ($aes_key_binary === false) {
                    throw new Exception('Failed to decode base64 AES key');
                }
                $aes_key = $aes_key_binary;

                $logger->log_api_interaction('Update User', [
                    'user_id' => $user_id,
                    'customer_id' => $customer_id,
                    'aes_key_converted' => true,
                    'aes_key_binary_length_after' => mb_strlen($aes_key, '8bit'),
                    'step' => 'aes_key_converted'
                ], 'info', 'AES key converted from base64 to binary');
            }

            // Encrypt the data
            $iv_base64 = base64_encode($iv);
            $encrypted_data = $encryption->encrypt_with_aes($json_data, $aes_key, $iv_base64);

            if (!$encrypted_data) {
                throw new Exception('Failed to encrypt user data');
            }

            $logger->log_api_interaction('Update User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'iv_base64' => $iv_base64,
                'iv_hex' => $iv_hex,
                'encrypted_data_length' => strlen($encrypted_data),
                'encrypted_data_preview' => substr($encrypted_data, 0, 50) . '...',
                'aes_key_final_length' => mb_strlen($aes_key, '8bit'),
                'step' => 'data_encrypted'
            ], 'info', 'User data encrypted successfully');

            // ЛОГУВАННЯ ЗМІННИХ ПЕРЕД СТВОРЕННЯМ REQUEST_PAYLOAD
            $logger->log_api_interaction('Update User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'step' => 'variables_before_payload',
                'variables_analysis' => [
                    'customer_id' => [
                        'value' => $customer_id,
                        'type' => gettype($customer_id),
                        'is_null' => is_null($customer_id),
                        'is_int' => is_int($customer_id),
                        'is_numeric' => is_numeric($customer_id)
                    ],
                    'iv_hex' => [
                        'value' => $iv_hex,
                        'type' => gettype($iv_hex),
                        'is_string' => is_string($iv_hex),
                        'length' => strlen($iv_hex),
                        'is_hex' => ctype_xdigit($iv_hex),
                        'is_empty' => empty($iv_hex)
                    ],
                    'encrypted_data' => [
                        'value_preview' => substr($encrypted_data, 0, 50) . '...',
                        'type' => gettype($encrypted_data),
                        'is_string' => is_string($encrypted_data),
                        'length' => strlen($encrypted_data),
                        'is_empty' => empty($encrypted_data),
                        'is_binary' => !ctype_print($encrypted_data)
                    ]
                ],
                'all_variables_valid' => !is_null($customer_id) && is_int($customer_id) &&
                    is_string($iv_hex) && !empty($iv_hex) && ctype_xdigit($iv_hex) &&
                    is_string($encrypted_data) && !empty($encrypted_data)
            ], 'info', 'Variables validation before creating request payload');

            // Prepare request payload with base64 encoded encrypted data
            $encrypted_data_base64 = base64_encode($encrypted_data);

            // IMPORTANT: aesIVHex now contains IV instead of AES key
            // This allows the server to generate AES key using the provided IV

            $logger->log_api_interaction('Update User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'step' => 'base64_encoding',
                'encrypted_data_length' => strlen($encrypted_data),
                'encrypted_data_base64_length' => strlen($encrypted_data_base64),
                'base64_encoding_success' => !empty($encrypted_data_base64),
                'base64_encoding_valid' => base64_decode($encrypted_data_base64) === $encrypted_data
            ], 'info', 'Base64 encoding of encrypted data');

            $request_payload = [
                'primaryKey' => $customer_id,
                'type' => 2,
                'aesIVHex' => $iv_hex, // Передаємо IV замість AES ключа
                'encryptedData' => $encrypted_data_base64
            ];

            // ЛОГУВАННЯ СТРУКТУРИ REQUEST_PAYLOAD (aesIVHex тепер містить IV замість AES ключа)
            $logger->log_api_interaction('Update User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'step' => 'request_payload_created',
                'request_payload_structure' => [
                    'primaryKey' => [
                        'value' => $customer_id,
                        'type' => gettype($customer_id),
                        'is_null' => is_null($customer_id),
                        'is_int' => is_int($customer_id)
                    ],
                    'type' => [
                        'value' => 1,
                        'type' => gettype(1),
                        'is_int' => is_int(1)
                    ],
                    'aesIVHex' => [
                        'value' => $iv_hex,
                        'type' => gettype($iv_hex),
                        'is_string' => is_string($iv_hex),
                        'length' => strlen($iv_hex),
                        'is_hex' => ctype_xdigit($iv_hex),
                        'note' => 'Now contains IV instead of AES key'
                    ],
                    'encryptedData' => [
                        'value_preview' => substr($encrypted_data_base64, 0, 50) . '...',
                        'type' => gettype($encrypted_data_base64),
                        'is_string' => is_string($encrypted_data_base64),
                        'length' => strlen($encrypted_data_base64),
                        'is_empty' => empty($encrypted_data_base64),
                        'is_base64' => !empty($encrypted_data_base64) && base64_decode($encrypted_data_base64) !== false
                    ]
                ],
                'all_values_valid' => !is_null($customer_id) && is_int($customer_id) &&
                    is_string($iv_hex) && !empty($iv_hex) &&
                    is_string($encrypted_data) && !empty($encrypted_data) &&
                    is_string($encrypted_data_base64) && !empty($encrypted_data_base64)
            ], 'info', 'Request payload structure validation');

            $logger->log_api_interaction('Update User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'iv_hex' => $iv_hex,
                'iv_hex_length' => strlen($iv_hex),
                'iv_hex_valid' => ctype_xdigit($iv_hex),
                'iv_hex_for_request' => $iv_hex,
                'iv_hex_for_request_length' => strlen($iv_hex),
                'iv_hex_for_request_valid' => ctype_xdigit($iv_hex),
                'encrypted_data_length' => strlen($encrypted_data),
                'encrypted_data_base64_length' => strlen($encrypted_data_base64),
                'data_keys' => array_keys($data_to_encrypt),
                'password_provided' => !empty($user_data['password']),
                'note' => 'aesIVHex now contains IV instead of AES key',
                'step' => 'request_prepared'
            ], 'info', 'Update user request prepared');

            // Send POST request to UpdateUser endpoint
            $request_url = $this->api_base_url . '/Users/UpdateUser';

            // ДЕТАЛЬНЕ ЛОГУВАННЯ ДЛЯ ДІАГНОСТИКИ
            $logger->log_api_interaction('Update User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'step' => 'before_json_encode',
                'request_payload' => $request_payload,
                'request_payload_type' => gettype($request_payload),
                'request_payload_count' => is_array($request_payload) ? count($request_payload) : 'N/A',
                'request_payload_keys' => is_array($request_payload) ? array_keys($request_payload) : 'N/A',
                'primaryKey_type' => gettype($request_payload['primaryKey']),
                'primaryKey_value' => $request_payload['primaryKey'],
                'type_type' => gettype($request_payload['type']),
                'type_value' => $request_payload['type'],
                'aesIVHex_type' => gettype($request_payload['aesIVHex']),
                'aesIVHex_value' => $request_payload['aesIVHex'],
                'aesIVHex_length' => strlen($request_payload['aesIVHex']),
                'aesIVHex_is_hex' => ctype_xdigit($request_payload['aesIVHex']),
                'aesIVHex_note' => 'Now contains IV instead of AES key',
                'encryptedData_type' => gettype($request_payload['encryptedData']),
                'encryptedData_length' => strlen($request_payload['encryptedData']),
                'encryptedData_preview' => substr($request_payload['encryptedData'], 0, 50) . '...',
                'encryptedData_is_base64' => !empty($request_payload['encryptedData']) && base64_decode($request_payload['encryptedData']) !== false
            ], 'info', 'Request payload details before JSON encoding');

            $request_body = json_encode($request_payload);

            // ЛОГУВАННЯ РЕЗУЛЬТАТУ JSON_ENCODE
            $json_encode_error = json_last_error();
            $json_encode_error_msg = json_last_error_msg();

            $logger->log_api_interaction('Update User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'step' => 'after_json_encode',
                'json_encode_success' => $request_body !== false,
                'json_encode_error' => $json_encode_error,
                'json_encode_error_msg' => $json_encode_error_msg,
                'request_body_type' => gettype($request_body),
                'request_body_length' => $request_body !== false ? strlen($request_body) : 'N/A',
                'request_body_preview' => $request_body !== false ? substr($request_body, 0, 100) . '...' : 'N/A',
                'request_body_is_false' => $request_body === false,
                'request_body_is_null' => $request_body === null,
                'request_body_is_bool' => is_bool($request_body)
            ], 'info', 'JSON encoding result analysis');

            // ПЕРЕВІРКА НА ПОМИЛКИ JSON_ENCODE
            if ($request_body === false) {
                $logger->log_api_interaction('Update User', [
                    'user_id' => $user_id,
                    'customer_id' => $customer_id,
                    'step' => 'json_encode_failed',
                    'json_error' => $json_encode_error,
                    'json_error_msg' => $json_encode_error_msg,
                    'request_payload_debug' => var_export($request_payload, true)
                ], 'error', 'JSON encoding failed for request payload');
                throw new Exception('Failed to encode request payload to JSON: ' . $json_encode_error_msg);
            }

            $logger->log_api_interaction('Update User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'request_url' => $request_url,
                'request_body_length' => strlen($request_body),
                'request_payload' => $request_payload,
                'step' => 'request_sending'
            ], 'info', 'Sending POST request to UpdateUser endpoint');

            // ДЕТАЛЬНЕ ЛОГУВАННЯ ПАРАМЕТРІВ WP_REMOTE_POST
            $wp_remote_params = [
                'timeout' => 30,
                'sslverify' => true,
                'headers' => [
                    'Content-Type' => 'application/json',
                    'User-Agent' => 'WordPress/' . get_bloginfo('version') . '; ' . get_bloginfo('url')
                ],
                'body' => $request_body
            ];

            $logger->log_api_interaction('Update User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'step' => 'wp_remote_post_params',
                'wp_remote_params' => $wp_remote_params,
                'body_type' => gettype($wp_remote_params['body']),
                'body_is_string' => is_string($wp_remote_params['body']),
                'body_is_array' => is_array($wp_remote_params['body']),
                'body_is_bool' => is_bool($wp_remote_params['body']),
                'body_is_null' => is_null($wp_remote_params['body']),
                'body_length' => is_string($wp_remote_params['body']) ? strlen($wp_remote_params['body']) : 'N/A',
                'body_preview' => is_string($wp_remote_params['body']) ? substr($wp_remote_params['body'], 0, 100) . '...' : 'N/A'
            ], 'info', 'wp_remote_post parameters analysis');

            $response = wp_remote_post($request_url, $wp_remote_params);

            // ЛОГУВАННЯ РЕЗУЛЬТАТУ WP_REMOTE_POST
            $logger->log_api_interaction('Update User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'step' => 'wp_remote_post_result',
                'response_type' => gettype($response),
                'response_is_wp_error' => is_wp_error($response),
                'response_is_array' => is_array($response),
                'response_is_null' => is_null($response),
                'response_is_bool' => is_bool($response),
                'response_is_string' => is_string($response),
                'response_is_object' => is_object($response),
                'response_class' => is_object($response) ? get_class($response) : 'N/A',
                'response_count' => is_array($response) ? count($response) : 'N/A',
                'response_keys' => is_array($response) ? array_keys($response) : 'N/A'
            ], 'info', 'wp_remote_post result analysis');

            if (is_wp_error($response)) {
                $logger->log_api_interaction('Update User', [
                    'user_id' => $user_id,
                    'customer_id' => $customer_id,
                    'step' => 'wp_error_detailed',
                    'error_message' => $response->get_error_message(),
                    'error_code' => $response->get_error_code(),
                    'error_data' => $response->get_error_data(),
                    'response_object_class' => get_class($response),
                    'response_object_methods' => get_class_methods($response),
                    'step' => 'wp_error'
                ], 'error', 'Update user failed with WordPress error - detailed analysis');
                throw new Exception('Failed to update user: ' . $response->get_error_message());
            }

            $response_code = wp_remote_retrieve_response_code($response);
            $body = wp_remote_retrieve_body($response);
            $headers = wp_remote_retrieve_headers($response);

            $logger->log_api_interaction('Update User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'response_code' => $response_code,
                'response_body' => $body,
                'response_headers' => $headers,
                'body_length' => strlen($body),
                'step' => 'response_received'
            ], $response_code === 200 ? 'info' : 'error', 'Update user response received');

            if ($response_code !== 200) {
                $logger->log_api_interaction('Update User', [
                    'user_id' => $user_id,
                    'customer_id' => $customer_id,
                    'response_code' => $response_code,
                    'response_body' => $body,
                    'step' => 'http_error'
                ], 'error', 'Update user failed with HTTP ' . $response_code);
                throw new Exception('Failed to update user: HTTP ' . $response_code);
            }

            // Convert headers to array
            $headers_array = [];
            if (is_object($headers) && method_exists($headers, 'getAll')) {
                $headers_array = $headers->getAll();
            } elseif (is_array($headers)) {
                $headers_array = $headers;
            }

            // Handle encrypted response
            $iv_base64_for_decryption = base64_encode(hex2bin($iv_hex));

            $logger->log_api_interaction('Update User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'response_body' => $body,
                'response_body_length' => strlen($body),
                'iv_base64_for_decryption' => $iv_base64_for_decryption,
                'step' => 'processing_response'
            ], 'info', 'Processing encrypted response from server');

            $data = $this->handle_encrypted_response_with_headers($body, $headers_array, 'Update User', [
                'user_id' => $customer_id,
                'aes_iv' => $iv_base64_for_decryption,
                'aes_key' => $aes_key
            ]);

            // Handle empty response (success case for update operations)
            if (empty($body) && $response_code === 200) {
                $logger->log_api_interaction('Update User', [
                    'user_id' => $user_id,
                    'customer_id' => $customer_id,
                    'response_body' => $body,
                    'response_code' => $response_code,
                    'step' => 'empty_response_success'
                ], 'success', 'UpdateUser API returned empty response (success)');
                return ['success' => true, 'message' => 'User updated successfully'];
            }

            // Handle text response (success case for update operations)
            if ($data === null && $response_code === 200 && !empty($body)) {
                $logger->log_api_interaction('Update User', [
                    'user_id' => $user_id,
                    'customer_id' => $customer_id,
                    'response_body' => $body,
                    'response_code' => $response_code,
                    'step' => 'text_response_success'
                ], 'success', 'UpdateUser API returned text response (success)');
                return ['success' => true, 'message' => $body];
            }

            if (!is_array($data)) {
                $logger->log_api_interaction('Update User', [
                    'user_id' => $user_id,
                    'customer_id' => $customer_id,
                    'response_body' => $body,
                    'decoded_data' => $data,
                    'data_type' => gettype($data),
                    'step' => 'type_error'
                ], 'error', 'UpdateUser API returned unsupported data type: ' . gettype($data));
                throw new Exception('Invalid response format: expected array, got ' . gettype($data));
            }

            $logger->log_api_interaction('Update User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'data_keys' => array_keys($data),
                'step' => 'success'
            ], 'success', 'Successfully updated user data');

            return $data;
        } catch (\Exception $e) {
            $logger->log_api_interaction('Update User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'error' => $e->getMessage(),
                'step' => 'exception'
            ], 'error', 'Failed to update user: ' . $e->getMessage());
            error_log('DIT Integration: Update user failed - ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Delete user from the server
     *
     * @param int $user_id User ID to delete
     * @param int $customer_id Customer ID
     * @return array|null Response data or null on failure
     */
    public function delete_user(int $user_id, int $customer_id): ?array
    {
        $core = Core::get_instance();
        $logger = $core->logger;

        try {
            // Form DELETE request URL with parameters
            $request_url = $this->api_base_url . '/Users/DeleteUser?CustomerId=' . urlencode($customer_id) . '&UserId=' . urlencode($user_id);

            $logger->log_api_interaction('Delete User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'url' => $request_url,
                'method' => 'DELETE',
                'step' => 'request_start'
            ], 'info', 'Starting delete user request');

            $response = wp_remote_request($request_url, [
                'method' => 'DELETE',
                'timeout' => 30,
                'sslverify' => true,
                'headers' => [
                    'Accept' => '*/*',
                    'User-Agent' => 'WordPress/' . get_bloginfo('version') . '; ' . get_bloginfo('url')
                ]
            ]);

            if (is_wp_error($response)) {
                $logger->log_api_interaction('Delete User', [
                    'user_id' => $user_id,
                    'customer_id' => $customer_id,
                    'error' => $response->get_error_message(),
                    'step' => 'wp_error'
                ], 'error', 'Delete user failed with WordPress error');
                throw new Exception('Failed to delete user: ' . $response->get_error_message());
            }

            $response_code = wp_remote_retrieve_response_code($response);
            $body = wp_remote_retrieve_body($response);
            $headers = wp_remote_retrieve_headers($response);

            $logger->log_api_interaction('Delete User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'response_code' => $response_code,
                'response_body' => $body,
                'response_headers' => $headers,
                'body_length' => strlen($body),
                'step' => 'response_received'
            ], $response_code === 200 ? 'info' : 'error', 'Delete user response received');

            if ($response_code !== 200) {
                $logger->log_api_interaction('Delete User', [
                    'user_id' => $user_id,
                    'customer_id' => $customer_id,
                    'response_code' => $response_code,
                    'response_body' => $body,
                    'step' => 'http_error'
                ], 'error', 'Delete user failed with HTTP ' . $response_code);
                throw new Exception('Failed to delete user: HTTP ' . $response_code);
            }

            // Success - user deleted
            $logger->log_api_interaction('Delete User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'response_code' => $response_code,
                'response_body' => $body,
                'step' => 'success'
            ], 'success', 'User deleted successfully');

            return [
                'success' => true,
                'message' => 'User deleted successfully',
                'user_id' => $user_id,
                'customer_id' => $customer_id
            ];
        } catch (\Exception $e) {
            $logger->log_api_interaction('Delete User', [
                'user_id' => $user_id,
                'customer_id' => $customer_id,
                'error' => $e->getMessage(),
                'step' => 'exception'
            ], 'error', 'Failed to delete user: ' . $e->getMessage());
            error_log('DIT Integration: Delete user failed - ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Update customer information on the server
     *
     * @param int $customer_id Customer ID to update
     * @param array $customer_data Customer data to update
     * @return array|null Response data or null on failure
     */
    public function update_customer(int $customer_id, array $customer_data): ?array
    {
        $core = Core::get_instance();
        $logger = $core->logger;
        $encryption = $core->encryption;

        try {
            // Generate 16-byte IV for this request
            $iv = random_bytes(16);
            $iv_hex = bin2hex($iv);

            // Validate hex string
            if (!ctype_xdigit($iv_hex)) {
                throw new Exception('Generated IV contains non-hex characters: ' . $iv_hex);
            }

            // Prepare customer data for encryption (original customer structure)
            $data_to_encrypt = [
                'CustomerId' => $customer_id,
                'NameFirst' => $customer_data['first_name'] ?? '',
                'NameLast' => $customer_data['last_name'] ?? '',
                'Email' => $customer_data['email'] ?? '',
                'Company' => $customer_data['company'] ?? ''
            ];

            // Add password only if provided
            if (!empty($customer_data['password'])) {
                $data_to_encrypt['Password'] = $customer_data['password'];
            }

            $logger->log_api_interaction('Update Customer', [
                'customer_id' => $customer_id,
                'data_to_encrypt' => $data_to_encrypt,
                'data_keys' => array_keys($data_to_encrypt),
                'password_included' => !empty($customer_data['password']),
                'step' => 'data_prepared'
            ], 'info', 'Customer data prepared for encryption (with Company field)');

            // Convert to JSON
            $json_data = json_encode($data_to_encrypt);
            $json_error = json_last_error();
            $json_error_msg = json_last_error_msg();

            if ($json_error !== JSON_ERROR_NONE) {
                throw new Exception('Failed to encode customer data to JSON: ' . $json_error_msg);
            }

            $logger->log_api_interaction('Update Customer', [
                'customer_id' => $customer_id,
                'json_data' => $json_data,
                'json_error' => $json_error,
                'json_error_msg' => $json_error_msg,
                'json_length' => strlen($json_data),
                'step' => 'json_encoded'
            ], 'info', 'Customer data encoded to JSON');

            // Get AES key directly from customer-specific storage
            $aes_key = $this->get_user_permanent_aes_key($customer_id);

            if (!$aes_key) {
                $logger->log_api_interaction('Update Customer', [
                    'customer_id' => $customer_id,
                    'aes_key_found' => false,
                    'aes_key_source' => 'get_user_permanent_aes_key',
                    'step' => 'aes_key_not_found'
                ], 'error', 'No AES key found for customer ' . $customer_id);
            } else {
                $logger->log_api_interaction('Update Customer', [
                    'customer_id' => $customer_id,
                    'aes_key_found' => true,
                    'aes_key_source' => 'get_user_permanent_aes_key',
                    'aes_key_length' => strlen($aes_key),
                    'step' => 'aes_key_retrieved'
                ], 'info', 'AES key retrieved for customer ' . $customer_id);
            }

            if (!$aes_key) {
                $logger->log_api_interaction('Update Customer', [
                    'customer_id' => $customer_id,
                    'aes_key_found' => false,
                    'step' => 'customer_aes_key_not_found'
                ], 'error', 'Customer AES key not found for encryption');
                return null;
            }

            // Convert base64 AES key to binary if needed
            $aes_key_original_length = strlen($aes_key);
            $aes_key_binary_length = mb_strlen($aes_key, '8bit');

            $logger->log_api_interaction('Update Customer', [
                'customer_id' => $customer_id,
                'aes_key_original_length' => $aes_key_original_length,
                'aes_key_binary_length' => $aes_key_binary_length,
                'aes_key_preview' => substr($aes_key, 0, 20) . '...',
                'step' => 'aes_key_analysis'
            ], 'info', 'AES key analysis before conversion');

            // If key is base64 encoded (44 characters), decode it to binary
            if ($aes_key_original_length === 44 && $aes_key_binary_length === 44) {
                $aes_key_binary = base64_decode($aes_key);
                if ($aes_key_binary === false) {
                    throw new Exception('Failed to decode base64 AES key');
                }
                $aes_key = $aes_key_binary;

                $logger->log_api_interaction('Update Customer', [
                    'customer_id' => $customer_id,
                    'aes_key_converted' => true,
                    'aes_key_binary_length_after' => mb_strlen($aes_key, '8bit'),
                    'step' => 'aes_key_converted'
                ], 'info', 'AES key converted from base64 to binary');
            }

            // Encrypt the data
            $iv_base64 = base64_encode($iv);
            $encrypted_data = $encryption->encrypt_with_aes($json_data, $aes_key, $iv_base64);

            if (!$encrypted_data) {
                throw new Exception('Failed to encrypt customer data');
            }

            // Use base64 encoded format for JSON compatibility
            $encrypted_data_string = base64_encode($encrypted_data);

            $logger->log_api_interaction('Update Customer', [
                'customer_id' => $customer_id,
                'iv_base64' => $iv_base64,
                'iv_hex' => $iv_hex,
                'encrypted_data_length' => strlen($encrypted_data),
                'encrypted_data_string_length' => strlen($encrypted_data_string),
                'encrypted_data_preview' => substr($encrypted_data, 0, 50) . '...',
                'encrypted_data_string_preview' => substr($encrypted_data_string, 0, 50) . '...',
                'aes_key_final_length' => mb_strlen($aes_key, '8bit'),
                'data_block_length_valid' => (strlen($encrypted_data) % 16) === 0,
                'data_block_length' => strlen($encrypted_data),
                'base64_encoding_success' => !empty($encrypted_data_string),
                'base64_encoding_valid' => base64_decode($encrypted_data_string) === $encrypted_data,
                'step' => 'data_encrypted'
            ], 'info', 'Customer data encrypted successfully (using base64 encoded format for JSON compatibility)');

            // Prepare request payload with base64 encoded encrypted data for JSON compatibility
            $request_payload = [
                'primaryKey' => $customer_id,
                'type' => 2,  // typeCustomer = 2 (NOT 1!)
                'aesIVHex' => $iv_hex,
                'encryptedData' => $encrypted_data_string  // Using binary format like UpdateUser
            ];

            $logger->log_api_interaction('Update Customer', [
                'customer_id' => $customer_id,
                'iv_hex' => $iv_hex,
                'iv_hex_length' => strlen($iv_hex),
                'iv_hex_valid' => ctype_xdigit($iv_hex),
                'encrypted_data_length' => strlen($encrypted_data),
                'encrypted_data_string_length' => strlen($encrypted_data_string),
                'data_format' => 'binary',
                'data_keys' => array_keys($data_to_encrypt),
                'password_provided' => !empty($customer_data['password']),
                'step' => 'request_prepared'
            ], 'info', 'Update customer request prepared (type=2 for customer, binary format)');

            // Send POST request to UpdateCustomer endpoint
            $request_url = $this->api_base_url . '/Customers/UpdateCustomer';
            $request_body = json_encode($request_payload);

            $logger->log_api_interaction('Update Customer', [
                'customer_id' => $customer_id,
                'request_url' => $request_url,
                'request_body_length' => strlen($request_body),
                'request_payload' => $request_payload,
                'step' => 'request_sending'
            ], 'info', 'Sending POST request to UpdateCustomer endpoint');

            $response = wp_remote_post($request_url, [
                'timeout' => 30,
                'sslverify' => true,
                'headers' => [
                    'Content-Type' => 'application/json',
                    'User-Agent' => 'WordPress/' . get_bloginfo('version') . '; ' . get_bloginfo('url')
                ],
                'body' => $request_body
            ]);

            if (is_wp_error($response)) {
                $logger->log_api_interaction('Update Customer', [
                    'customer_id' => $customer_id,
                    'error' => $response->get_error_message(),
                    'step' => 'wp_error'
                ], 'error', 'Update customer failed with WordPress error');
                throw new Exception('Failed to update customer: ' . $response->get_error_message());
            }

            $response_code = wp_remote_retrieve_response_code($response);
            $body = wp_remote_retrieve_body($response);
            $headers = wp_remote_retrieve_headers($response);

            $logger->log_api_interaction('Update Customer', [
                'customer_id' => $customer_id,
                'response_code' => $response_code,
                'response_body' => $body,
                'response_headers' => $headers,
                'body_length' => strlen($body),
                'step' => 'response_received'
            ], $response_code === 200 ? 'info' : 'error', 'Update customer response received');

            if ($response_code !== 200) {
                $logger->log_api_interaction('Update Customer', [
                    'customer_id' => $customer_id,
                    'response_code' => $response_code,
                    'response_body' => $body,
                    'step' => 'http_error'
                ], 'error', 'Update customer failed with HTTP ' . $response_code);
                throw new Exception('Failed to update customer: HTTP ' . $response_code);
            }

            // Convert headers to array
            $headers_array = [];
            if (is_object($headers) && method_exists($headers, 'getAll')) {
                $headers_array = $headers->getAll();
            } elseif (is_array($headers)) {
                $headers_array = $headers;
            }

            // Handle encrypted response
            $iv_base64_for_decryption = base64_encode(hex2bin($iv_hex));

            $logger->log_api_interaction('Update Customer', [
                'customer_id' => $customer_id,
                'response_body' => $body,
                'response_body_length' => strlen($body),
                'iv_base64_for_decryption' => $iv_base64_for_decryption,
                'step' => 'processing_response'
            ], 'info', 'Processing encrypted response from server');

            $data = $this->handle_encrypted_response_with_headers($body, $headers_array, 'Update Customer', [
                'customer_id' => $customer_id,
                'aes_iv' => $iv_base64_for_decryption,
                'aes_key' => $aes_key
            ]);

            // Handle empty response (success case for update operations)
            if (empty($body) && $response_code === 200) {
                $logger->log_api_interaction('Update Customer', [
                    'customer_id' => $customer_id,
                    'response_body' => $body,
                    'response_code' => $response_code,
                    'step' => 'empty_response_success'
                ], 'success', 'UpdateCustomer API returned empty response (success)');
                return ['success' => true, 'message' => 'Customer updated successfully'];
            }

            // Handle text response (success case for update operations)
            if ($data === null && $response_code === 200 && !empty($body)) {
                $logger->log_api_interaction('Update Customer', [
                    'customer_id' => $customer_id,
                    'response_body' => $body,
                    'response_code' => $response_code,
                    'step' => 'text_response_success'
                ], 'success', 'UpdateCustomer API returned text response (success)');
                return ['success' => true, 'message' => $body];
            }

            if (!is_array($data)) {
                $logger->log_api_interaction('Update Customer', [
                    'customer_id' => $customer_id,
                    'response_body' => $body,
                    'decoded_data' => $data,
                    'data_type' => gettype($data),
                    'step' => 'type_error'
                ], 'error', 'UpdateCustomer API returned unsupported data type: ' . gettype($data));
                throw new Exception('Invalid response format: expected array, got ' . gettype($data));
            }

            $logger->log_api_interaction('Update Customer', [
                'customer_id' => $customer_id,
                'data_keys' => array_keys($data),
                'step' => 'success'
            ], 'success', 'Successfully updated customer data');

            return $data;
        } catch (\Exception $e) {
            $logger->log_api_interaction('Update Customer', [
                'customer_id' => $customer_id,
                'error' => $e->getMessage(),
                'step' => 'exception'
            ], 'error', 'Failed to update customer: ' . $e->getMessage());
            error_log('DIT Integration: Update customer failed - ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Get customer information from the server
     *
     * @param int $customer_id Customer ID to get
     * @return array|null Response data or null on failure
     */
    public function get_customer(int $customer_id): ?array
    {
        $core = Core::get_instance();
        $logger = $core->logger;
        $encryption = $core->encryption;

        // Генеруємо 16-байтовий IV
        $iv = random_bytes(16);
        $iv_hex = bin2hex($iv); // hex-encode the IV as per developer instructions

        try {
            // Update API URL from settings before making request
            $this->update_api_url();

            // Form GET request URL with parameters including IV
            $request_url = $this->api_base_url . '/Customers/GetCustomer?CustomerId=' . urlencode($customer_id) . '&AesIVHex=' . $iv_hex;

            $logger->log_api_interaction('Get Customer', [
                'customer_id' => $customer_id,
                'iv_hex' => $iv_hex,
                'iv_base64_for_decryption' => base64_encode(hex2bin($iv_hex)),
                'url' => $request_url,
                'api_base_url' => $this->api_base_url,
                'step' => 'request_start'
            ], 'info', 'Starting get customer request with IV');

            $response = wp_remote_get($request_url, [
                'timeout' => 30,
                'sslverify' => true,
                'headers' => [
                    'Accept' => '*/*',
                    'User-Agent' => 'WordPress/' . get_bloginfo('version') . '; ' . get_bloginfo('url')
                ]
            ]);

            if (is_wp_error($response)) {
                $logger->log_api_interaction('Get Customer', [
                    'customer_id' => $customer_id,
                    'error' => $response->get_error_message(),
                    'step' => 'wp_error'
                ], 'error', 'Get customer failed with WordPress error');
                throw new Exception('Failed to get customer: ' . $response->get_error_message());
            }

            $response_code = wp_remote_retrieve_response_code($response);
            $body = wp_remote_retrieve_body($response);
            $headers = wp_remote_retrieve_headers($response);

            $logger->log_api_interaction('Get Customer', [
                'customer_id' => $customer_id,
                'response_code' => $response_code,
                'response_body' => $body,
                'response_headers' => $headers,
                'body_length' => strlen($body),
                'step' => 'response_received'
            ], $response_code === 200 ? 'info' : 'error', 'Get customer response received');

            if ($response_code !== 200) {
                $logger->log_api_interaction('Get Customer', [
                    'customer_id' => $customer_id,
                    'response_code' => $response_code,
                    'response_body' => $body,
                    'step' => 'http_error'
                ], 'error', 'Get customer failed with HTTP ' . $response_code);

                // Try alternative endpoint if main one fails
                if ($response_code === 404) {
                    $logger->log_api_interaction('Get Customer', [
                        'customer_id' => $customer_id,
                        'step' => 'trying_alternative_endpoint',
                        'note' => 'GetCustomer returned 404, trying alternative endpoints'
                    ], 'warning', 'GetCustomer endpoint not found, trying alternatives');

                    // Try alternative endpoint names
                    $alternative_endpoints = [
                        '/Customers/GetCustomerInfo',
                        '/Customers/GetCustomerData',
                        '/Customers/CustomerInfo'
                    ];

                    foreach ($alternative_endpoints as $endpoint) {
                        $alt_url = $this->api_base_url . $endpoint . '?CustomerId=' . urlencode($customer_id) . '&AesIVHex=' . $iv_hex;

                        $logger->log_api_interaction('Get Customer', [
                            'customer_id' => $customer_id,
                            'alternative_endpoint' => $endpoint,
                            'alt_url' => $alt_url,
                            'step' => 'trying_alternative'
                        ], 'info', 'Trying alternative endpoint: ' . $endpoint);

                        $alt_response = wp_remote_get($alt_url, [
                            'timeout' => 30,
                            'sslverify' => true,
                            'headers' => [
                                'Accept' => '*/*',
                                'User-Agent' => 'WordPress/' . get_bloginfo('version') . '; ' . get_bloginfo('url')
                            ]
                        ]);

                        if (!is_wp_error($alt_response)) {
                            $alt_code = wp_remote_retrieve_response_code($alt_response);
                            if ($alt_code === 200) {
                                $logger->log_api_interaction('Get Customer', [
                                    'customer_id' => $customer_id,
                                    'alternative_endpoint' => $endpoint,
                                    'alt_url' => $alt_url,
                                    'step' => 'alternative_success'
                                ], 'success', 'Alternative endpoint successful: ' . $endpoint);

                                // Use alternative response
                                $body = wp_remote_retrieve_body($alt_response);
                                $headers = wp_remote_retrieve_headers($alt_response);
                                $response_code = 200;
                                break;
                            }
                        }
                    }

                    // If still no success, throw original error
                    if ($response_code !== 200) {
                        throw new Exception('Failed to get customer: HTTP ' . $response_code . ' (tried alternatives)');
                    }
                } else {
                    throw new Exception('Failed to get customer: HTTP ' . $response_code);
                }
            }

            // Convert headers to array
            $headers_array = [];
            if (is_object($headers) && method_exists($headers, 'getAll')) {
                $headers_array = $headers->getAll();
            } elseif (is_array($headers)) {
                $headers_array = $headers;
            }

            // Handle encrypted response with IV context
            $iv_base64_for_decryption = base64_encode(hex2bin($iv_hex));
            $data = $this->handle_encrypted_response_with_headers($body, $headers_array, 'Get Customer', [
                'customer_id' => $customer_id,
                'aes_iv' => $iv_base64_for_decryption
            ]);

            if (!is_array($data)) {
                $logger->log_api_interaction('Get Customer', [
                    'customer_id' => $customer_id,
                    'response_body' => $body,
                    'decoded_data' => $data,
                    'data_type' => gettype($data),
                    'step' => 'type_error'
                ], 'error', 'GetCustomer API returned unsupported data type: ' . gettype($data));
                throw new Exception('Invalid response format: expected array, got ' . gettype($data));
            }

            $logger->log_api_interaction('Get Customer', [
                'customer_id' => $customer_id,
                'data_keys' => array_keys($data),
                'step' => 'success'
            ], 'success', 'Successfully retrieved customer data');

            return $data;
        } catch (\Exception $e) {
            $logger->log_api_interaction('Get Customer', [
                'customer_id' => $customer_id,
                'error' => $e->getMessage(),
                'step' => 'exception'
            ], 'error', 'Failed to get customer: ' . $e->getMessage());
            error_log('DIT Integration: Get customer failed - ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Request password reset token
     *
     * @param int $primary_key User or customer ID
     * @param int $login_type 1 for User, 2 for Customer
     * @return array|null Response with token and user data
     */
    public function change_password_ask(int $primary_key, int $login_type): ?array
    {
        $logger = new \DIT\Logger();

        try {
            // For password reset, we need to get AES key differently since user is not logged in
            $aes_key = $this->get_aes_key_for_password_reset($primary_key, $login_type);
            if (!$aes_key) {
                $logger->log_api_interaction('Change Password Ask', [
                    'primary_key' => $primary_key,
                    'login_type' => $login_type,
                    'error' => 'No AES key available for password reset'
                ], 'error', 'No AES key available for password reset');
                throw new Exception('No AES key available for password reset');
            }

            // Generate IV for this request
            $iv = random_bytes(16);
            $iv_hex = bin2hex($iv);

            // Prepare request payload (empty encryptedData as per developer instructions)
            $request_payload = [
                'primaryKey' => $primary_key,
                'type' => $login_type,
                'aesIVHex' => $iv_hex,
                'encryptedData' => '' // Empty as per developer instructions
            ];

            $logger->log_api_interaction('Change Password Ask', [
                'primary_key' => $primary_key,
                'login_type' => $login_type,
                'iv_hex' => $iv_hex,
                'payload' => $request_payload,
                'request_url' => $this->api_base_url . '/Application/ChangePasswordAsk',
                'aes_key_found' => !empty($aes_key),
                'aes_key_length' => $aes_key ? strlen($aes_key) : 0,
                'step' => 'request_preparation'
            ], 'info', 'Preparing change password ask request');

            // Send request
            $response = wp_remote_post($this->api_base_url . '/Application/ChangePasswordAsk', [
                'timeout' => 30,
                'sslverify' => true,
                'headers' => [
                    'Content-Type' => 'application/json',
                    'Accept' => '*/*',
                    'User-Agent' => 'WordPress/' . get_bloginfo('version') . '; ' . get_bloginfo('url')
                ],
                'body' => json_encode($request_payload)
            ]);

            if (is_wp_error($response)) {
                $logger->log_api_interaction('Change Password Ask', [
                    'primary_key' => $primary_key,
                    'login_type' => $login_type,
                    'error' => $response->get_error_message(),
                    'step' => 'wp_error'
                ], 'error', 'Change password ask failed with WordPress error');
                throw new Exception('Failed to request password reset: ' . $response->get_error_message());
            }

            $response_code = wp_remote_retrieve_response_code($response);
            $body = wp_remote_retrieve_body($response);
            $headers = wp_remote_retrieve_headers($response);

            $logger->log_api_interaction('Change Password Ask', [
                'primary_key' => $primary_key,
                'login_type' => $login_type,
                'response_code' => $response_code,
                'response_body' => $body,
                'body_length' => strlen($body),
                'step' => 'response_received'
            ], $response_code === 200 ? 'info' : 'error', 'Change password ask response received');

            if ($response_code !== 200) {
                $logger->log_api_interaction('Change Password Ask', [
                    'primary_key' => $primary_key,
                    'login_type' => $login_type,
                    'response_code' => $response_code,
                    'response_body' => $body,
                    'step' => 'http_error'
                ], 'error', 'Change password ask failed with HTTP ' . $response_code);
                throw new Exception('Failed to request password reset: HTTP ' . $response_code);
            }

            // Convert headers to array
            $headers_array = [];
            if (is_object($headers) && method_exists($headers, 'getAll')) {
                $headers_array = $headers->getAll();
            } elseif (is_array($headers)) {
                $headers_array = $headers;
            }

            $logger->log_api_interaction('Change Password Ask', [
                'primary_key' => $primary_key,
                'login_type' => $login_type,
                'response_headers' => $headers_array,
                'step' => 'headers_processed'
            ], 'info', 'Response headers processed for decryption');

            // Try to parse as regular JSON first
            $data = json_decode($body, true);
            if ($data !== null) {
                $logger->log_api_interaction('Change Password Ask', [
                    'primary_key' => $primary_key,
                    'login_type' => $login_type,
                    'response_type' => 'json',
                    'data_keys' => array_keys($data),
                    'step' => 'json_parsed_successfully'
                ], 'success', 'Response parsed as JSON successfully');
            } else {
                $logger->log_api_interaction('Change Password Ask', [
                    'primary_key' => $primary_key,
                    'login_type' => $login_type,
                    'response_type' => 'encrypted',
                    'body_preview' => substr($body, 0, 50) . '...',
                    'step' => 'json_parse_failed_trying_decrypt'
                ], 'info', 'Response is not JSON, trying decryption');

                // Try to get AES key from cookies first
                $cookie_aes_key = null;
                if (isset($_COOKIE['dit_aes_key'])) {
                    $cookie_aes_key = $_COOKIE['dit_aes_key'];
                } elseif (isset($_COOKIE['dit_aes_key_123'])) {
                    $cookie_aes_key = $_COOKIE['dit_aes_key_123'];
                } elseif (isset($_COOKIE['dit_aes_key_124'])) {
                    $cookie_aes_key = $_COOKIE['dit_aes_key_124'];
                } elseif (isset($_COOKIE['aes_key'])) {
                    $cookie_aes_key = $_COOKIE['aes_key'];
                } elseif (isset($_COOKIE['encryption_key'])) {
                    $cookie_aes_key = $_COOKIE['encryption_key'];
                }

                $logger->log_api_interaction('Change Password Ask', [
                    'primary_key' => $primary_key,
                    'login_type' => $login_type,
                    'cookie_aes_key_found' => !empty($cookie_aes_key),
                    'cookie_aes_key_length' => $cookie_aes_key ? strlen($cookie_aes_key) : 0,
                    'cookie_aes_key_preview' => $cookie_aes_key ? substr($cookie_aes_key, 0, 20) . '...' : null,
                    'cookie_aes_key_is_hex' => $cookie_aes_key ? ctype_xdigit($cookie_aes_key) : false,
                    'cookie_aes_key_is_base64' => $cookie_aes_key ? base64_decode($cookie_aes_key, true) !== false : false,
                    'available_cookies' => array_keys($_COOKIE),
                    'step' => 'cookie_aes_key_check'
                ], 'info', 'Checking for AES key in cookies');

                // Use cookie AES key if available, otherwise use generated key
                $decryption_aes_key = $aes_key; // Default to generated key

                if ($cookie_aes_key) {
                    // Try to convert hex-encoded key to base64
                    if (ctype_xdigit($cookie_aes_key)) {
                        // Convert hex to binary, then to base64
                        $binary_key = hex2bin($cookie_aes_key);
                        if ($binary_key !== false) {
                            $decryption_aes_key = base64_encode($binary_key);
                            $logger->log_api_interaction('Change Password Ask', [
                                'primary_key' => $primary_key,
                                'login_type' => $login_type,
                                'conversion_type' => 'hex_to_base64',
                                'original_length' => strlen($cookie_aes_key),
                                'converted_length' => strlen($decryption_aes_key),
                                'step' => 'key_conversion_hex_to_base64'
                            ], 'info', 'Converted hex key to base64');
                        }
                    } elseif (base64_decode($cookie_aes_key, true) !== false) {
                        // Already base64 encoded - use as-is
                        $decryption_aes_key = $cookie_aes_key;
                        $binary_key_length = strlen(base64_decode($cookie_aes_key, true));
                        $logger->log_api_interaction('Change Password Ask', [
                            'primary_key' => $primary_key,
                            'login_type' => $login_type,
                            'conversion_type' => 'already_base64',
                            'key_length' => strlen($decryption_aes_key),
                            'binary_key_length' => $binary_key_length,
                            'step' => 'key_already_base64'
                        ], 'info', 'Key already in base64 format');
                    } else {
                        // Use as-is (might be raw binary or other format)
                        $decryption_aes_key = $cookie_aes_key;
                        $logger->log_api_interaction('Change Password Ask', [
                            'primary_key' => $primary_key,
                            'login_type' => $login_type,
                            'conversion_type' => 'use_as_is',
                            'key_length' => strlen($decryption_aes_key),
                            'step' => 'key_use_as_is'
                        ], 'info', 'Using key as-is');
                    }
                }

                // Handle encrypted response with direct decryption
                $iv_base64_for_decryption = base64_encode(hex2bin($iv_hex));

                // Try direct decryption first with converted key
                $decrypted_data = openssl_decrypt(
                    base64_decode($body),
                    'AES-256-CBC',
                    base64_decode($decryption_aes_key),
                    OPENSSL_RAW_DATA,
                    base64_decode($iv_base64_for_decryption)
                );

                // If that fails, try with the original cookie key directly
                if ($decrypted_data === false && $cookie_aes_key) {
                    $logger->log_api_interaction('Change Password Ask', [
                        'primary_key' => $primary_key,
                        'login_type' => $login_type,
                        'trying_original_cookie_key' => true,
                        'cookie_key_length' => strlen($cookie_aes_key),
                        'step' => 'trying_original_cookie_key'
                    ], 'info', 'Trying decryption with original cookie key');

                    $decrypted_data = openssl_decrypt(
                        base64_decode($body),
                        'AES-256-CBC',
                        $cookie_aes_key, // Use original key directly
                        OPENSSL_RAW_DATA,
                        base64_decode($iv_base64_for_decryption)
                    );
                }

                // If that fails, try with first 32 bytes of the cookie key
                if ($decrypted_data === false && $cookie_aes_key) {
                    $binary_cookie_key = base64_decode($cookie_aes_key, true);
                    if ($binary_cookie_key !== false && strlen($binary_cookie_key) >= 32) {
                        $truncated_key = substr($binary_cookie_key, 0, 32);
                        $logger->log_api_interaction('Change Password Ask', [
                            'primary_key' => $primary_key,
                            'login_type' => $login_type,
                            'trying_truncated_cookie_key' => true,
                            'original_binary_length' => strlen($binary_cookie_key),
                            'truncated_binary_length' => strlen($truncated_key),
                            'step' => 'trying_truncated_cookie_key'
                        ], 'info', 'Trying decryption with first 32 bytes of cookie key');

                        $decrypted_data = openssl_decrypt(
                            base64_decode($body),
                            'AES-256-CBC',
                            $truncated_key, // Use first 32 bytes
                            OPENSSL_RAW_DATA,
                            base64_decode($iv_base64_for_decryption)
                        );
                    }
                }

                if ($decrypted_data !== false) {
                    $logger->log_api_interaction('Change Password Ask', [
                        'primary_key' => $primary_key,
                        'login_type' => $login_type,
                        'decryption_success' => true,
                        'decrypted_length' => strlen($decrypted_data),
                        'decrypted_preview' => substr($decrypted_data, 0, 100) . '...',
                        'step' => 'direct_decryption_success'
                    ], 'success', 'Direct decryption successful');

                    $data = json_decode($decrypted_data, true);
                    if ($data === null) {
                        throw new Exception('Failed to decode decrypted JSON: ' . json_last_error_msg());
                    }
                } else {
                    $logger->log_api_interaction('Change Password Ask', [
                        'primary_key' => $primary_key,
                        'login_type' => $login_type,
                        'decryption_success' => false,
                        'step' => 'direct_decryption_failed'
                    ], 'warning', 'Direct decryption failed, trying complex method');

                    // Fallback to complex method
                    $data = $this->handle_encrypted_response_with_headers($body, $headers_array, 'Change Password Ask', [
                        'primary_key' => $primary_key,
                        'login_type' => $login_type,
                        'aes_iv' => $iv_base64_for_decryption,
                        'aes_key' => $aes_key
                    ]);
                }
            }

            if (!is_array($data)) {
                $logger->log_api_interaction('Change Password Ask', [
                    'primary_key' => $primary_key,
                    'login_type' => $login_type,
                    'response_body' => $body,
                    'decoded_data' => $data,
                    'data_type' => gettype($data),
                    'step' => 'type_error'
                ], 'error', 'ChangePasswordAsk API returned unsupported data type: ' . gettype($data));
                throw new Exception('Invalid response format: expected array, got ' . gettype($data));
            }

            $logger->log_api_interaction('Change Password Ask', [
                'primary_key' => $primary_key,
                'login_type' => $login_type,
                'data_keys' => array_keys($data),
                'step' => 'success'
            ], 'success', 'Successfully requested password reset token');

            return $data;
        } catch (\Exception $e) {
            $logger->log_api_interaction('Change Password Ask', [
                'primary_key' => $primary_key,
                'login_type' => $login_type,
                'error' => $e->getMessage(),
                'step' => 'exception'
            ], 'error', 'Failed to request password reset: ' . $e->getMessage());
            error_log('DIT Integration: Change password ask failed - ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Submit password reset with token
     *
     * @param array $request_data ChangePasswordRequest data
     * @return int Error code (0 = success)
     */
    public function change_password_answer(array $request_data): int
    {
        $logger = new \DIT\Logger();

        try {
            $primary_key = $request_data['PrimaryKey'] ?? 0;
            $login_type = $request_data['LoginType'] ?? 0;
            $token = $request_data['Token'] ?? 0;
            $password_new = $request_data['PasswordNew'] ?? '';

            // Get AES key for encryption
            $aes_key = $this->get_aes_key_for_decryption($primary_key);
            if (!$aes_key) {
                $logger->log_api_interaction('Change Password Answer', [
                    'primary_key' => $primary_key,
                    'login_type' => $login_type,
                    'error' => 'No AES key available'
                ], 'error', 'No AES key available for encryption');
                return 1; // Error code for failure
            }

            // Generate IV for this request
            $iv = random_bytes(16);
            $iv_hex = bin2hex($iv);

            // Prepare data for encryption
            $data_to_encrypt = [
                'PrimaryKey' => $primary_key,
                'LoginType' => $login_type,
                'Token' => $token,
                // Не логувати пароль у відкритому вигляді
                'PasswordNew' => '[HIDDEN]'
            ];

            // Логування даних до шифрування (без пароля)
            $logger->log_api_interaction('Change Password Answer', [
                'primary_key' => $primary_key,
                'login_type' => $login_type,
                'iv_hex' => $iv_hex,
                'data_to_encrypt' => $data_to_encrypt,
                'endpoint' => $this->api_base_url . '/ChangePasswordAnswer',
                'step' => 'request_preparation'
            ], 'info', 'Preparing change password answer request');

            // Encrypt the data
            $encrypted_data = openssl_encrypt(
                json_encode([
                    'PrimaryKey' => $primary_key,
                    'LoginType' => $login_type,
                    'Token' => $token,
                    'PasswordNew' => $password_new
                ]),
                'AES-256-CBC',
                $aes_key,
                OPENSSL_RAW_DATA,
                $iv
            );

            if ($encrypted_data === false) {
                $logger->log_api_interaction('Change Password Answer', [
                    'primary_key' => $primary_key,
                    'login_type' => $login_type,
                    'error' => 'Encryption failed'
                ], 'error', 'Failed to encrypt password reset data');
                return 1; // Error code for failure
            }

            // Convert encrypted data to base64 string
            $encrypted_data_string = base64_encode($encrypted_data);

            // Prepare request payload
            $request_payload = [
                'primaryKey' => $primary_key,
                'type' => $login_type,
                'aesIVHex' => $iv_hex,
                'encryptedData' => $encrypted_data_string
            ];

            $logger->log_api_interaction('Change Password Answer', [
                'primary_key' => $primary_key,
                'login_type' => $login_type,
                'token' => $token,
                'iv_hex' => $iv_hex,
                'payload' => $request_payload,
                'endpoint' => $this->api_base_url . '/ChangePasswordAnswer',
                'step' => 'sending_request'
            ], 'info', 'Sending change password answer request');

            // Send request
            $response = wp_remote_post($this->api_base_url . '/Application/ChangePasswordAnswer', [
                'timeout' => 30,
                'sslverify' => true,
                'headers' => [
                    'Content-Type' => 'application/json',
                    'Accept' => '*/*',
                    'User-Agent' => 'WordPress/' . get_bloginfo('version') . '; ' . get_bloginfo('url')
                ],
                'body' => json_encode($request_payload)
            ]);

            if (is_wp_error($response)) {
                $logger->log_api_interaction('Change Password Answer', [
                    'primary_key' => $primary_key,
                    'login_type' => $login_type,
                    'error' => $response->get_error_message(),
                    'step' => 'wp_error'
                ], 'error', 'Change password answer failed with WordPress error');
                return 1; // Error code for failure
            }

            $response_code = wp_remote_retrieve_response_code($response);
            $body = wp_remote_retrieve_body($response);
            $headers = wp_remote_retrieve_headers($response);

            // Convert headers to array
            $headers_array = [];
            if (is_object($headers) && method_exists($headers, 'getAll')) {
                $headers_array = $headers->getAll();
            } elseif (is_array($headers)) {
                $headers_array = $headers;
            }

            $logger->log_api_interaction('Change Password Answer', [
                'primary_key' => $primary_key,
                'login_type' => $login_type,
                'response_code' => $response_code,
                'response_body' => $body,
                'response_headers' => $headers_array,
                'body_length' => strlen($body),
                'step' => 'response_received'
            ], $response_code === 200 ? 'info' : 'error', 'Change password answer response received');

            if ($response_code !== 200) {
                $logger->log_api_interaction('Change Password Answer', [
                    'primary_key' => $primary_key,
                    'login_type' => $login_type,
                    'response_code' => $response_code,
                    'response_body' => $body,
                    'step' => 'http_error'
                ], 'error', 'Change password answer failed with HTTP ' . $response_code);
                return 1; // Error code for failure
            }

            // Parse response (should be a simple error code)
            $error_code = intval(trim($body));

            // Логування розшифрованих даних (без пароля)
            $logger->log_api_interaction('Change Password Answer', [
                'primary_key' => $primary_key,
                'login_type' => $login_type,
                'token' => $token,
                'step' => 'decrypted_data',
                'decrypted_data' => [
                    'PrimaryKey' => $primary_key,
                    'LoginType' => $login_type,
                    'Token' => $token,
                    'PasswordNew' => '[HIDDEN]'
                ]
            ], $error_code === 0 ? 'success' : 'error', 'Password reset completed with error code: ' . $error_code);

            return $error_code;
        } catch (\Exception $e) {
            $logger->log_api_interaction('Change Password Answer', [
                'primary_key' => $primary_key ?? 0,
                'login_type' => $login_type ?? 0,
                'error' => $e->getMessage(),
                'step' => 'exception'
            ], 'error', 'Failed to submit password reset: ' . $e->getMessage());
            error_log('DIT Integration: Change password answer failed - ' . $e->getMessage());
            return 1; // Error code for failure
        }
    }

    /**
     * Get AES key for password reset (when user is not logged in)
     *
     * @param int $primary_key User or customer ID
     * @param int $login_type 1 for User, 2 for Customer
     * @return string|null AES key or null if not found
     */
    private function get_aes_key_for_password_reset(int $primary_key, int $login_type): ?string
    {
        $logger = new \DIT\Logger();

        try {
            // First, try to get AES key from session (if user is logged in)
            $session_manager = new \DIT\Session_Manager();
            $session_data = $session_manager->get_session_data();

            $logger->log_api_interaction('Password Reset AES Key', [
                'primary_key' => $primary_key,
                'login_type' => $login_type,
                'session_data_exists' => !empty($session_data),
                'session_keys' => $session_data ? array_keys($session_data) : [],
                'session_data_preview' => $session_data ? array_slice($session_data, 0, 3) : [],
                'step' => 'session_check'
            ], 'info', 'Checking session for AES key');

            // Check for AES key in different possible locations
            $aes_key_from_session = null;
            if (!empty($session_data['aes_key'])) {
                $aes_key_from_session = $session_data['aes_key'];
            } elseif (!empty($session_data['encryption_key'])) {
                $aes_key_from_session = $session_data['encryption_key'];
            } elseif (!empty($session_data['user_aes_key'])) {
                $aes_key_from_session = $session_data['user_aes_key'];
            }

            if ($aes_key_from_session) {
                $logger->log_api_interaction('Password Reset AES Key', [
                    'primary_key' => $primary_key,
                    'login_type' => $login_type,
                    'key_found' => true,
                    'key_length' => strlen($aes_key_from_session),
                    'source' => 'session'
                ], 'info', 'AES key found in session');
                return $aes_key_from_session;
            }

            // Try to get AES key from permanent storage
            $aes_key = $this->get_user_permanent_aes_key($primary_key);

            if ($aes_key) {
                $logger->log_api_interaction('Password Reset AES Key', [
                    'primary_key' => $primary_key,
                    'login_type' => $login_type,
                    'key_found' => true,
                    'key_length' => strlen($aes_key),
                    'source' => 'permanent_storage'
                ], 'info', 'AES key found in permanent storage');
                return $aes_key;
            }

            // If not found, try to get it from API
            $logger->log_api_interaction('Password Reset AES Key', [
                'primary_key' => $primary_key,
                'login_type' => $login_type,
                'key_found' => false,
                'source' => 'permanent_storage'
            ], 'info', 'AES key not found in permanent storage, trying fallback methods');

            // Try to get encryption key from plugin settings
            $settings = get_option('dit_settings');
            $encryption_key = $settings['encryption_key'] ?? null;

            if ($encryption_key) {
                $logger->log_api_interaction('Password Reset AES Key', [
                    'primary_key' => $primary_key,
                    'login_type' => $login_type,
                    'key_found' => true,
                    'key_length' => strlen($encryption_key),
                    'source' => 'plugin_settings'
                ], 'info', 'Using encryption key from plugin settings');
                return $encryption_key;
            }

            // If still not found, try to generate a temporary key
            $logger->log_api_interaction('Password Reset AES Key', [
                'primary_key' => $primary_key,
                'login_type' => $login_type,
                'key_found' => false,
                'source' => 'plugin_settings'
            ], 'info', 'No encryption key found in plugin settings');

            // Generate new AES key for password reset (32 bytes = 256 bits for AES-256)
            $new_aes_key = base64_encode(random_bytes(32));

            $logger->log_api_interaction('Password Reset AES Key', [
                'primary_key' => $primary_key,
                'login_type' => $login_type,
                'key_found' => true,
                'key_length' => strlen($new_aes_key),
                'source' => 'generated_new'
            ], 'info', 'Generated new AES key for password reset');

            return $new_aes_key;
        } catch (\Exception $e) {
            $logger->log_api_interaction('Password Reset AES Key', [
                'primary_key' => $primary_key,
                'login_type' => $login_type,
                'error' => $e->getMessage()
            ], 'error', 'Failed to get AES key for password reset: ' . $e->getMessage());
            return null;
        }
    }



    /**
     * Ensure steganography key exists for current session
     * Creates new AES key and stores it in steganography format
     * 
     * @param int $customer_id Customer ID
     * @param string $user_email User email for logging
     * @return bool True if key was created/updated successfully
     */
    /**
     * DEPRECATED: This method should not be used during login
     * Steganography keys should only be created during registration
     * 
     * @param int $customer_id Customer ID
     * @param string $user_email User email
     * @return bool Always returns false to prevent automatic user creation during login
     */
    public function ensure_steganography_key_for_session($customer_id, $user_email = '')
    {
        error_log('DIT API: WARNING - ensure_steganography_key_for_session called during login');
        error_log('DIT API: This method is deprecated and should not be used during login');
        error_log('DIT API: Customer ID: ' . $customer_id . ', Email: ' . $user_email);
        error_log('DIT API: Steganography keys should only be created during registration');

        // Return false to prevent automatic user creation during login
        return false;
    }

    /**
     * Check if valid steganography key exists for customer
     * 
     * @param int $customer_id Customer ID
     * @return bool True if valid steganography key exists
     */
    private function has_valid_steganography_key($customer_id)
    {
        if (!isset($_SESSION)) {
            session_start();
        }

        error_log('DIT API: Checking steganography key validity for customer_id: ' . $customer_id);

        // Check if key exists in session
        if (!isset($_SESSION['dit_aes_keys'][$customer_id])) {
            error_log('DIT API: - No key found in session');
            return false;
        }

        $key = $_SESSION['dit_aes_keys'][$customer_id];
        error_log('DIT API: - Key found in session, length: ' . strlen($key));
        error_log('DIT API: - Key format check: ' . (ctype_xdigit($key) ? 'hex' : 'binary'));

        // Check if key is in steganography format (128 hex characters)
        if (ctype_xdigit($key) && strlen($key) === 128) {
            error_log('DIT API: - Valid steganography key format detected (128 hex chars)');
            return true;
        }

        // If it's a binary key (32 bytes), it's old format
        if (strlen($key) === 32 && !ctype_xdigit($key)) {
            error_log('DIT API: - Old binary key format detected (32 bytes), needs conversion');
            return false;
        }

        error_log('DIT API: - Unknown key format, length: ' . strlen($key) . ', is_hex: ' . (ctype_xdigit($key) ? 'yes' : 'no'));
        return false;
    }

    /**
     * Call WebLogin API with steganographic encryption
     * This method implements the developer's procedure for WebLogin API
     * 
     * @param string $requestB64 Base64 encoded encrypted request
     * @param string $keyInterleaved Interleaved hex string (GGKKGGKK format)
     * @param string $hexIV Hex encoded IV
     * @return array|null Response data or null on failure
     */
    public function call_weblogin_api(string $requestB64, string $keyInterleaved, string $hexIV): ?array
    {
        $core = Core::get_instance();
        $logger = $core->logger;

        try {
            $logger->log_api_interaction('WebLogin API Call', [
                'step' => 'start',
                'requestB64_length' => strlen($requestB64),
                'keyInterleaved_length' => strlen($keyInterleaved),
                'hexIV_length' => strlen($hexIV),
                'hexIV_valid' => ctype_xdigit($hexIV)
            ], 'info', 'Starting WebLogin API call');

            // Build URL with query parameters
            $url_params = [
                'requestB64' => urlencode($requestB64),
                'keyInterleaved' => urlencode($keyInterleaved),
                'hexIV' => urlencode($hexIV)
            ];

            $url = add_query_arg($url_params, $this->api_base_url . '/Application/WebLogin');

            $logger->log_api_interaction('WebLogin API Call', [
                'step' => 'url_built',
                'base_url' => $this->api_base_url,
                'endpoint' => '/Application/WebLogin',
                'full_url' => $url,
                'url_params' => $url_params
            ], 'info', 'WebLogin API URL built');

            // Send POST request to WebLogin endpoint
            $response = wp_remote_post($url, [
                'timeout' => 30,
                'sslverify' => true,
                'user-agent' => 'DIT-Integration-WebLogin/1.0'
            ]);

            if (is_wp_error($response)) {
                $logger->log_api_interaction('WebLogin API Call', [
                    'step' => 'wp_error',
                    'error' => $response->get_error_message()
                ], 'error', 'WebLogin API call failed with WordPress error');
                return null;
            }

            $response_code = wp_remote_retrieve_response_code($response);
            $body = wp_remote_retrieve_body($response);
            $headers = wp_remote_retrieve_headers($response);

            $logger->log_api_interaction('WebLogin API Call', [
                'step' => 'response_received',
                'response_code' => $response_code,
                'response_body' => $body,
                'response_headers' => $headers,
                'body_length' => strlen($body)
            ], $response_code === 200 ? 'info' : 'error', 'WebLogin API response received');

            if ($response_code !== 200) {
                $logger->log_api_interaction('WebLogin API Call', [
                    'step' => 'http_error',
                    'response_code' => $response_code,
                    'response_body' => $body
                ], 'error', 'WebLogin API failed with HTTP ' . $response_code);
                return null;
            }

            // Try to decode JSON response
            $data = json_decode($body, true);

            if (json_last_error() !== JSON_ERROR_NONE) {
                $logger->log_api_interaction('WebLogin API Call', [
                    'step' => 'json_decode_error',
                    'response_body' => $body,
                    'json_error' => json_last_error_msg()
                ], 'error', 'Invalid JSON response from WebLogin API');
                return null;
            }

            $logger->log_api_interaction('WebLogin API Call', [
                'step' => 'success',
                'decoded_data' => $data,
                'identifier' => $data['identifier'] ?? null,
                'loginType' => $data['loginType'] ?? null,
                'errorcode' => $data['errorcode'] ?? null
            ], 'success', 'WebLogin API call successful');

            return $data;
        } catch (\Exception $e) {
            $logger->log_api_interaction('WebLogin API Call', [
                'step' => 'exception',
                'error' => $e->getMessage()
            ], 'error', 'WebLogin API call failed with exception: ' . $e->getMessage());

            error_log('DIT API: WebLogin API call failed - ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Create WebLogin request with steganographic key
     * This method implements the developer's procedure exactly:
     * 1. Creating an AES key and IV + Generating 32 bytes of interleaving data
     * 2. Hex-encoding the IV, the key, and the throwaway data
     * 3. Interleaving the throwaway data with the key
     * 4. Populating the PHP equivalent of a WebLoginRequest
     * 5. Serializing, encrypting with the new key and IV, and base64 encoding the request
     *
     * @param string $email User email
     * @param string $password Plain password
     * @param int $loginType Login type (1=User, 2=Customer, 3=Administrator)
     * @return array Array with 'requestB64', 'keyInterleaved', 'hexIV' for WebLogin API
     * @throws Exception
     */
    public function create_weblogin_request(string $email, string $password, int $loginType): array
    {
        $core = Core::get_instance();
        $logger = $core->logger;
        $encryption = $core->encryption;

        try {
            $logger->log_api_interaction('WebLogin Request Creation', [
                'step' => 'start',
                'email' => $email,
                'login_type' => $loginType,
                'password_length' => strlen($password)
            ], 'info', 'Starting WebLogin request creation according to developer procedure');

            // Step 1: Creating an AES key and IV + Generating 32 bytes of interleaving data
            $aes_data = $encryption->generate_aes_key();
            $aes_key = $aes_data['key'];
            $iv = $aes_data['iv'];

            // Generate 32 bytes of interleaving data (this can be a second AES key)
            $interleaving_data = random_bytes(32);

            $logger->log_api_interaction('WebLogin Request Creation', [
                'step' => 'keys_generated',
                'aes_key_length' => mb_strlen($aes_key, '8bit'),
                'iv_length' => mb_strlen($iv, '8bit'),
                'interleaving_data_length' => mb_strlen($interleaving_data, '8bit')
            ], 'info', 'AES key, IV and interleaving data generated');

            // Step 2: Hex-encoding the IV, the key, and the throwaway data
            $hex_iv = bin2hex($iv);
            $hex_key = bin2hex($aes_key);
            $hex_interleaving = bin2hex($interleaving_data);

            $logger->log_api_interaction('WebLogin Request Creation', [
                'step' => 'hex_encoding',
                'hex_iv_length' => strlen($hex_iv),
                'hex_key_length' => strlen($hex_key),
                'hex_interleaving_length' => strlen($hex_interleaving)
            ], 'info', 'IV, key and interleaving data hex-encoded');

            // Step 3: Interleaving the throwaway data with the key
            $keyInterleaved = '';
            for ($i = 0; $i < strlen($hex_key); $i += 2) {
                $keyInterleaved .= substr($hex_interleaving, $i, 2);  // G (garbage/interleaving)
                $keyInterleaved .= substr($hex_key, $i, 2);           // K (key)
            }

            $logger->log_api_interaction('WebLogin Request Creation', [
                'step' => 'interleaving',
                'keyInterleaved_length' => strlen($keyInterleaved),
                'keyInterleaved_preview' => substr($keyInterleaved, 0, 16) . '...',
                'format_verification' => (strlen($keyInterleaved) === 128)
            ], 'info', 'Key interleaving completed (GGKKGGKK format)');

            // Step 4: Populating the PHP equivalent of a WebLoginRequest
            $request_data = [
                'LoginType' => $loginType,
                'Password' => $password,  // Plain text password as per developer's procedure
                'Email' => $email
            ];

            $logger->log_api_interaction('WebLogin Request Creation', [
                'step' => 'request_structure',
                'request_data' => $request_data,
                'login_type' => $loginType,
                'email' => $email,
                'password_provided' => !empty($password)
            ], 'info', 'WebLoginRequest structure populated');

            // Step 5: Serializing, encrypting with the new key and IV, and base64 encoding the request
            $serialized_request = json_encode($request_data);
            if ($serialized_request === false) {
                throw new Exception('Failed to serialize request data: ' . json_last_error_msg());
            }

            // ВИПРАВЛЕННЯ: Використовувати оригінальний IV для шифрування
            $encrypted_request = $encryption->encrypt_with_aes($serialized_request, $aes_key, $iv);
            $requestB64 = base64_encode($encrypted_request);

            $logger->log_api_interaction('WebLogin Request Creation', [
                'step' => 'encryption_complete',
                'serialized_length' => strlen($serialized_request),
                'encrypted_length' => strlen($encrypted_request),
                'requestB64_length' => strlen($requestB64),
                'requestB64_preview' => substr($requestB64, 0, 20) . '...'
            ], 'info', 'Request serialized, encrypted and base64 encoded');

            // Return data exactly as required by WebLogin API
            $result = [
                'requestB64' => $requestB64,
                'keyInterleaved' => $keyInterleaved,
                'hexIV' => $hex_iv,
                // Additional data for internal use
                'aes_key' => $aes_key,
                'iv' => $iv,
                'interleaving_data' => $interleaving_data
            ];

            $logger->log_api_interaction('WebLogin Request Creation', [
                'step' => 'complete',
                'result_keys' => array_keys($result),
                'requestB64_length' => strlen($result['requestB64']),
                'keyInterleaved_length' => strlen($result['keyInterleaved']),
                'hexIV_length' => strlen($result['hexIV'])
            ], 'success', 'WebLogin request created successfully according to developer procedure');

            return $result;
        } catch (\Exception $e) {
            $logger->log_api_interaction('WebLogin Request Creation', [
                'step' => 'error',
                'email' => $email,
                'error' => $e->getMessage()
            ], 'error', 'Failed to create WebLogin request: ' . $e->getMessage());
            throw $e;
        }
    }
}
