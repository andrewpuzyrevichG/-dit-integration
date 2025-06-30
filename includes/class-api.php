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
     * RSA key cache expiration time (1 hour)
     *
     * @var int
     */
    private $rsa_key_cache_time = 3600;

    /**
     * RSA key cache timestamp
     *
     * @var int
     */
    private $rsa_key_cache_timestamp = 0;

    /**
     * Constructor
     */
    public function __construct()
    {
        $this->api_base_url = 'https://api.dataintegritytool.org:5001';
    }

    /**
     * Initialize the API
     */
    public function init()
    {
        // Add any initialization logic here
        // For example, we could verify the API connection
        $rsa_key = $this->get_server_rsa_key();
        if ($rsa_key === null) {
            error_log('DIT Integration: Failed to initialize API - could not get RSA key');
        }
    }

    /**
     * Get server RSA public key
     *
     * @return string|null Base64 encoded RSA public key or null on failure
     */
    private function get_server_rsa_key(): ?string
    {
        // Check if we have a cached key that's still valid
        if (
            $this->cached_rsa_key !== null &&
            (time() - $this->rsa_key_cache_timestamp) < $this->rsa_key_cache_time
        ) {
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

            // Cache the key
            $this->cached_rsa_key = $body;
            $this->rsa_key_cache_timestamp = time();

            $logger->log_api_interaction(
                'Get RSA Key',
                [
                    'response_code' => $response_code,
                    'key_length' => mb_strlen($body, '8bit'),
                    'cached' => true
                ],
                'success',
                'Successfully retrieved and cached RSA key'
            );

            return $body;
        } catch (Exception $e) {
            $logger->log_api_interaction(
                'Get RSA Key',
                ['error' => $e->getMessage()],
                'error',
                'Failed to get RSA key'
            );
            error_log('DIT Integration: Failed to get RSA key - ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Register a new customer (main method)
     * Uses the new Prepare endpoint by default
     *
     * @param array $user_data User data to register
     * @return int|null Customer ID or null on failure
     */
    public function register_customer(array $user_data): ?int
    {
        // Use the new Prepare endpoint by default
        return $this->register_customer_prepare($user_data);
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
            $aes_key = $encryption->generate_aes_key(); // 256-bit key
            $iv = $encryption->generate_iv(); // 128-bit IV

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
                'Notes' => $user_data['notes'] ?? ''
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
                'body' => $encoded_payload, // просто base64-рядок, без JSON-обгортки
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

            // Cache the username, CustomerId, and the returned AES key
            \DIT\save_user_data($user_name, $customer_id, $permanent_aes_key);

            $logger->log_api_interaction('Register Customer', [
                'customer_id' => $customer_id,
                'encryption_method' => 'rsa',
                'response_decrypted' => true
            ], 'success', 'Customer registered successfully with RSA encryption.');

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
     * Authenticate customer
     *
     * @param string $email Customer email
     * @param string $sha256password SHA-256 hashed password
     * @return array|null Authentication data or null on failure
     */
    public function login(string $email, string $sha256password): ?array
    {
        $url = add_query_arg([
            'email' => urlencode($email),
            'password' => urlencode($sha256password)
        ], $this->api_base_url . '/Session/Login');

        $response = wp_remote_get($url);

        if (is_wp_error($response)) {
            error_log('DIT Integration: Failed to login - ' . $response->get_error_message());
            return null;
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (!isset($data['PrimaryKey']) || !isset($data['errorcode'])) {
            error_log('DIT Integration: Invalid login response');
            return null;
        }

        return [
            'PrimaryKey' => (int) $data['PrimaryKey'],
            'errorcode' => (int) $data['errorcode']
        ];
    }

    /**
     * Check if email exists
     *
     * @param string $email Email to check
     * @return int|null 0 if email is available, 1 if taken, null on error
     */
    public function check_email(string $email): ?int
    {
        $url = add_query_arg([
            'Email' => urlencode($email)
        ], $this->api_base_url . '/Customers/CheckEmail');

        $response = wp_remote_get($url);

        if (is_wp_error($response)) {
            error_log('DIT Integration: Failed to check email - ' . $response->get_error_message());
            return null;
        }

        $body = wp_remote_retrieve_body($response);
        $result = json_decode($body, true);

        // The API returns a direct integer value
        if (!is_numeric($result)) {
            error_log('DIT Integration: Invalid email check response');
            return null;
        }

        return (int) $result;
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
        error_log('DIT Integration: RSA key cache cleared');
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

        return [
            'is_cached' => $is_cached,
            'cache_age' => $cache_age,
            'is_valid' => $is_valid,
            'cache_timeout' => $this->rsa_key_cache_time,
            'key_length' => $is_cached ? mb_strlen($this->cached_rsa_key, '8bit') : 0
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
    public function set_user_permanent_aes_key_active(int $customer_id): bool
    {
        $core = Core::get_instance();
        $encryption = $core->encryption;

        $permanent_aes_key = $this->get_user_permanent_aes_key($customer_id);
        if ($permanent_aes_key === null) {
            error_log('DIT Integration: User not found for customer ID: ' . $customer_id);
            return false;
        }

        $encryption->set_user_permanent_aes_key($permanent_aes_key);
        error_log('DIT Integration: Set permanent AES key as active for customer ID: ' . $customer_id);
        return true;
    }

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
            $aes_key = base64_decode($encryption->generate_aes_key()); // 32 bytes
            $iv = base64_decode($encryption->generate_iv()); // 16 bytes

            // 3. Prepare payload (повний, не обрізаний)
            $payload = [
                'name' => $user_data['name'] ?? '',
                'email' => $user_data['email'] ?? '',
                'password' => isset($user_data['password']) ? hash('sha256', $user_data['password']) : '',
                'tools' => $user_data['tools'] ?? [],
                'ts' => time()
            ];
            $json_payload = json_encode($payload);
            if ($json_payload === false) {
                throw new \Exception('Failed to encode registration payload to JSON: ' . json_last_error_msg());
            }

            // 4. Encrypt payload with AES
            $payload_b64 = $encryption->encrypt_with_aes($json_payload, $aes_key, base64_encode($iv));

            // 5. Encrypt AES key with RSA
            $encrypted_key_b64 = $encryption->encrypt_with_rsa($aes_key, $rsa_key);

            // 6. Prepare request body
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
            \DIT\save_user_data($user_name, $customer_id, $permanent_aes_key);

            $logger->log_api_interaction('Register Customer Hybrid', [
                'customer_id' => $customer_id
            ], 'success', 'Customer registered successfully with hybrid encryption.');

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
            'encryption_method' => 'rsa_two_step',
            'user_data_keys' => array_keys($user_data)
        ], 'info', 'Starting two-step registration process.');

        try {
            // Step 1: Generate temporary AES key locally (as per documentation)
            $temporary_aes_key = $encryption->generate_aes_key(); // 256-bit temporary key

            $logger->log_api_interaction('Register Customer Two-Step', [
                'temporary_aes_key_generated' => true
            ], 'info', 'Generated temporary AES key locally.');

            // Step 2: Prepare the request data with correct field names as server expects
            $request_data = [
                'Name' => $user_data['name'] ?? '',
                'Email' => $user_data['email'] ?? '',
                'Password' => $user_data['password'] ?? '', // Plain password as server expects
                'Description' => $user_data['description'] ?? '',
                'Notes' => $user_data['notes'] ?? '',
                'Tools' => $user_data['tools'] ?? [],
                'AesKey' => $temporary_aes_key, // Temporary AES key
                'SubscriptionTime' => $user_data['subscriptionTime'] ?? '365 days'
            ];

            $json_request = json_encode($request_data);
            if ($json_request === false) {
                throw new Exception('Failed to encode registration request to JSON: ' . json_last_error_msg());
            }

            // Step 3: Call PrepareRegisterCustomerRequest with unencrypted data
            $prepare_url = $this->api_base_url . '/Customers/PrepareRegisterCustomerRequest';

            $logger->log_api_interaction('Prepare Register Customer', [
                'request_url' => $prepare_url,
                'method' => 'PUT',
                'json_payload' => $json_request,
                'request_length' => strlen($json_request),
                'temporary_aes_key_included' => true
            ], 'info', 'Sending prepare request with unencrypted data.');

            $prepare_response = wp_remote_request($prepare_url, [
                'method' => 'PUT',
                'headers' => [
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/json'
                ],
                'body' => $json_request, // Send unencrypted JSON data
                'timeout' => 30
            ]);

            if (is_wp_error($prepare_response)) {
                throw new Exception('Prepare request failed: ' . $prepare_response->get_error_message());
            }

            $prepare_code = wp_remote_retrieve_response_code($prepare_response);
            $prepare_body = wp_remote_retrieve_body($prepare_response);

            $logger->log_api_interaction('Prepare Register Customer', [
                'response_code' => $prepare_code,
                'response_body' => $prepare_body
            ], $prepare_code === 200 ? 'success' : 'error', 'Prepare response received.');

            if ($prepare_code !== 200) {
                throw new Exception('Prepare request failed: HTTP ' . $prepare_code . ' - ' . $prepare_body);
            }

            // Step 4: Parse prepare response to get permanent AES key
            $permanent_aes_key = '';
            if (!empty($prepare_body)) {
                $prepare_data = json_decode($prepare_body, true);
                if ($prepare_data && isset($prepare_data['aesKey'])) {
                    $permanent_aes_key = $prepare_data['aesKey']; // Hex string as per documentation
                    $logger->log_api_interaction('Prepare Register Customer', [
                        'permanent_aes_key_received' => true,
                        'permanent_aes_key_length' => strlen($permanent_aes_key)
                    ], 'success', 'Permanent AES key received from prepare response.');
                } else {
                    // If response is not JSON or doesn't contain aesKey, treat as success
                    $logger->log_api_interaction('Prepare Register Customer', [
                        'note' => 'Prepare response does not contain permanent AES key, will use temporary key'
                    ], 'info', 'Prepare response handled as success indicator.');
                }
            }

            // Step 5: Get server RSA public key for final registration
            $rsa_key = $this->get_server_rsa_key();
            if (!$rsa_key) {
                throw new Exception('Failed to get server RSA public key for final registration.');
            }

            // Step 6: Prepare final registration data with permanent AES key
            $final_request_data = [
                'AesKey' => $permanent_aes_key ?: $temporary_aes_key, // Use permanent key if available
                'Name' => $user_data['name'] ?? '',
                'Description' => $user_data['description'] ?? '',
                'Email' => $user_data['email'] ?? '',
                'Password' => isset($user_data['password']) ? hash('sha256', $user_data['password']) : '',
                'Tools' => $user_data['tools'] ?? [],
                'Notes' => $user_data['notes'] ?? '',
                'SubscriptionTime' => $user_data['subscriptionTime'] ?? '365 days'
            ];

            $final_json_payload = json_encode($final_request_data);
            if ($final_json_payload === false) {
                throw new Exception('Failed to encode final registration payload to JSON: ' . json_last_error_msg());
            }

            // Step 7: Encrypt final payload with RSA
            $encrypted_final_payload = $encryption->encrypt_data_with_rsa($final_json_payload, $rsa_key);
            if (empty($encrypted_final_payload)) {
                throw new Exception('Failed to encrypt final registration payload with RSA.');
            }

            // Step 8: Call RegisterCustomer with encrypted data
            $register_url = $this->api_base_url . '/Customers/RegisterCustomer';

            $logger->log_api_interaction('Register Customer', [
                'request_url' => $register_url,
                'method' => 'PUT',
                'encrypted_payload_length' => strlen($encrypted_final_payload),
                'permanent_aes_key_used' => !empty($permanent_aes_key)
            ], 'info', 'Sending encrypted registration data.');

            $register_response = wp_remote_request($register_url, [
                'method' => 'PUT',
                'headers' => [
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/json'
                ],
                'body' => $encrypted_final_payload, // Send RSA encrypted data
                'timeout' => 30
            ]);

            if (is_wp_error($register_response)) {
                throw new Exception('Registration request failed: ' . $register_response->get_error_message());
            }

            $register_code = wp_remote_retrieve_response_code($register_response);
            $register_body = wp_remote_retrieve_body($register_response);

            $logger->log_api_interaction('Register Customer', [
                'response_code' => $register_code,
                'response_body' => $register_body,
                'request_url_sent' => $register_url,
                'request_method_sent' => 'PUT'
            ], $register_code === 200 ? 'success' : 'error', 'Registration response received.');

            if ($register_code !== 200) {
                throw new Exception('Registration failed: HTTP ' . $register_code . ' - ' . $register_body);
            }

            // Step 9: Parse the registration response
            $response_data = json_decode($register_body, true);
            if (!$response_data) {
                throw new Exception('Invalid response format: not JSON');
            }

            if (!isset($response_data['customerId'])) {
                throw new Exception('Invalid response format: missing customerId');
            }

            $customer_id = (int) $response_data['customerId'];
            $user_name = $user_data['name'] ?? '';

            // Use permanent AES key from prepare response, or fallback to temporary key
            $final_aes_key = $permanent_aes_key ?: $temporary_aes_key;

            // Cache the username, CustomerId, and the permanent AES key
            \DIT\save_user_data($user_name, $customer_id, $final_aes_key);

            $logger->log_api_interaction('Register Customer Two-Step', [
                'customer_id' => $customer_id,
                'encryption_method' => 'rsa_two_step',
                'permanent_aes_key_stored' => !empty($permanent_aes_key),
                'temporary_aes_key_used' => empty($permanent_aes_key),
                'final_aes_key_length' => strlen($final_aes_key)
            ], 'success', 'Customer registered successfully with two-step process.');

            return $customer_id;
        } catch (Exception $e) {
            $logger->log_api_interaction('Register Customer Two-Step', [
                'error' => $e->getMessage(),
                'encryption_method' => 'rsa_two_step'
            ], 'error', 'Registration failed with two-step process.');
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
                'Email' => $email,
                'Password' => $password
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
}
