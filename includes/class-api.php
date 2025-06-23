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
     * Register a new customer with different encryption approaches
     *
     * @param array $user_data User data to register
     * @param string $encryption_method Encryption method to use ('rsa', 'aes', 'hybrid')
     * @return int|null Customer ID or null on failure
     */
    public function register_customer_with_method(array $user_data, string $encryption_method = 'rsa'): ?int
    {
        $core = Core::get_instance();
        $logger = $core->logger;
        $encryption = $core->encryption;

        $logger->log_api_interaction('Register Customer', [
            'encryption_method' => $encryption_method
        ], 'info', 'Starting registration process with specified encryption method.');

        try {
            // Step 1: Get RSA public key from the server (if needed)
            $rsa_key = null;
            if (in_array($encryption_method, ['rsa', 'hybrid'])) {
                $rsa_key = $this->get_server_rsa_key();
                if (!$rsa_key) {
                    throw new Exception('Failed to get server RSA public key for registration.');
                }
            }

            // Step 2: Prepare the raw data payload for encryption (optimized for RSA size limits)
            $registration_payload = [
                'ak' => $user_data['aes_key'] ?? '',  // aesKey - shortened
                'n'  => $user_data['name'] ?? '',     // name - shortened
                'e'  => $user_data['email'] ?? '',    // email - shortened
                'p'  => isset($user_data['password']) ? hash('sha256', $user_data['password']) : '', // password - shortened
                't'  => $user_data['tools'] ?? [],    // tools - shortened
                'ts' => time()                        // timestamp - shortened
            ];

            // Log form data (without sensitive information)
            $logger->log_api_interaction('Register Customer', [
                'email' => $user_data['email'] ?? '',
                'has_name' => !empty($user_data['name']),
                'has_password' => !empty($user_data['password']),
                'tools_count' => count($user_data['tools'] ?? []),
                'encryption_method' => $encryption_method
            ], 'info', 'Form data extracted for registration.');

            // Step 3: Convert the payload to a JSON string.
            $json_payload = json_encode($registration_payload);
            if ($json_payload === false) {
                throw new Exception('Failed to encode registration payload to JSON: ' . json_last_error_msg());
            }

            // Step 5: Encrypt the JSON payload based on the chosen method
            $encrypted_payload = '';
            $register_user_b64 = '';

            // Only RSA encryption is supported for this endpoint
            if (strlen($json_payload) > 245) {
                throw new Exception('Payload too large for RSA encryption (' . strlen($json_payload) . ' bytes). Max allowed is 245 bytes. Optimize your data.');
            }
            $encrypted_payload = $encryption->encrypt_data_with_rsa($json_payload, $rsa_key);
            if (empty($encrypted_payload)) {
                throw new Exception('Failed to encrypt the registration JSON payload with RSA.');
            }
            // For RegisterCustomer, send only the RSA-encrypted data (no wrapper)
            $register_user_b64 = $encrypted_payload;

            // Log encryption process
            $logger->log_api_interaction('Register Customer', [
                'json_payload_length' => mb_strlen($json_payload, '8bit'),
                'encrypted_payload_length' => mb_strlen($encrypted_payload, '8bit'),
                'no_wrapper' => true,
                'encryption_method' => 'rsa'
            ], 'info', 'Encryption process completed with rsa method (no wrapper).');

            // Log the actual Base64 string and its length
            $logger->log_api_interaction('Register Customer', [
                'base64_payload_length' => strlen($register_user_b64),
                'base64_payload_first20' => substr($register_user_b64, 0, 20),
                'base64_payload_last20' => substr($register_user_b64, -20),
                'base64_invalid_chars' => preg_match('/[^A-Za-z0-9\/+\=]/', $register_user_b64) ? 'yes' : 'no',
                'base64_full_payload' => $register_user_b64, // Log the full Base64 string
                'base64_contains_plus' => strpos($register_user_b64, '+') !== false ? 'yes' : 'no',
                'base64_contains_slash' => strpos($register_user_b64, '/') !== false ? 'yes' : 'no',
                'base64_contains_equals' => strpos($register_user_b64, '=') !== false ? 'yes' : 'no',
            ], 'debug', 'Base64-encoded RSA payload before sending.', JSON_UNESCAPED_SLASHES);

            // Log the RSA public key fingerprint (SHA-256)
            $rsa_key_fingerprint = null;
            if ($rsa_key) {
                $pem = $encryption->convert_to_pem_format($rsa_key);
                $pem_clean = preg_replace('/-----.*-----|\s/', '', $pem);
                $rsa_key_fingerprint = hash('sha256', base64_decode($pem_clean));
            }
            $logger->log_api_interaction('Register Customer', [
                'rsa_key_fingerprint_sha256' => $rsa_key_fingerprint,
                'rsa_key_length' => strlen($rsa_key),
                'rsa_key_first20' => substr($rsa_key, 0, 20),
                'rsa_key_last20' => substr($rsa_key, -20),
            ], 'debug', 'RSA public key info used for encryption.');

            // Step 8: Send the registration request
            // Use proper URL encoding for Base64 - encode only the necessary characters
            $encoded_base64 = str_replace(['+', '/', '='], ['%2B', '%2F', '%3D'], $register_user_b64);
            $request_url = $this->api_base_url . '/Customers/RegisterCustomer?registerCustomerB64=' . $encoded_base64;

            $logger->log_api_interaction('Register Customer', [
                'request_url' => $request_url,
                'method' => 'PUT',
                'original_base64' => $register_user_b64,
                'encoded_base64' => $encoded_base64,
                'encoded_base64_length' => strlen($encoded_base64),
                'encoded_contains_percent' => strpos($encoded_base64, '%') !== false ? 'yes' : 'no',
                'url_length' => strlen($request_url)
            ], 'info', 'Sending registration request with proper URL encoding.');

            $response = wp_remote_request($request_url, [
                'method' => 'PUT',
                'timeout' => 30,
                'sslverify' => true
            ]);

            if (is_wp_error($response)) {
                throw new Exception('Registration request failed: ' . $response->get_error_message());
            }

            $response_code = wp_remote_retrieve_response_code($response);
            $response_body = wp_remote_retrieve_body($response);

            $logger->log_api_interaction('Register Customer', [
                'response_code' => $response_code,
                'response_body' => $response_body,
                'encryption_method' => $encryption_method
            ], $response_code === 200 ? 'success' : 'error', 'Registration response received.');

            if ($response_code !== 200) {
                throw new Exception('Registration failed: HTTP ' . $response_code . ' - ' . $response_body);
            }

            // Step 9: Parse the response
            $response_data = json_decode($response_body, true);
            if (!$response_data || !isset($response_data['customerId'])) {
                throw new Exception('Invalid response format: missing customerId');
            }

            $customer_id = (int) $response_data['customerId'];

            // Step 10: Save user data for future use
            $user_name = $user_data['name'] ?? '';
            $permanent_aes_key = $response_data['permanentAesKey'] ?? $response_data['aesKey'] ?? '';
            \DIT\save_user_data($user_name, $customer_id, $permanent_aes_key);

            $logger->log_api_interaction('Register Customer', [
                'customer_id' => $customer_id,
                'encryption_method' => $encryption_method
            ], 'success', 'Customer registered successfully with ' . $encryption_method . ' encryption.');

            return $customer_id;
        } catch (Exception $e) {
            $logger->log_api_interaction('Register Customer', [
                'error' => $e->getMessage(),
                'encryption_method' => $encryption_method
            ], 'error', 'Registration failed with ' . $encryption_method . ' encryption.');
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
}
