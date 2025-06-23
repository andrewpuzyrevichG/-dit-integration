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
            error_log('DIT Integration: Using cached RSA key');
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

            // LOGGING RAW KEY
            error_log('DIT Integration: [RSA] Raw key from API (first 100 chars): ' . substr($body, 0, 100));
            error_log('DIT Integration: [RSA] Raw key from API (last 100 chars): ' . substr($body, -100));
            error_log('DIT Integration: [RSA] Raw key length: ' . strlen($body));
            error_log('DIT Integration: [RSA] Raw key contains newlines: ' . (strpos($body, "\n") !== false ? 'yes' : 'no'));
            error_log('DIT Integration: [RSA] Raw key contains spaces: ' . (strpos($body, " ") !== false ? 'yes' : 'no'));

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
                    'key_length' => strlen($body),
                    'cached' => true
                ],
                'success',
                'Successfully retrieved and cached RSA key'
            );

            // LOGGING PEM FORMAT
            $encryption = $core->encryption;
            if ($encryption && method_exists($encryption, 'convert_to_pem_format')) {
                $pem = $encryption->convert_to_pem_format($body);
                error_log('DIT Integration: [RSA] PEM key (first 100 chars): ' . substr($pem, 0, 100));
                error_log('DIT Integration: [RSA] PEM key (last 100 chars): ' . substr($pem, -100));
                error_log('DIT Integration: [RSA] PEM key length: ' . strlen($pem));
            }

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
     * Register a new customer
     *
     * @param array $user_data User data to register
     * @return int|null Customer ID or null on failure
     */
    public function register_customer(array $user_data): ?int
    {
        $core = Core::get_instance();
        $logger = $core->logger;
        $encryption = $core->encryption;

        $logger->log_api_interaction('Register Customer', [], 'info', 'Starting registration process.');

        try {
            // Step 1: Get RSA public key from the server
            $rsa_key = $this->get_server_rsa_key();
            if (!$rsa_key) {
                throw new Exception('Failed to get server RSA public key for registration.');
            }

            // Step 2: Prepare the raw data payload for encryption
            $registration_payload = [
                'Name' => $user_data['name'] ?? '',
                'Description' => $user_data['description'] ?? '',
                'Email' => $user_data['email'] ?? '',
                'PasswordHash' => hash('sha256', $user_data['password'] ?? ''),
                'Tools' => $user_data['tools'] ?? [0, 1, 2],
                'Notes' => $user_data['notes'] ?? ''
            ];

            // Step 3: Encrypt the payload using the compliant AES+RSA method
            $encryption_wrapper = $encryption->encrypt_request_payload($registration_payload, $rsa_key);
            if (empty($encryption_wrapper)) {
                throw new Exception('Failed to encrypt the registration payload.');
            }
            $logger->log_api_interaction('Register Customer', ['wrapper_keys' => array_keys($encryption_wrapper)], 'info', 'Payload encrypted successfully.');

            // The API expects a JSON of our encryption wrapper, sent as a query string parameter.
            $register_user_b64 = json_encode($encryption_wrapper);

            // Manually build the URL with rawurlencode to ensure RFC 3986 compliance,
            // which is more robust for Base64 strings than the default WordPress encoding.
            $url = $this->api_base_url . '/Customers/RegisterCustomer?registerUserB64=' . rawurlencode($register_user_b64);

            $logger->log_api_interaction(
                'Register Customer',
                [
                    'url' => $url,
                    'method' => 'PUT',
                    'payload_location' => 'query_string',
                    'encoding' => 'rawurlencode'
                ],
                'info',
                'Final payload prepared for sending via query string.'
            );

            // Make the API request with the payload in the query string and an empty body.
            $response = wp_remote_request(
                $url,
                [
                    'method'      => 'PUT',
                    'timeout'     => 45,
                    'headers'     => [
                        'Accept'       => 'application/json',
                        'User-Agent'   => 'DIT-WordPress-Plugin/1.0.1'
                    ],
                    'body'        => null, // Body is empty as per documentation
                    'sslverify'   => true,
                ]
            );

            // Step 6: Process the response
            if (is_wp_error($response)) {
                throw new Exception('API request failed: ' . $response->get_error_message());
            }

            $response_code = wp_remote_retrieve_response_code($response);
            $response_body = wp_remote_retrieve_body($response);

            $logger->log_api_interaction(
                'Register Customer',
                [
                    'response_code' => $response_code,
                    'response_body_length' => strlen($response_body),
                    'response_body_preview' => substr($response_body, 0, 500)
                ],
                $response_code === 200 ? 'success' : 'error',
                'Received API response.'
            );

            if ($response_code !== 200) {
                // Provide more detailed error logging
                $error_message = 'Registration failed with status ' . $response_code . ': ' . $response_body;
                $decoded_body = json_decode($response_body, true);
                if (json_last_error() === JSON_ERROR_NONE && isset($decoded_body['errors'])) {
                    $error_message .= ' | Validation Errors: ' . print_r($decoded_body['errors'], true);
                }
                throw new Exception($error_message);
            }

            $data = json_decode($response_body, true);
            if (!isset($data['customerId'])) {
                throw new Exception('Invalid registration response: missing customerId.');
            }

            $logger->log_api_interaction(
                'Register Customer',
                ['customer_id' => $data['customerId']],
                'success',
                'Customer registered successfully!'
            );

            return (int) $data['customerId'];
        } catch (Exception $e) {
            $logger->log_api_interaction('Register Customer', ['error' => $e->getMessage()], 'error', 'Registration process failed.');
            error_log('DIT Integration: Failed to register customer - ' . $e->getMessage());
            return null;
        }
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
            'key_length' => $is_cached ? strlen($this->cached_rsa_key) : 0
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
            $results['rsa_key_length'] = $rsa_key ? strlen($rsa_key) : 0;
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
                    'response_length' => strlen(wp_remote_retrieve_body($response))
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
}
