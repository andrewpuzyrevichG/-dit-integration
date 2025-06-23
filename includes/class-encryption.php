<?php

/**
 * DIT Encryption Class
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
 * Class Encryption
 * Handles encryption operations for DIT integration
 */
class Encryption
{
    private $active_key = null;

    public function store_aes_key(string $aes_key): void
    {
        $this->active_key = $aes_key;
    }

    public function clear_temporary_aes_key(): void
    {
        $this->active_key = null;
    }

    public function set_user_permanent_aes_key(string $permanent_aes_key): void
    {
        $this->active_key = $permanent_aes_key;
    }

    public function init()
    {
        if (!extension_loaded('openssl')) {
            error_log('DIT Integration: OpenSSL extension is not available');
        }
    }

    private function display_error(string $message, string $type = 'error'): void
    {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            if (!wp_doing_ajax() && defined('WP_DEBUG_DISPLAY') && WP_DEBUG_DISPLAY) {
                echo '<div class="notice notice-' . esc_attr($type) . ' is-dismissible">';
                echo '<p><strong>DIT Integration:</strong> ' . esc_html($message) . '</p>';
                echo '</div>';
            }

            if (defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
                error_log('DIT Integration: ' . $message);
            }
        }
    }

    public function generate_aes_key(): string
    {
        try {
            $key = random_bytes(32);
            return base64_encode($key);
        } catch (Exception $e) {
            $this->display_error('Failed to generate AES key: ' . $e->getMessage());
            throw $e;
        }
    }

    public function generate_iv(): string
    {
        try {
            // Generate a random 128-bit (16-byte) initialization vector
            $iv = random_bytes(16);
            return base64_encode($iv);
        } catch (Exception $e) {
            $this->display_error('Failed to generate IV: ' . $e->getMessage());
            throw $e;
        }
    }

    public function encrypt_with_aes(string $data, string $aes_key, string $base64_iv): string
    {
        try {
            // Check AES key length - use mb_strlen for binary data
            if (mb_strlen($aes_key, '8bit') !== 32) {
                throw new Exception('Invalid AES key length: must be 32 bytes');
            }

            // Decode base64 IV to get binary data
            $iv = base64_decode($base64_iv);
            if ($iv === false || mb_strlen($iv, '8bit') !== 16) {
                throw new Exception('Invalid IV format or length');
            }

            $encrypted = openssl_encrypt(
                $data,
                'AES-256-CBC',
                $aes_key,
                OPENSSL_RAW_DATA,
                $iv
            );

            if ($encrypted === false) {
                throw new Exception('AES encryption failed: ' . openssl_error_string());
            }

            return base64_encode($encrypted);
        } catch (Exception $e) {
            $this->display_error('AES encryption error: ' . $e->getMessage());
            throw $e;
        }
    }

    public function decrypt_with_aes(string $base64_encrypted, string $aes_key, string $base64_iv): string
    {
        try {
            // Check AES key length - use mb_strlen for binary data
            if (mb_strlen($aes_key, '8bit') !== 32) {
                throw new Exception('Invalid AES key length: must be 32 bytes');
            }

            $iv = base64_decode($base64_iv);
            if ($iv === false || mb_strlen($iv, '8bit') !== 16) {
                throw new Exception('Invalid IV format or length');
            }

            $encrypted = base64_decode($base64_encrypted);
            if ($encrypted === false) {
                throw new Exception('Invalid encrypted data format');
            }

            $decrypted = openssl_decrypt(
                $encrypted,
                'AES-256-CBC',
                $aes_key,
                OPENSSL_RAW_DATA,
                $iv
            );

            if ($decrypted === false) {
                throw new Exception('AES decryption failed: ' . openssl_error_string());
            }

            return $decrypted;
        } catch (Exception $e) {
            $this->display_error('AES decryption error: ' . $e->getMessage());
            throw $e;
        }
    }

    public function encrypt_with_rsa(string $aes_key, string $rsa_public_key_base64): string
    {
        try {
            // AES key must be raw binary 32 bytes - use mb_strlen for binary data
            if (mb_strlen($aes_key, '8bit') !== 32) {
                throw new Exception('Invalid AES key length: must be 32 bytes of raw binary');
            }

            // Construct PEM format
            $public_key_pem = $this->convert_to_pem_format($rsa_public_key_base64);

            // Import public key
            $public_key_resource = openssl_pkey_get_public($public_key_pem);
            if ($public_key_resource === false) {
                $err = openssl_error_string();
                throw new Exception('Failed to import RSA public key: ' . $err);
            }

            // Check key type
            $key_details = openssl_pkey_get_details($public_key_resource);
            if ($key_details === false || $key_details['type'] !== OPENSSL_KEYTYPE_RSA) {
                throw new Exception('Invalid key type: must be RSA');
            }

            // Encrypt AES key with RSA
            $encrypted = '';
            $result = openssl_public_encrypt(
                $aes_key,
                $encrypted,
                $public_key_resource,
                OPENSSL_PKCS1_PADDING
            );

            if ($result === false) {
                $err = openssl_error_string();
                throw new Exception('RSA encryption failed: ' . $err);
            }

            return base64_encode($encrypted);
        } catch (Exception $e) {
            $this->display_error('RSA encryption error: ' . $e->getMessage());
            throw $e;
        }
    }

    public function encrypt_data_with_rsa(string $data, string $rsa_public_key_base64): string
    {
        try {
            // Construct PEM format from the base64 public key
            $public_key_pem = $this->convert_to_pem_format($rsa_public_key_base64);

            // Import public key
            $public_key_resource = openssl_pkey_get_public($public_key_pem);
            if ($public_key_resource === false) {
                $err = openssl_error_string();
                error_log("OpenSSL ERROR (importing public key): " . $err);
                throw new Exception('Failed to import RSA public key: ' . $err);
            }

            // Check key type to ensure it is an RSA key
            $key_details = openssl_pkey_get_details($public_key_resource);
            if ($key_details === false || $key_details['type'] !== OPENSSL_KEYTYPE_RSA) {
                throw new Exception('Invalid key type provided: must be an RSA public key.');
            }

            // Encrypt the data with the RSA public key
            $encrypted = '';
            $result = openssl_public_encrypt(
                $data,
                $encrypted,
                $public_key_resource,
                OPENSSL_PKCS1_PADDING
            );

            if ($result === false) {
                $err = openssl_error_string();
                error_log("OpenSSL ERROR (encryption): " . $err);
                throw new Exception('RSA encryption failed: ' . $err);
            }

            // In PHP 8.0+, the key resource is automatically freed.
            // openssl_free_key($public_key_resource);

            // Return the encrypted data, encoded in Base64
            return base64_encode($encrypted);
        } catch (Exception $e) {
            $this->display_error('RSA data encryption error: ' . $e->getMessage());
            throw $e;
        }
    }

    public function convert_to_pem_format(string $rsa_public_key_base64): string
    {
        // Remove any whitespace and newlines
        $raw_key = trim($rsa_public_key_base64);
        $pem = wordwrap($raw_key, 64, "\n", true);

        // Try PKCS#1 format first (RSA-specific) - this is what your key actually is
        $pkcs1_pem = "-----BEGIN RSA PUBLIC KEY-----\n" . $pem . "\n-----END RSA PUBLIC KEY-----\n";

        // Test if PKCS#1 works
        $test_key = openssl_pkey_get_public($pkcs1_pem);
        if ($test_key !== false) {
            return $pkcs1_pem;
        }

        // Fallback to PKCS#8 format (generic)
        $pkcs8_pem = "-----BEGIN PUBLIC KEY-----\n" . $pem . "\n-----END PUBLIC KEY-----\n";

        // Test if PKCS#8 works
        $test_key = openssl_pkey_get_public($pkcs8_pem);
        if ($test_key !== false) {
            return $pkcs8_pem;
        }

        // If both fail, try using OpenSSL CLI conversion
        $converted_pem = $this->convert_via_openssl_cli($rsa_public_key_base64);
        if ($converted_pem !== false) {
            return $converted_pem;
        }

        // Last resort - return PKCS#1 format and let the caller handle errors
        return $pkcs1_pem;
    }

    private function convert_via_openssl_cli(string $rsa_public_key_base64): string|false
    {
        try {
            // Decode base64 to get DER
            $key_bin = base64_decode($rsa_public_key_base64, true);
            if ($key_bin === false) {
                return false;
            }

            // Create temporary files
            $temp_file = tempnam(sys_get_temp_dir(), 'rsa_key_');
            $pem_file = $temp_file . '.pem';

            file_put_contents($temp_file, $key_bin);

            // Convert using OpenSSL command line
            $command = "openssl rsa -pubin -inform DER -in {$temp_file} -outform PEM -out {$pem_file} 2>&1";
            $output = shell_exec($command);

            if (file_exists($pem_file)) {
                $pem_content = file_get_contents($pem_file);
                unlink($temp_file);
                unlink($pem_file);

                if ($pem_content && strpos($pem_content, 'BEGIN PUBLIC KEY') !== false) {
                    return $pem_content;
                }
            }

            // Cleanup if conversion failed
            if (file_exists($temp_file)) {
                unlink($temp_file);
            }
            if (file_exists($pem_file)) {
                unlink($pem_file);
            }

            return false;
        } catch (Exception $e) {
            return false;
        }
    }

    private function try_alternative_key_import(string $rsa_public_key_base64)
    {
        // Try to decode as DER and re-encode
        $key_bin = base64_decode($rsa_public_key_base64, true);
        if ($key_bin === false) {
            error_log("Failed to decode base64 key");
            return false;
        }

        // Try to extract key using openssl
        $temp_file = tempnam(sys_get_temp_dir(), 'rsa_key_');
        file_put_contents($temp_file, $key_bin);

        // Try to convert using openssl command line
        $pem_file = $temp_file . '.pem';
        $command = "openssl rsa -pubin -inform DER -in {$temp_file} -outform PEM -out {$pem_file} 2>&1";

        $output = shell_exec($command);
        error_log("OpenSSL conversion output: " . $output);

        if (file_exists($pem_file)) {
            $pem_content = file_get_contents($pem_file);
            unlink($temp_file);
            unlink($pem_file);

            if ($pem_content && strpos($pem_content, 'BEGIN PUBLIC KEY') !== false) {
                error_log("Successfully converted key using OpenSSL CLI");
                return openssl_pkey_get_public($pem_content);
            }
        }

        unlink($temp_file);
        return false;
    }

    public function get_active_key(): ?string
    {
        return $this->active_key;
    }

    public function is_configured()
    {
        return $this->active_key !== null;
    }

    public function validate_rsa_key(string $rsa_public_key_base64): bool
    {
        // Logging the raw key
        error_log("Entering the validate_rsa_key() method");
        error_log("RSA key raw base64: " . $rsa_public_key_base64);
        error_log("RSA key length: " . mb_strlen($rsa_public_key_base64, '8bit'));

        // Try to decode and analyze
        $key_bin = base64_decode($rsa_public_key_base64, true);
        if ($key_bin !== false) {
            error_log("Key decoded successfully. Length: " . mb_strlen($key_bin, '8bit') . " bytes");
        } else {
            error_log("Failed to decode base64 key");
            return false;
        }

        // Convert to PEM format
        $public_key_pem = $this->convert_to_pem_format($rsa_public_key_base64);
        error_log("PEM KEY for validation:\n" . $public_key_pem);

        $key = openssl_pkey_get_public($public_key_pem);
        if ($key === false) {
            $error = openssl_error_string();
            error_log("RSA key validation failed: " . $error);

            // Try alternative method
            error_log("Trying alternative validation method...");
            $key = $this->try_alternative_key_import($rsa_public_key_base64);

            if ($key === false) {
                return false;
            }
        }

        $details = openssl_pkey_get_details($key);
        if ($details === false || $details['type'] !== OPENSSL_KEYTYPE_RSA) {
            error_log("RSA key is not RSA type or details missing");
            // Remove deprecated function call - key will be freed automatically
            return false;
        }

        error_log("RSA key is valid. Bit length: " . $details['bits']);
        // Remove deprecated function call - key will be freed automatically
        return true;
    }

    public function generate_test_rsa_key(): string
    {
        // Generate a test RSA key pair
        $config = array(
            "digest_alg" => "sha256",
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        );

        $res = openssl_pkey_new($config);
        if ($res === false) {
            throw new Exception('Failed to generate RSA key pair');
        }

        // Extract public key
        $pubKey = openssl_pkey_get_details($res);
        if ($pubKey === false) {
            throw new Exception('Failed to extract public key');
        }

        $public_key_pem = $pubKey['key'];

        // Convert to base64
        $public_key_base64 = base64_encode($public_key_pem);

        error_log("Generated test RSA key: " . $public_key_base64);
        return $public_key_base64;
    }

    public function test_rsa_encryption(): bool
    {
        try {
            $test_key = $this->generate_test_rsa_key();
            $aes_key = random_bytes(32);
            $this->encrypt_with_rsa($aes_key, $test_key);
            return true;
        } catch (Exception $e) {
            $this->display_error('RSA encryption self-test failed: ' . $e->getMessage());
            return false;
        }
    }

    public function encrypt_request_payload(array $payload, string $rsa_key_base64): array
    {
        try {
            // Step 1: Generate a one-time AES key and IV
            $aes_key = random_bytes(32); // 256-bit key
            $iv_base64 = $this->generate_iv(); // 128-bit IV for CBC mode, base64 encoded

            // Step 2: Serialize the payload to JSON
            $json_payload = json_encode($payload);
            if ($json_payload === false) {
                throw new Exception('Failed to serialize payload to JSON: ' . json_last_error_msg());
            }

            // Step 3: Encrypt the JSON payload with the one-time AES key
            $encrypted_data_base64 = $this->encrypt_with_aes($json_payload, $aes_key, $iv_base64);

            // Step 4: Encrypt the one-time AES key with the server's public RSA key
            $encrypted_aes_key_base64 = $this->encrypt_with_rsa($aes_key, $rsa_key_base64);

            // Step 5: Assemble the final encrypted object
            $encrypted_object = [
                'data' => $encrypted_data_base64,
                'key'  => $encrypted_aes_key_base64,
                'iv'   => $iv_base64,
            ];

            // For debugging: log the structure of the created object
            error_log('DIT Integration: Created hybrid encryption payload with keys: ' . implode(', ', array_keys($encrypted_object)));

            return $encrypted_object;
        } catch (Exception $e) {
            $this->display_error('Failed to encrypt request payload: ' . $e->getMessage());
            throw $e;
        }
    }
}
