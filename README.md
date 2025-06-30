# DIT Integration Plugin

WordPress plugin for integration with Data Integrity Tool API. The plugin provides user registration, data encryption, and interaction with DIT API.

## Table of Contents

- [Installation](#installation)
- [Architecture](#architecture)
- [Classes and Methods](#classes-and-methods)
- [API Endpoints](#api-endpoints)
- [Encryption](#encryption)
- [Logging](#logging)
- [Usage](#usage)
- [Testing](#testing)
- [Known Issues](#known-issues)

## Installation

1. Download the plugin to `/wp-content/plugins/dit-integration/` directory
2. Activate the plugin in WordPress admin panel
3. Configure API parameters in "DIT Integration" section

## Architecture

The plugin uses object-oriented architecture with the following main components:

```
dit-integration/
├── dit-integration.php          # Main plugin file
├── includes/
│   ├── class-core.php           # Main initialization class
│   ├── class-api.php            # API interaction
│   ├── class-encryption.php     # Encryption/decryption
│   ├── class-logger.php         # Logging
│   ├── class-wpforms.php        # WPForms integration
│   └── helpers.php              # Helper functions
├── admin/
│   └── class-admin.php          # Admin panel
└── assets/
    ├── css/
    └── js/
```

## Classes and Methods

### Core Class (`includes/class-core.php`)

Main class for plugin initialization and dependency management.

#### Methods:

- **`__construct()`** - Class constructor
- **`init()`** - Initialize all components
- **`get_instance()`** - Singleton pattern
- **`run()`** - Run the plugin

#### Dependencies:
- Logger
- Admin
- API
- Encryption
- WPForms

### API Class (`includes/class-api.php`)

Class for interaction with DIT API.

#### Properties:
- `$api_base_url` - Base API URL
- `$cached_rsa_key` - Cached RSA key
- `$rsa_key_cache_timestamp` - Cache timestamp

#### Methods:

##### Private methods:
- **`get_server_rsa_key()`** - Get RSA key from server
- **`send_request_with_curl()`** - Send requests via cURL
- **`format_curl_headers()`** - Format headers for cURL
- **`parse_curl_headers()`** - Parse response headers

##### Public methods:
- **`register_customer(array $user_data)`** - Register customer
- **`login(string $email, string $sha256password)`** - Authentication
- **`check_email(string $email)`** - Check email
- **`allocate_licenses(int $customer_id, int $metering_count, int $subscription_days)`** - Allocate licenses
- **`send_data($data)`** - Send data
- **`clear_rsa_key_cache()`** - Clear RSA key cache
- **`get_rsa_key_cache_status()`** - RSA key cache status
- **`test_connection()`** - Test connection
- **`get_user_permanent_aes_key(int $customer_id)`** - Get permanent AES key
- **`get_user_name(int $customer_id)`** - Get user name
- **`set_user_permanent_aes_key_active(int $customer_id)`** - Activate permanent AES key

### Encryption Class (`includes/class-encryption.php`)

Class for data encryption and decryption.

#### Methods:

##### AES encryption:
- **`encrypt_with_aes(string $data, string $key, string $iv)`** - AES encryption
- **`decrypt_with_aes(string $encrypted_data, string $key, string $iv)`** - AES decryption
- **`generate_iv()`** - Generate IV (16 bytes)

##### RSA encryption:
- **`encrypt_with_rsa(string $aes_key, string $rsa_public_key_base64)`** - RSA encryption of AES key
- **`encrypt_data_with_rsa(string $data, string $rsa_public_key_base64)`** - RSA encryption of data
- **`convert_to_pem_format(string $rsa_public_key_base64)`** - Convert to PEM format
- **`validate_rsa_key(string $rsa_public_key_base64)`** - Validate RSA key

##### Helper methods:
- **`generate_test_rsa_key()`** - Generate test RSA key
- **`encrypt_request_payload(array $payload, string $rsa_key_base64)`** - Encrypt request payload
- **`set_user_permanent_aes_key(string $key)`** - Set permanent AES key
- **`clear_temporary_aes_key()`** - Clear temporary AES key

### Logger Class (`includes/class-logger.php`)

Class for logging all plugin operations.

#### Methods:
- **`log_api_interaction(string $action, array $data, string $level, string $message)`** - Log API interactions
- **`get_logs(int $limit = 100)`** - Get logs
- **`clear_logs()`** - Clear logs
- **`export_logs()`** - Export logs

### Admin Class (`admin/class-admin.php`)

Class for admin panel and AJAX handling.

#### Methods:
- **`init()`** - Initialize admin panel
- **`add_admin_menu()`** - Add menu
- **`enqueue_scripts()`** - Enqueue scripts
- **`render_main_page()`** - Render main page
- **`render_logs_page()`** - Render logs page

##### AJAX methods:
- **`handle_test_connection()`** - Test connection
- **`handle_clear_logs()`** - Clear logs
- **`handle_export_logs()`** - Export logs

### WPForms Class (`includes/class-wpforms.php`)

Class for WPForms integration.

#### Methods:
- **`init()`** - Initialize integration
- **`handle_form_submission(array $fields, array $entry, array $form_data)`** - Handle form submission
- **`register_user_from_form(array $form_data)`** - Register user from form
- **`extract_user_data(array $submitted_data, array $form_data)`** - Extract and process form data
- **`process_checkbox_values(array $fields, array $entry, array $form_data)`** - Process checkbox values (deprecated)

#### Checkbox Processing

The plugin automatically processes checkbox fields to extract tool selections. Checkboxes must follow the format:

```
Tool Name | Number
```

Example:
- `Data Integrity Tool | 0`
- `Audit Trail | 1`
- `Compliance Checker | 2`
- `Report Generator | 3`

The plugin extracts the numbers and sends them as the `tools` array to the API. If no checkboxes are selected, an empty array `[]` is sent.

For detailed setup instructions, see [CHECKBOX_SETUP_GUIDE.md](CHECKBOX_SETUP_GUIDE.md).

## API Endpoints

### Base URL
```
https://api.dataintegritytool.org:5001
```

### Available endpoints:

1. **`/Cryptography/GetServerRSAPublicKey`** - Get RSA key
2. **`/Customers/RegisterCustomer`** - Register customer
3. **`/Session/Login`** - Authentication
4. **`/Customers/CheckEmail`** - Check email
5. **`/Licensing/AllocateLicenses`** - Allocate licenses
6. **`/api/v1/submit`** - Submit data

## Encryption

### Registration encryption process:

1. **Prepare payload:**
   ```php
   $registration_payload = [
       'AesKey'      => $user_data['aes_key'],
       'Name'        => $user_data['name'],
       'Description' => $user_data['description'],
       'Email'       => $user_data['email'],
       'Password'    => hash('sha256', $user_data['password']),
       'Tools'       => $user_data['tools'],
       'Notes'       => $user_data['notes'],
   ];
   ```

2. **JSON encoding:**
   ```php
   $json_payload = json_encode($registration_payload);
   ```

3. **Generate IV:**
   ```php
   $iv = $encryption->generate_iv(); // 16 bytes, base64 encoded
   ```

4. **RSA encryption:**
   ```php
   $encrypted_payload = $encryption->encrypt_data_with_rsa($json_payload, $rsa_key);
   ```

5. **EncryptionWrapperDIT structure:**
   ```php
   $encryption_wrapper = [
       'primaryKey'    => 0,  // 0 for new registration
       'type'          => 2,  // 2 = Customer
       'aesIV'         => $iv,
       'encryptedData' => $encrypted_payload
   ];
   ```

### Encryption types:
- **RSA** - for encrypting AES keys and data
- **AES-256-CBC** - for encrypting main data
- **SHA-256** - for password hashing

## Logging

### Log levels:
- **info** - Informational messages
- **success** - Successful operations
- **warning** - Warnings
- **error** - Errors

### What is logged:
- All API interactions
- Encryption process
- Errors and exceptions
- Operation statuses

## Usage

### Register user:
```php
$api = Core::get_instance()->api;
$user_data = [
    'name' => 'John Doe',
    'email' => 'john@example.com',
    'password' => 'password123',
    'description' => 'Test user',
    'tools' => ['tool1', 'tool2'],
    'notes' => 'Test notes',
    'aes_key' => base64_encode(random_bytes(32))
];

$customer_id = $api->register_customer($user_data);
```

### Check email:
```php
$result = $api->check_email('test@example.com');
// 0 - email available, 1 - email taken
```

### Authentication:
```php
$auth_data = $api->login('test@example.com', hash('sha256', 'password'));
```

## Testing

### Available test files:
- `test-encryption-wrapper.php` - Test EncryptionWrapperDIT structure
- `test-simple-encryption-wrapper.php` - Simple encryption test
- `test-real-encryption-wrapper.php` - Test with real data
- `test-actual-request.php` - Test actual request
- `test-null-checks.php` - Test null checks
- `test-autoloader.php` - Test autoloader
- `test-encoding-simple.php` - Test encoding
- `test-registration-fixed.php` - Test registration
- `test-checkbox-processing.php` - Test checkbox processing
- `test-cookie-storage.php` - Test cookie storage
- `test-cookie-size.php` - Test cookie size limits

### Run tests:
```bash
php test-encryption-wrapper.php
php test-simple-encryption-wrapper.php
php test-checkbox-processing.php
```

### Checkbox Testing

To test checkbox processing:

1. **Run the test script:**
   ```bash
   php test-checkbox-processing.php
   ```

2. **Test different scenarios:**
   - Single checkbox selection
   - Multiple checkbox selections
   - No checkbox selection (default values)
   - Mixed tool selections

3. **Verify output:**
   - Check that numbers are extracted correctly
   - Verify tools array format
   - Confirm default values when no selection

## Known Issues

### 1. Base64 Decoding Error
**Problem:** Server cannot decode Base64 string due to format issues.

**Server error:**
```
System.FormatException: The input is not a valid Base-64 string as it contains a non-base 64 character, more than two padding characters, or an illegal character among the padding characters.
   at System.Convert.FromBase64CharPtr(Char* inputPtr, Int32 inputLength)
   at System.Convert.FromBase64String(String s)
   at DataIntegrityTool.Services.ServerCryptographyService.DecryptRSA(String requestEncryptedB64)
```

**Current status:** 
- ✅ JSON escaping fixed (removed `\/` issue)
- ✅ Proper URL encoding implemented (`+` → `%2B`, `/` → `%2F`, `=` → `%3D`)
- ❌ Server still cannot decode Base64 string

**Possible causes:**
1. Server expects different Base64 format
2. RSA encryption creates incompatible Base64
3. Server-side processing issue

**Status:** Requires investigation with API developers

### 2. API Format Mismatch (Resolved)
**Problem:** Server expected `registerUserB64` field, but code sent `EncryptionWrapperDIT` structure.

**Status:** ✅ Resolved - Now using correct `registerCustomerB64` query parameter

### 3. Documentation vs Implementation (Resolved)
**Problem:** Documentation described `EncryptionWrapperDIT` structure, but server expected different format.

**Status:** ✅ Resolved - Now using direct RSA encryption without wrapper

## Configuration

### Required PHP extensions:
- `openssl` - for encryption
- `curl` - for HTTP requests
- `json` - for JSON processing

### WordPress requirements:
- WordPress 5.0+
- PHP 7.4+

## License

This plugin is developed for Data Integrity Tool. All rights reserved.

## Support

For technical support, contact API developers or create issues in the repository.

---

**Version:** 1.0.1  
**Last updated:** June 23, 2025 