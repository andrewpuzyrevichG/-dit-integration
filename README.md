# DIT Integration Plugin

WordPress plugin for integration with Data Integrity Tool API. The plugin provides user registration, data encryption, and interaction with DIT API.

## Role System

The plugin uses a role-based system that matches the API specification:

- **User = 1** (typeUser)
- **Customer = 2** (typeCustomer) 
- **Administrator = 3** (typeDIT)

**Important:** All users register as **Customer (2)** by default. Login forms support role selection for existing users.

## Table of Contents

- [Installation](#installation)
- [Role System](#role-system)
- [Architecture](#architecture)
- [Classes and Methods](#classes-and-methods)
- [Dashboard System](#dashboard-system)
- [API Endpoints](#api-endpoints)
- [Encryption](#encryption)
- [Logging](#logging)
- [Usage](#usage)
- [Testing](#testing)
- [Known Issues](#known-issues)
- [Recent Updates](#recent-updates)

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

For detailed setup instructions, see the checkbox processing section above.

## Dashboard System

### Overview

The plugin implements a comprehensive dashboard system with role-based interfaces:

- **Customer (role 2)**: Full management interface with user management and tools
- **User (role 1)**: Basic interface with tool access and account settings

### Dashboard Templates

#### Customer Dashboard (`templates/dashboard/customer-dashboard.php`)

**Features:**
- **User Management**: List, add, and delete users associated with the customer
- **Tools Overview**: Display available tools (Data Integrity Tool, Audit Trail, Compliance Checker, Report Generator)
- **Account Settings**: Change password and view account information

**AJAX Functions:**
- `dit_get_customer_users` - Retrieve user list
- `dit_add_user` - Add new user
- `dit_delete_user` - Delete user
- `dit_update_password` - Update password

#### User Dashboard (`templates/dashboard/user-dashboard.php`)

**Features:**
- **Available Tools**: Display and launch available tools
- **Account Settings**: Change password and view account information
- **Recent Activity**: View recent user activity

**AJAX Functions:**
- `dit_get_user_activity` - Get user activity
- `dit_update_password` - Update password

### Navigation Structure

```
/dashboard/              # Main dashboard (role-specific)
/dashboard/account       # Account settings
/dashboard/users         # User management (Customer only)
/dashboard/licenses      # License management
/dashboard/payments      # Payment history (Customer only)
```

### Security Features

- **Role-based access control**: Different interfaces for different roles
- **Nonce validation**: All AJAX requests validated with WordPress nonces
- **Session management**: Automatic session timeout and activity tracking
- **Input validation**: Server-side validation for all user inputs

### Frontend Implementation

#### JavaScript Files
- `assets/js/dashboard.js` - Core dashboard functionality
- `assets/js/customer-dashboard.js` - Customer-specific features
- `assets/js/user-dashboard.js` - User-specific features

#### CSS Styling
- `assets/css/dashboard.css` - Responsive design with modern UI
- Mobile-friendly layout
- Modal dialogs for user interactions
- Loading states and animations

### Current Status

**Implemented:**
- ✅ Role-based dashboard templates
- ✅ User management for customers
- ✅ Tool display and access
- ✅ Account settings and password changes
- ✅ AJAX handlers for all operations
- ✅ Responsive design and modern UI
- ✅ Security validations and access control

**Mock Data (Ready for API Integration):**
- User lists for customers
- User activity data
- Tool availability information

**Future Enhancements:**
- Real API integration for user management
- Advanced user editing capabilities
- Detailed activity tracking
- Export functionality for reports

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

## Role System Details

### Role Mapping

The plugin uses numeric role IDs that match the API specification:

| Role | Numeric ID | API Value | Description |
|------|------------|-----------|-------------|
| User | 1 | typeUser = 1 | Regular user with basic access |
| Customer | 2 | typeCustomer = 2 | Customer with management rights |
| Administrator | 3 | typeDIT = 3 | Administrator with full access |

### Registration Process

All new registrations automatically assign the **Customer (2)** role:

1. User fills registration form
2. System extracts form data
3. **Role automatically set to Customer (2)**
4. Data sent to API with `role_id = 2`
5. API returns `customer_id`
6. User logged in as Customer

### Login Process

Login forms support role selection for existing users:

1. User fills login form with role selection
2. System maps text role to numeric ID:
   - "user" → 1
   - "customer" → 2
   - "administrator" → 3
3. Login request sent with `role_id`
4. API validates role and returns user data
5. Session created with correct role

### Role Priority in Login

The system determines user role in this order:

1. `role_id` from form submission (highest priority)
2. `customer_id` from API response
3. Saved `customer_id` from registration
4. `user_id` from API response
5. Default to User (1)

### Dashboard Navigation

Dashboard navigation is role-based:

- **Customer (2)**: User Management, License Management, Payment History
- **User (1) & Administrator (3)**: My License

### Legacy Role Migration

The system automatically migrates old text-based roles to numeric IDs:

| Legacy Role | New Role ID |
|-------------|-------------|
| "user" | 1 |
| "customer" | 2 |
| "administrator" | 3 |
| "admin" | 3 |
| "client" | 2 |
| "standard" | 1 |

### Testing Role System

Run the test script to verify the role system:
```bash
php test-role-mapping-simple.php
```

### Migration Script

To migrate existing users to the new role system:
```bash
php migrate-roles-to-api.php
```

## Recent Updates

### Dashboard System Implementation (Latest)

**Date:** January 2025

**Major Features Added:**
- ✅ **Role-based Dashboard Templates**: Separate interfaces for Customer and User roles
- ✅ **Customer Dashboard**: Full user management with add/delete functionality
- ✅ **User Dashboard**: Tool access and account settings
- ✅ **AJAX Integration**: Complete frontend-backend communication
- ✅ **Responsive Design**: Mobile-friendly modern UI
- ✅ **Security Implementation**: Nonce validation and role-based access control

**Technical Implementation:**
- Created `templates/dashboard/` directory with role-specific templates
- Implemented `assets/js/customer-dashboard.js` and `assets/js/user-dashboard.js`
- Enhanced `assets/css/dashboard.css` with modern styling
- Updated `includes/class-dashboard.php` with AJAX handlers
- Added comprehensive security validations

**Files Created/Modified:**
```
templates/dashboard/
├── customer-dashboard.php    # Customer interface
└── user-dashboard.php        # User interface

assets/js/
├── customer-dashboard.js     # Customer functionality
└── user-dashboard.js         # User functionality

assets/css/
└── dashboard.css             # Enhanced styling

includes/
└── class-dashboard.php       # Updated with AJAX handlers
```

**Current Status:**
- Dashboard system fully functional with mock data
- Ready for API integration
- All security measures implemented
- Responsive design completed

### Previous Updates

**Role System Enhancement (December 2024):**
- Implemented numeric role system (1=User, 2=Customer, 3=Administrator)
- Added role determination logic with priority system
- Created session management with role-based access
- Fixed role migration from legacy text-based system

**API Integration (November 2024):**
- Implemented DIT API integration
- Added encryption/decryption system
- Created WPForms integration
- Added comprehensive logging system

## Known Issues
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

## Enhanced Encrypted Response Handling

### Overview
The plugin now includes a comprehensive system for handling encrypted API responses with multiple fallback strategies and detailed logging.

### New Methods

#### `handle_encrypted_response()`
Universal method for processing encrypted API responses.

**Parameters:**
- `$response_body` (string) - Raw response body from API
- `$operation_name` (string) - Name of the operation for logging
- `$context` (array) - Additional context data for logging

**Returns:** `array|null` - Decrypted and parsed data or null on failure

**Features:**
- Automatic JSON parsing attempt first
- Encrypted data detection via regex pattern
- Multiple AES key retrieval strategies
- Multiple IV decryption strategies
- Comprehensive error logging

#### `handle_encrypted_response_with_headers()`
Enhanced version that also checks response headers for IV.

**Parameters:**
- `$response_body` (string) - Raw response body from API
- `$response_headers` (array) - Response headers
- `$operation_name` (string) - Name of the operation for logging
- `$context` (array) - Additional context data for logging

**Returns:** `array|null` - Decrypted and parsed data or null on failure

**Features:**
- All features from `handle_encrypted_response()`
- IV extraction from response headers
- Header IV decryption attempt before fallback strategies

#### `get_aes_key_for_decryption()`
Retrieves AES key from multiple sources with fallback strategy.

**Returns:** `string|null` - AES key or null if not found

**Retrieval Order:**
1. Session Manager
2. Cookies
3. Encryption Class
4. WordPress User Meta

#### `attempt_decryption_with_multiple_ivs()`
Attempts decryption with different IV strategies.

**Parameters:**
- `$encrypted_data` (string) - Base64 encoded encrypted data
- `$aes_key` (string) - AES key for decryption
- `$operation_name` (string) - Name of the operation for logging
- `$context` (array) - Additional context data for logging

**Returns:** `string|null` - Decrypted data or null on failure

**IV Strategies:**
- `zero_iv` - 16 bytes of zeros
- `one_iv` - 16 bytes of ones
- `random_iv` - Random 16 bytes (unlikely to work)

#### `store_aes_key_redundantly()`
Stores AES key in multiple locations for redundancy.

**Parameters:**
- `$aes_key` (string) - AES key to store
- `$user_id` (int) - User ID for WordPress user meta

**Returns:** `bool` - True if key was stored successfully

**Storage Locations:**
1. Session Manager
2. Encryption Class
3. Cookies
4. WordPress User Meta

#### `clear_aes_key_from_all_locations()`
Clears AES key from all storage locations.

**Parameters:**
- `$user_id` (int) - User ID for WordPress user meta

**Returns:** `bool` - True if key was cleared successfully

### Usage Example

```php
// In an API method
$data = $this->handle_encrypted_response_with_headers(
    $response_body,
    $response_headers,
    'Get Users For Customer',
    ['user_id' => $customer_id]
);

if ($data === null) {
    throw new Exception('Failed to parse or decrypt response');
}

return $data;
```

### Logging

The system provides detailed logging for all operations:

- **JSON parsing attempts**
- **Encrypted data detection**
- **AES key retrieval from different sources**
- **IV strategy attempts**
- **Decryption success/failure**
- **Storage operations**

### Error Handling

- Graceful fallback between different IV strategies
- Multiple AES key sources for redundancy
- Detailed error messages for debugging
- Comprehensive logging for troubleshooting

### Security Considerations

- IV should ideally be provided by the server in headers
- Current IV strategies are for compatibility/testing
- AES keys are stored in multiple locations for redundancy
- All operations are logged for audit purposes

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

**Version:** 1.1.0  
**Last updated:** July 10, 2025 