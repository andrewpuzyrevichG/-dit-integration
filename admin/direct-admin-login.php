<?php

/**
 * Direct Admin Login - Temporary solution for administrator login
 * Accessible through WordPress admin
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Check admin permissions
if (!current_user_can('manage_options')) {
    wp_die('Unauthorized access');
}

// Handle form submission
if (isset($_POST['admin_login'])) {
    $admin_email = sanitize_email($_POST['admin_email']);
    $admin_password = sanitize_text_field($_POST['admin_password']);

    if (empty($admin_email) || empty($admin_password)) {
        $error_message = 'Please provide both email and password';
    } else {
        // Run the direct login
        $login_result = run_direct_admin_login($admin_email, $admin_password);
    }
}

function run_direct_admin_login($email, $password)
{
    $results = [];

    // Step 1: Create SHA256 hash
    $sha256_password = hash('sha256', $password);
    $results['step1'] = [
        'title' => 'Password Hashing',
        'original_password' => $password,
        'sha256_hash' => $sha256_password,
        'hash_length' => strlen($sha256_password)
    ];

    // Step 2: Build URL for administrator login (role = 3)
    $api_base_url = 'https://api.dataintegritytool.org:5001';
    $url = add_query_arg([
        'email' => urlencode($email),
        'PasswordHash' => urlencode($sha256_password),
        'role' => '3' // Administrator role
    ], $api_base_url . '/Session/Login');

    $results['step2'] = [
        'title' => 'Request URL',
        'base_url' => $api_base_url,
        'endpoint' => '/Session/Login',
        'full_url' => $url,
        'role' => '3',
        'role_name' => 'Administrator',
        'url_length' => strlen($url)
    ];

    // Step 3: Test the request
    $response = wp_remote_get($url, [
        'timeout' => 30,
        'sslverify' => true,
        'user-agent' => 'DIT-Integration-Admin/1.0'
    ]);

    if (is_wp_error($response)) {
        $results['step3'] = [
            'title' => 'Request Result',
            'error' => true,
            'error_message' => $response->get_error_message()
        ];
    } else {
        $response_code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        $headers = wp_remote_retrieve_headers($response);

        $results['step3'] = [
            'title' => 'Request Result',
            'error' => false,
            'response_code' => $response_code,
            'response_body' => $body,
            'response_headers' => $headers,
            'body_length' => strlen($body)
        ];

        // Try to decode JSON
        $data = json_decode($body, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            $results['step4'] = [
                'title' => 'JSON Decoded',
                'success' => true,
                'data' => $data,
                'user_id' => $data['UserId'] ?? null,
                'error_code' => $data['errorcode'] ?? null,
                'error_message' => $data['errormessage'] ?? null
            ];

            // If login successful, create session
            if (isset($data['UserId']) && $data['UserId'] > 0) {
                $session_result = create_admin_session($email, $data, $sha256_password);
                $results['step5'] = [
                    'title' => 'Session Creation',
                    'session_result' => $session_result
                ];
            }
        } else {
            $results['step4'] = [
                'title' => 'JSON Decoded',
                'success' => false,
                'json_error' => json_last_error_msg(),
                'raw_body' => $body
            ];
        }
    }

    return $results;
}

function create_admin_session($email, $login_data, $aes_key)
{
    try {
        // Initialize session manager
        $session_manager = new \DIT\Session_Manager();

        // Prepare user data
        $user_data = [
            'email' => $email,
            'role_id' => 3, // Administrator
            'password' => $aes_key // Use SHA256 hash as AES key
        ];

        // Initialize session
        $session_success = $session_manager->init_session($login_data, $user_data);

        if ($session_success) {
            return [
                'success' => true,
                'message' => 'Administrator session created successfully',
                'redirect_url' => home_url('/dashboard')
            ];
        } else {
            return [
                'success' => false,
                'message' => 'Failed to create administrator session'
            ];
        }
    } catch (Exception $e) {
        return [
            'success' => false,
            'message' => 'Session creation error: ' . $e->getMessage()
        ];
    }
}

?>
<div class="wrap">
    <h1>DIT Integration - Direct Admin Login</h1>
    <p><strong>⚠️ Тимчасове рішення для адміністратора</strong></p>

    <?php if (isset($error_message)): ?>
        <div class="notice notice-error">
            <p><?php echo esc_html($error_message); ?></p>
        </div>
    <?php endif; ?>

    <div class="card">
        <h2>Direct Administrator Login</h2>
        <p>Цей інструмент дозволяє адміністратору увійти безпосередньо через API.</p>

        <form method="post">
            <table class="form-table">
                <tr>
                    <th scope="row"><label for="admin_email">Email адміністратора:</label></th>
                    <td><input type="email" id="admin_email" name="admin_email" class="regular-text" value="<?php echo isset($_POST['admin_email']) ? esc_attr($_POST['admin_email']) : ''; ?>" required></td>
                </tr>
                <tr>
                    <th scope="row"><label for="admin_password">Пароль:</label></th>
                    <td><input type="password" id="admin_password" name="admin_password" class="regular-text" value="<?php echo isset($_POST['admin_password']) ? esc_attr($_POST['admin_password']) : ''; ?>" required></td>
                </tr>
            </table>
            <p class="submit">
                <input type="submit" name="admin_login" class="button button-primary" value="Увійти як адміністратор">
            </p>
        </form>
    </div>

    <?php if (isset($login_result)): ?>
        <div class="card">
            <h2>Login Results</h2>

            <?php foreach ($login_result as $step_key => $step_data): ?>
                <div style="background: #f9f9f9; padding: 15px; margin: 10px 0; border-left: 4px solid #0073aa;">
                    <h3><?php echo esc_html($step_data['title']); ?></h3>

                    <?php if ($step_key === 'step1'): ?>
                        <p><strong>Original Password:</strong> <?php echo esc_html($step_data['original_password']); ?></p>
                        <p><strong>SHA256 Hash:</strong> <code><?php echo esc_html($step_data['sha256_hash']); ?></code></p>
                        <p><strong>Hash Length:</strong> <?php echo esc_html($step_data['hash_length']); ?> characters</p>

                    <?php elseif ($step_key === 'step2'): ?>
                        <p><strong>Base URL:</strong> <?php echo esc_html($step_data['base_url']); ?></p>
                        <p><strong>Endpoint:</strong> <?php echo esc_html($step_data['endpoint']); ?></p>
                        <p><strong>Role:</strong> <?php echo esc_html($step_data['role']); ?> (<?php echo esc_html($step_data['role_name']); ?>)</p>
                        <p><strong>Full URL:</strong> <code><?php echo esc_html($step_data['full_url']); ?></code></p>

                    <?php elseif ($step_key === 'step3'): ?>
                        <?php if ($step_data['error']): ?>
                            <p><strong>Error:</strong> <?php echo esc_html($step_data['error_message']); ?></p>
                        <?php else: ?>
                            <p><strong>Response Code:</strong> <?php echo esc_html($step_data['response_code']); ?></p>
                            <p><strong>Response Body:</strong>
                            <pre><?php echo esc_html($step_data['response_body']); ?></pre>
                            </p>
                        <?php endif; ?>

                    <?php elseif ($step_key === 'step4'): ?>
                        <?php if ($step_data['success']): ?>
                            <p><strong>Login Success:</strong> ✅</p>
                            <p><strong>User ID:</strong> <?php echo esc_html($step_data['user_id']); ?></p>
                            <?php if (isset($step_data['error_code']) && $step_data['error_code'] !== 0): ?>
                                <p><strong>Error Code:</strong> <?php echo esc_html($step_data['error_code']); ?></p>
                                <p><strong>Error Message:</strong> <?php echo esc_html($step_data['error_message']); ?></p>
                            <?php endif; ?>
                        <?php else: ?>
                            <p><strong>JSON Error:</strong> <?php echo esc_html($step_data['json_error']); ?></p>
                            <p><strong>Raw Body:</strong>
                            <pre><?php echo esc_html($step_data['raw_body']); ?></pre>
                            </p>
                        <?php endif; ?>

                    <?php elseif ($step_key === 'step5'): ?>
                        <?php if ($step_data['session_result']['success']): ?>
                            <div style="background: #d4edda; padding: 10px; border-left: 4px solid #28a745;">
                                <p><strong>✅ Session Created Successfully!</strong></p>
                                <p><?php echo esc_html($step_data['session_result']['message']); ?></p>
                                <p><a href="<?php echo esc_url($step_data['session_result']['redirect_url']); ?>" class="button button-primary">Перейти до Dashboard</a></p>
                            </div>
                        <?php else: ?>
                            <div style="background: #f8d7da; padding: 10px; border-left: 4px solid #dc3545;">
                                <p><strong>❌ Session Creation Failed</strong></p>
                                <p><?php echo esc_html($step_data['session_result']['message']); ?></p>
                            </div>
                        <?php endif; ?>
                    <?php endif; ?>
                </div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>

    <div class="card">
        <h2>Instructions</h2>
        <ol>
            <li>Введіть email та пароль адміністратора</li>
            <li>Натисніть "Увійти як адміністратор"</li>
            <li>Система автоматично створить сесію адміністратора</li>
            <li>Після успішного входу перейдіть до Dashboard</li>
        </ol>

        <h3>Important Notes:</h3>
        <ul>
            <li>⚠️ Це тимчасове рішення поки не виправимо Reset Password</li>
            <li>🔒 Доступ тільки для WordPress адміністраторів</li>
            <li>📧 Використовуйте оригінальний пароль (не хеш)</li>
            <li>🔄 Система автоматично хешує пароль перед відправкою</li>
        </ul>
    </div>
</div>