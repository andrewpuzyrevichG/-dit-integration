<?php

namespace DIT;

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class Reset_Password
 * Handles password reset functionality
 */
class Reset_Password
{

    /**
     * Constructor
     */
    public function __construct()
    {
        add_action('wp_ajax_dit_reset_password_request', array($this, 'handle_reset_request'));
        add_action('wp_ajax_nopriv_dit_reset_password_request', array($this, 'handle_reset_request'));

        add_action('wp_ajax_dit_reset_password_verify', array($this, 'handle_token_verification'));
        add_action('wp_ajax_nopriv_dit_reset_password_verify', array($this, 'handle_token_verification'));

        add_action('wp_ajax_dit_reset_password_submit', array($this, 'handle_password_reset'));
        add_action('wp_ajax_nopriv_dit_reset_password_submit', array($this, 'handle_password_reset'));

        // Register shortcode
        add_shortcode('dit_reset_password_form', array($this, 'render_reset_form'));
    }

    /**
     * Handle password reset request (step 1)
     */
    public function handle_reset_request(): void
    {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'] ?? '', 'dit_reset_password_nonce')) {
            wp_send_json_error('Invalid nonce');
            return;
        }

        $email = sanitize_email($_POST['email'] ?? '');
        if (empty($email)) {
            wp_send_json_error('Email is required');
            return;
        }

        try {
            // Get user/customer data by email
            $api = API::get_instance();

            $login_roles = $api->get_login_roles_for_email($email);

            if (!$login_roles) {
                wp_send_json_error('Email not found');
                return;
            }

            // Use the first available role (customer or user)
            // $login_roles is an array of IDs, we need to determine the type
            if (empty($login_roles)) {
                wp_send_json_error('User not found');
                return;
            }

            // For now, assume the first ID is a customer (type 2)
            // In a real implementation, you might need to check both customer and user tables
            $primary_key = $login_roles[0] ?? 0;
            $login_type = 2; // Assume customer for now

            if (!$primary_key) {
                wp_send_json_error('User not found');
                return;
            }

            // Try to get AES key for this customer
            $aes_key = $api->get_user_permanent_aes_key($primary_key);

            // If no AES key found, try to get it from API
            if (!$aes_key) {
                // Try to get AES key via API call
                $aes_key = $api->get_user_permanent_aes_key($primary_key);
            }

            // Request password reset token
            $response = $api->change_password_ask($primary_key, $login_type);

            if (!$response) {
                wp_send_json_error('Failed to request password reset');
                return;
            }

            // Extract user data and token
            $name_first = $response['NameFirst'] ?? '';
            $name_last = $response['NameLast'] ?? '';
            $token = $response['ChangePasswordToken'] ?? '';
            $error_code = $response['ErrorCode'] ?? 1;

            if ($error_code !== 0) {
                wp_send_json_error('Failed to generate reset token');
                return;
            }

            // Send email with token
            $email_sent = $this->send_reset_email($email, $name_first, $name_last, $token);

            if (!$email_sent) {
                wp_send_json_error('Failed to send reset email');
                return;
            }

            // Store data in session for next steps
            $reset_data = [
                'primary_key' => $primary_key,
                'login_type' => $login_type,
                'email' => $email,
                'token' => $token,
                'timestamp' => time()
            ];

            // Store in WordPress options (temporary)
            set_transient('dit_reset_' . md5($email), $reset_data, 3600); // 1 hour expiry

            wp_send_json_success([
                'message' => 'Reset code sent to your email',
                'email' => $email
            ]);
        } catch (\Exception $e) {
            wp_send_json_error('An error occurred while processing your request');
        }
    }

    /**
     * Handle token verification (step 2)
     */
    public function handle_token_verification(): void
    {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'] ?? '', 'dit_reset_password_nonce')) {
            wp_send_json_error('Invalid nonce');
            return;
        }

        $email = sanitize_email($_POST['email'] ?? '');
        $token = sanitize_text_field($_POST['token'] ?? '');

        if (empty($email) || empty($token)) {
            wp_send_json_error('Email and token are required');
            return;
        }

        // Get stored reset data
        $reset_data = get_transient('dit_reset_' . md5($email));

        if (!$reset_data) {
            wp_send_json_error('Reset session expired. Please request a new code.');
            return;
        }

        // Verify token
        if ($reset_data['token'] != $token) {
            wp_send_json_error('Invalid reset code');
            return;
        }

        // Check if token is not expired (1 hour)
        if (time() - $reset_data['timestamp'] > 3600) {
            delete_transient('dit_reset_' . md5($email));
            wp_send_json_error('Reset code expired. Please request a new code.');
            return;
        }

        wp_send_json_success([
            'message' => 'Code verified successfully',
            'email' => $email
        ]);
    }

    /**
     * Handle password reset submission (step 3)
     */
    public function handle_password_reset(): void
    {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'] ?? '', 'dit_reset_password_nonce')) {
            wp_send_json_error('Invalid nonce');
            return;
        }

        $email = sanitize_email($_POST['email'] ?? '');
        $token = sanitize_text_field($_POST['token'] ?? '');
        $new_password = $_POST['new_password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';

        if (empty($email) || empty($token) || empty($new_password) || empty($confirm_password)) {
            wp_send_json_error('All fields are required');
            return;
        }

        if ($new_password !== $confirm_password) {
            wp_send_json_error('Passwords do not match');
            return;
        }

        // Get stored reset data
        $reset_data = get_transient('dit_reset_' . md5($email));

        if (!$reset_data) {
            wp_send_json_error('Reset session expired. Please request a new code.');
            return;
        }

        // Verify token again
        if ($reset_data['token'] != $token) {
            wp_send_json_error('Invalid reset code');
            return;
        }

        try {
            // Submit password reset
            $api = API::get_instance();
            $request_data = [
                'PrimaryKey' => $reset_data['primary_key'],
                'LoginType' => $reset_data['login_type'],
                'Token' => intval($token),
                'PasswordNew' => $new_password
            ];

            $error_code = $api->change_password_answer($request_data);

            if ($error_code !== 0) {
                wp_send_json_error('Failed to reset password. Please try again.');
                return;
            }

            // Clear reset data
            delete_transient('dit_reset_' . md5($email));

            wp_send_json_success([
                'message' => 'Password reset successfully'
            ]);
        } catch (\Exception $e) {
            wp_send_json_error('An error occurred while resetting your password');
        }
    }

    /**
     * Send reset email with token
     */
    private function send_reset_email(string $email, string $name_first, string $name_last, string $token): bool
    {
        $admin_email = get_option('admin_email');
        $site_name = get_bloginfo('name');

        $to = $email;
        $subject = 'Password Reset Code - ' . $site_name;

        // Email template
        $message = "Hello " . ($name_first ? $name_first . ' ' . $name_last : 'there') . ",\n\n";
        $message .= "You have requested to reset your password for " . $site_name . ".\n\n";
        $message .= "Your 6-digit reset code is: %%TOKEN%%\n\n";
        $message .= "This code will expire in 1 hour.\n\n";
        $message .= "If you did not request this password reset, please ignore this email.\n\n";
        $message .= "Best regards,\n" . $site_name . " Team";

        // Replace token placeholder
        $message = str_replace('%%TOKEN%%', $token, $message);

        $headers = [
            'From: ' . $site_name . ' <' . $admin_email . '>',
            'Content-Type: text/plain; charset=UTF-8'
        ];

        return wp_mail($to, $subject, $message, $headers);
    }

    /**
     * Render reset password form (shortcode)
     */
    public function render_reset_form($atts)
    {
        // Enqueue reset password JavaScript
        wp_enqueue_script('dit-reset-password', DIT_PLUGIN_URL . 'assets/js/reset-password.js', array('jquery'), DIT_PLUGIN_VERSION, true);

        // Localize script with AJAX URL and nonce
        wp_localize_script('dit-reset-password', 'dit_reset_ajax', array(
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('dit_reset_password_nonce')
        ));

        ob_start();
?>
        <div class="dit-reset-password-container">
            <div class="dit-reset-password-wrapper">
                <h1>Reset Password</h1>

                <!-- Step 1: Email Form -->
                <div id="step-email" class="reset-step active">
                    <h2>Enter your email address</h2>
                    <p>We'll send you a 6-digit code to reset your password.</p>

                    <form id="email-form" class="reset-form">
                        <div class="form-group">
                            <label for="reset-email">Email Address</label>
                            <input type="email" id="reset-email" name="email" required
                                placeholder="Enter your email address">
                        </div>

                        <button type="submit" class="btn btn-primary">Send Reset Code</button>
                    </form>
                </div>

                <!-- Step 2: Token Form -->
                <div id="step-token" class="reset-step">
                    <h2>Enter the 6-digit code</h2>
                    <p>We've sent a code to your email address.</p>

                    <form id="token-form" class="reset-form">
                        <div class="form-group">
                            <label for="token-input">6-Digit Code</label>
                            <div class="token-input-container">
                                <input type="text" class="token-digit" maxlength="1" data-index="0">
                                <input type="text" class="token-digit" maxlength="1" data-index="1">
                                <input type="text" class="token-digit" maxlength="1" data-index="2">
                                <input type="text" class="token-digit" maxlength="1" data-index="3">
                                <input type="text" class="token-digit" maxlength="1" data-index="4">
                                <input type="text" class="token-digit" maxlength="1" data-index="5">
                            </div>
                            <input type="hidden" id="token-input" name="token">
                        </div>

                        <button type="submit" class="btn btn-primary">Verify Code</button>
                        <button type="button" class="btn btn-secondary" id="resend-code">Resend Code</button>
                    </form>
                </div>

                <!-- Step 3: New Password Form -->
                <div id="step-password" class="reset-step">
                    <h2>Create new password</h2>
                    <p>Enter your new password below.</p>

                    <form id="password-form" class="reset-form">
                        <div class="form-group">
                            <label for="new-password">New Password</label>
                            <input type="password" id="new-password" name="new_password" required
                                placeholder="Enter new password">
                        </div>

                        <div class="form-group">
                            <label for="confirm-password">Confirm Password</label>
                            <input type="password" id="confirm-password" name="confirm_password" required
                                placeholder="Confirm new password">
                        </div>

                        <button type="submit" class="btn btn-primary">Reset Password</button>
                    </form>
                </div>

                <!-- Success Message -->
                <div id="step-success" class="reset-step">
                    <h2>Password Reset Successful</h2>
                    <p>Your password has been successfully reset.</p>
                    <a href="/login" class="btn btn-primary">Go to Login</a>
                </div>

                <!-- Error Messages -->
                <div id="error-message" class="error-message" style="display: none;"></div>
            </div>
        </div>

        <style>
            .dit-reset-password-container {
                max-width: 500px;
                margin: 50px auto;
                padding: 20px;
            }

            .dit-reset-password-wrapper {
                background: #fff;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            }

            .reset-step {
                display: none;
            }

            .reset-step.active {
                display: block;
            }

            .form-group {
                margin-bottom: 20px;
            }

            .form-group label {
                display: block;
                margin-bottom: 5px;
                font-weight: 600;
            }

            .form-group input {
                width: 100%;
                padding: 12px;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-size: 16px;
            }

            .token-input-container {
                display: flex;
                gap: 10px;
                justify-content: center;
            }

            .token-digit {
                width: 50px !important;
                height: 50px;
                text-align: center;
                font-size: 20px;
                font-weight: bold;
            }

            .btn {
                padding: 12px 24px;
                border: none;
                border-radius: 4px;
                font-size: 16px;
                cursor: pointer;
                margin-right: 10px;
            }

            .btn-primary {
                background: #0073aa;
                color: white;
            }

            .btn-secondary {
                background: #6c757d;
                color: white;
            }

            .error-message {
                background: #f8d7da;
                color: #721c24;
                padding: 12px;
                border-radius: 4px;
                margin-top: 20px;
                border: 1px solid #f5c6cb;
            }
        </style>
<?php
        return ob_get_clean();
    }
}
