<?php

/**
 * Template Name: Reset Password
 * 
 * Custom template for password reset functionality
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

get_header();
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
// Enqueue reset password JavaScript
wp_enqueue_script('dit-reset-password', DIT_PLUGIN_URL . 'assets/js/reset-password.js', array('jquery'), DIT_PLUGIN_VERSION, true);

// Localize script with AJAX URL and nonce
wp_localize_script('dit-reset-password', 'dit_reset_ajax', array(
    'ajax_url' => admin_url('admin-ajax.php'),
    'nonce' => wp_create_nonce('dit_reset_password_nonce')
));
?>

<?php get_footer(); ?>