jQuery(document).ready(function ($) {
    'use strict';

    // Store current email for all steps
    let currentEmail = '';

    // Initialize token input handling
    initTokenInput();

    // Step 1: Email Form
    $('#email-form').on('submit', function (e) {
        e.preventDefault();

        const email = $('#reset-email').val().trim();
        if (!email) {
            showError('Please enter your email address');
            return;
        }

        if (!isValidEmail(email)) {
            showError('Please enter a valid email address');
            return;
        }

        currentEmail = email;
        showLoading('Sending reset code...');

        $.ajax({
            url: dit_reset_ajax.ajax_url,
            type: 'POST',
            data: {
                action: 'dit_reset_password_request',
                email: email,
                nonce: dit_reset_ajax.nonce
            },
            success: function (response) {
                hideLoading();
                if (response.success) {
                    showStep('step-token');
                    showSuccess('Reset code sent to ' + email);
                } else {
                    showError(response.data || 'Failed to send reset code');
                }
            },
            error: function () {
                hideLoading();
                showError('An error occurred. Please try again.');
            }
        });
    });

    // Step 2: Token Form
    $('#token-form').on('submit', function (e) {
        e.preventDefault();

        const token = $('#token-input').val();
        if (!token || token.length !== 6) {
            showError('Please enter the 6-digit code');
            return;
        }

        showLoading('Verifying code...');

        $.ajax({
            url: dit_reset_ajax.ajax_url,
            type: 'POST',
            data: {
                action: 'dit_reset_password_verify',
                email: currentEmail,
                token: token,
                nonce: dit_reset_ajax.nonce
            },
            success: function (response) {
                hideLoading();
                if (response.success) {
                    showStep('step-password');
                    showSuccess('Code verified successfully');
                } else {
                    showError(response.data || 'Invalid reset code');
                }
            },
            error: function () {
                hideLoading();
                showError('An error occurred. Please try again.');
            }
        });
    });

    // Resend code button
    $('#resend-code').on('click', function () {
        if (!currentEmail) {
            showError('Please enter your email address first');
            return;
        }

        showLoading('Sending new code...');

        $.ajax({
            url: dit_reset_ajax.ajax_url,
            type: 'POST',
            data: {
                action: 'dit_reset_password_request',
                email: currentEmail,
                nonce: dit_reset_ajax.nonce
            },
            success: function (response) {
                hideLoading();
                if (response.success) {
                    showSuccess('New reset code sent to ' + currentEmail);
                } else {
                    showError(response.data || 'Failed to send new code');
                }
            },
            error: function () {
                hideLoading();
                showError('An error occurred. Please try again.');
            }
        });
    });

    // Step 3: Password Form
    $('#password-form').on('submit', function (e) {
        e.preventDefault();

        const newPassword = $('#new-password').val();
        const confirmPassword = $('#confirm-password').val();

        if (!newPassword) {
            showError('Please enter a new password');
            return;
        }

        if (newPassword.length < 6) {
            showError('Password must be at least 6 characters long');
            return;
        }

        if (newPassword !== confirmPassword) {
            showError('Passwords do not match');
            return;
        }

        const token = $('#token-input').val();
        if (!token) {
            showError('Please enter the reset code first');
            return;
        }

        showLoading('Resetting password...');

        $.ajax({
            url: dit_reset_ajax.ajax_url,
            type: 'POST',
            data: {
                action: 'dit_reset_password_submit',
                email: currentEmail,
                token: token,
                new_password: newPassword,
                confirm_password: confirmPassword,
                nonce: dit_reset_ajax.nonce
            },
            success: function (response) {
                hideLoading();
                if (response.success) {
                    showStep('step-success');
                    showSuccess('Password reset successfully');
                } else {
                    showError(response.data || 'Failed to reset password');
                }
            },
            error: function () {
                hideLoading();
                showError('An error occurred. Please try again.');
            }
        });
    });

    // Helper functions
    function showStep(stepId) {
        $('.reset-step').removeClass('active');
        $('#' + stepId).addClass('active');
        hideError();
    }

    function showError(message) {
        $('#error-message').text(message).show();
        $('html, body').animate({
            scrollTop: $('#error-message').offset().top - 100
        }, 500);
    }

    function hideError() {
        $('#error-message').hide();
    }

    function showSuccess(message) {
        // You can implement a success message system here
        console.log('Success:', message);
    }

    function showLoading(message) {
        // Disable all buttons
        $('.btn').prop('disabled', true);

        // You can implement a loading indicator here
        console.log('Loading:', message);
    }

    function hideLoading() {
        // Enable all buttons
        $('.btn').prop('disabled', false);
    }

    function isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    function initTokenInput() {
        const tokenInputs = $('.token-digit');

        tokenInputs.on('input', function () {
            const currentIndex = parseInt($(this).data('index'));
            const value = $(this).val();

            // Auto-focus next input
            if (value && currentIndex < 5) {
                tokenInputs.eq(currentIndex + 1).focus();
            }

            // Update hidden token input
            updateTokenInput();
        });

        tokenInputs.on('keydown', function (e) {
            const currentIndex = parseInt($(this).data('index'));

            // Handle backspace
            if (e.key === 'Backspace' && !$(this).val() && currentIndex > 0) {
                tokenInputs.eq(currentIndex - 1).focus();
            }
        });

        tokenInputs.on('paste', function (e) {
            e.preventDefault();
            const pastedData = (e.originalEvent.clipboardData || window.clipboardData).getData('text');
            const digits = pastedData.replace(/\D/g, '').slice(0, 6);

            if (digits.length === 6) {
                digits.split('').forEach((digit, index) => {
                    tokenInputs.eq(index).val(digit);
                });
                updateTokenInput();
            }
        });
    }

    function updateTokenInput() {
        let token = '';
        $('.token-digit').each(function () {
            token += $(this).val();
        });
        $('#token-input').val(token);
    }
}); 