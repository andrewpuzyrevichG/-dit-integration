jQuery(document).ready(function ($) {
    'use strict';

    // Handle license type change
    $('#dit-settings-license-type').on('change', function () {
        const isMetered = $(this).val() === 'metered';
        $('.dit-metered-fields')[isMetered ? 'show' : 'hide']();
    });

    // Handle settings form submission
    $('#dit-settings-form').on('submit', function (e) {
        e.preventDefault();
        console.log('DIT Integration: Form submission started');

        const $form = $(this);
        const $submitButton = $form.find('input[type=submit]');
        const originalText = $submitButton.val();

        // Disable submit button and show loading state
        $submitButton.prop('disabled', true).val('Saving...');

        // Get form data
        const formData = new FormData(this);
        formData.append('action', 'dit_save_settings');
        formData.append('nonce', ditAdmin.nonce);

        // Log form data
        console.log('DIT Integration: Form data:');
        for (let pair of formData.entries()) {
            console.log(pair[0] + ': ' + pair[1]);
        }

        // Send AJAX request
        $.ajax({
            url: ditAdmin.ajaxUrl,
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function (response) {
                console.log('DIT Integration: AJAX response:', response);
                if (response.success) {
                    showNotice('success', response.data.message);
                } else {
                    showNotice('error', response.data.message);
                }
            },
            error: function (xhr, status, error) {
                console.log('DIT Integration: AJAX error:', { xhr, status, error });
                showNotice('error', 'Error: ' + error);
            },
            complete: function () {
                // Re-enable submit button
                $submitButton.prop('disabled', false).val(originalText);
                console.log('DIT Integration: Form submission completed');
            }
        });
    });

    // Handle API test button
    $('#dit-test-api').on('click', function (e) {
        e.preventDefault();

        const $button = $(this);
        const originalText = $button.text();

        // Disable button and show loading state
        $button.prop('disabled', true).text('Testing...');

        // Send AJAX request
        $.ajax({
            url: ditAdmin.ajaxUrl,
            type: 'POST',
            data: {
                action: 'dit_test_api',
                nonce: ditAdmin.nonce
            },
            success: function (response) {
                if (response.success) {
                    showNotice('success', response.data.message);
                } else {
                    showNotice('error', response.data.message);
                }
            },
            error: function (xhr, status, error) {
                showNotice('error', 'Error: ' + error);
            },
            complete: function () {
                // Re-enable button
                $button.prop('disabled', false).text(originalText);
            }
        });
    });

    // Helper function to show notices
    function showNotice(type, message) {
        const $notice = $("<div class=\"notice notice-" + type + " is-dismissible\"><p>" + message + "</p></div>");
        $(".wrap h1").after($notice);

        // Auto dismiss after 5 seconds
        setTimeout(function () {
            $notice.fadeOut(function () {
                $(this).remove();
            });
        }, 5000);
    }

    // Initialize tooltips
    $('.dit-tooltip').tooltipster({
        theme: 'tooltipster-light',
        maxWidth: 300,
        animation: 'fade',
        delay: 200,
        side: 'right'
    });
}); 