jQuery(document).ready(function ($) {
    'use strict';

    // Handle Clear Logs button click
    $('#dit-clear-logs').on('click', function (e) {
        e.preventDefault();

        const $button = $(this);
        const originalText = $button.text();

        // Disable button and show loading state
        $button.prop('disabled', true);

        // Send AJAX request
        $.ajax({
            url: ditAdmin.ajaxUrl,
            type: 'POST',
            data: {
                action: 'dit_clear_logs',
                nonce: ditAdmin.nonce
            },
            success: function (response) {
                if (response.success) {
                    // Clear the logs display
                    $('#dit-logs-content').text('');
                    showStatus('success', response.data.message);
                } else {
                    showStatus('error', response.data.message);
                }
            },
            error: function (xhr, status, error) {
                showStatus('error', 'Error: ' + error);
            },
            complete: function () {
                // Re-enable button
                $button.prop('disabled', false);
            }
        });
    });

    // Handle Refresh Logs button click
    $('#dit-refresh-logs').on('click', function (e) {
        e.preventDefault();

        const $button = $(this);
        const originalText = $button.text();

        // Disable button and show loading state
        $button.prop('disabled', true);

        // Send AJAX request
        $.ajax({
            url: ditAdmin.ajaxUrl,
            type: 'POST',
            data: {
                action: 'dit_get_logs',
                nonce: ditAdmin.nonce
            },
            success: function (response) {
                if (response.success) {
                    // Update the logs display
                    $('#dit-logs-content').text(response.data.logs);
                    // Update last updated timestamp
                    $('#dit-logs-last-updated').text(new Date().toLocaleString());
                    showStatus('success', 'Logs refreshed successfully.');
                } else {
                    showStatus('error', response.data.message);
                }
            },
            error: function (xhr, status, error) {
                showStatus('error', 'Error: ' + error);
            },
            complete: function () {
                // Re-enable button
                $button.prop('disabled', false);
            }
        });
    });

    // Helper function to show status messages
    function showStatus(type, message) {
        const $status = $('#dit-logs-status');
        $status.removeClass('success error').addClass(type).html(message).show();

        // Auto hide after 5 seconds
        setTimeout(function () {
            $status.fadeOut();
        }, 5000);
    }
});
