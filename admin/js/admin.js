jQuery(document).ready(function ($) {
    $('#dit-test-api').on('click', function (e) {
        e.preventDefault();

        var $button = $(this);
        var $spinner = $button.next('.spinner');

        $button.prop('disabled', true);
        $spinner.addClass('is-active');

        $.ajax({
            url: ditAdmin.ajaxUrl,
            type: 'POST',
            data: {
                action: 'dit_test_api',
                nonce: ditAdmin.nonce
            },
            success: function (response) {
                if (response.success) {
                    alert('API connection successful!');
                } else {
                    alert('API connection failed: ' + response.data);
                }
            },
            error: function () {
                alert('API connection failed: Network error');
            },
            complete: function () {
                $button.prop('disabled', false);
                $spinner.removeClass('is-active');
            }
        });
    });

    // Handle license type change
    $('select[name="dit_settings[license_type]"]').on('change', function () {
        var licenseType = $(this).val();

        // Enable/disable subscription duration field
        $('input[name="dit_settings[subscription_duration]"]').prop('disabled', licenseType !== 'subscription');

        // Enable/disable metered license count field
        $('input[name="dit_settings[metered_license_count]"]').prop('disabled', licenseType !== 'metered');
    });
}); 