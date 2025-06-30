<?php

/**
 * Settings page template
 *
 * @package DIT_Integration
 */

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

// Get all WPForms forms
$forms = wpforms()->form->get();
$settings = get_option('dit_settings', []);
?>
<div class="wrap dit-settings-wrap">
    <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

    <form id="dit-settings-form" method="post">
        <table class="form-table">
            <tr>
                <th scope="row">
                    <label for="dit_signup_form"><?php _e('Sign Up Form', 'dit-integration'); ?></label>
                </th>
                <td>
                    <select id="dit_signup_form" name="dit_settings[signup_form]" class="regular-text">
                        <option value=""><?php _e('Select a form', 'dit-integration'); ?></option>
                        <?php if (!empty($forms)) : ?>
                            <?php foreach ($forms as $form) : ?>
                                <option value="<?php echo esc_attr($form->ID); ?>"
                                    <?php selected($settings['signup_form'] ?? '', $form->ID); ?>>
                                    <?php echo esc_html($form->post_title); ?>
                                </option>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </select>
                    <p class="description">
                        <?php _e('Select the WPForms form for user registration.', 'dit-integration'); ?>
                    </p>
                </td>
            </tr>

            <tr>
                <th scope="row">
                    <label for="dit_signin_form"><?php _e('Sign In Form', 'dit-integration'); ?></label>
                </th>
                <td>
                    <select id="dit_signin_form" name="dit_settings[signin_form]" class="regular-text">
                        <option value=""><?php _e('Select a form', 'dit-integration'); ?></option>
                        <?php if (!empty($forms)) : ?>
                            <?php foreach ($forms as $form) : ?>
                                <option value="<?php echo esc_attr($form->ID); ?>"
                                    <?php selected($settings['signin_form'] ?? '', $form->ID); ?>>
                                    <?php echo esc_html($form->post_title); ?>
                                </option>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </select>
                    <p class="description"><?php _e('Select the WPForms form for user login.', 'dit-integration'); ?>
                    </p>
                </td>
            </tr>

            <tr>
                <th scope="row">
                    <label for="dit_license_type"><?php _e('License Type', 'dit-integration'); ?></label>
                </th>
                <td>
                    <select id="dit-settings-license-type" name="dit_settings[license_type]" class="regular-text">
                        <option value="unlimited"
                            <?php selected($settings['license_type'] ?? 'unlimited', 'unlimited'); ?>>
                            <?php _e('Unlimited', 'dit-integration'); ?>
                        </option>
                        <option value="metered" <?php selected($settings['license_type'] ?? 'unlimited', 'metered'); ?>>
                            <?php _e('Metered', 'dit-integration'); ?>
                        </option>
                    </select>
                    <p class="description"><?php _e('Select the type of license to allocate.', 'dit-integration'); ?>
                    </p>
                </td>
            </tr>

            <tr class="dit-metered-fields"
                <?php echo ($settings['license_type'] ?? 'unlimited') === 'metered' ? '' : 'style="display: none;"'; ?>>
                <th scope="row">
                    <label
                        for="dit_metered_license_count"><?php _e('Metered License Count', 'dit-integration'); ?></label>
                </th>
                <td>
                    <input type="number" id="dit_metered_license_count" name="dit_settings[metered_license_count]"
                        class="regular-text" min="1"
                        value="<?php echo esc_attr($settings['metered_license_count'] ?? 100); ?>">
                    <p class="description">
                        <?php _e('Number of licenses to allocate for metered license type.', 'dit-integration'); ?></p>
                </td>
            </tr>

            <tr>
                <th scope="row">
                    <label
                        for="dit_subscription_duration"><?php _e('Subscription Duration', 'dit-integration'); ?></label>
                </th>
                <td>
                    <select id="dit_subscription_duration" name="dit_settings[subscription_duration]"
                        class="regular-text">
                        <option value="monthly"
                            <?php selected($settings['subscription_duration'] ?? 'monthly', 'monthly'); ?>>
                            <?php _e('Monthly', 'dit-integration'); ?>
                        </option>
                        <option value="yearly"
                            <?php selected($settings['subscription_duration'] ?? 'monthly', 'yearly'); ?>>
                            <?php _e('Yearly', 'dit-integration'); ?>
                        </option>
                    </select>
                    <p class="description"><?php _e('Select the duration of the subscription.', 'dit-integration'); ?>
                    </p>
                </td>
            </tr>

            <tr>
                <th scope="row">
                    <label for="dit_debug_mode"><?php _e('Debug Mode', 'dit-integration'); ?></label>
                </th>
                <td>
                    <label>
                        <input type="checkbox" id="dit_debug_mode" name="dit_settings[debug_mode]" value="1"
                            <?php checked($settings['debug_mode'] ?? false); ?>>
                        <?php _e('Enable debug mode for detailed logging', 'dit-integration'); ?>
                    </label>
                </td>
            </tr>
        </table>

        <p class="submit">
            <input type="submit" name="submit" id="submit" class="button button-primary"
                value="<?php esc_attr_e('Save Settings', 'dit-integration'); ?>">
            <button type="button" id="dit-test-api"
                class="button"><?php _e('Test API Connection', 'dit-integration'); ?></button>
        </p>
    </form>
</div>

<style>
    .dit-settings-wrap .form-table th {
        width: 250px;
    }

    .dit-settings-wrap .regular-text {
        min-width: 300px;
    }
</style>