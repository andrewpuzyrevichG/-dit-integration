<?php

namespace DIT;

/**
 * Class Page_Creator
 * 
 * Handles automatic creation of plugin pages during activation
 */
class Page_Creator
{

    /**
     * Create reset password page if it doesn't exist
     */
    public static function create_reset_password_page(): void
    {
        // Check if page already exists
        $page = get_page_by_path('reset-password');

        if (!$page) {
            // Create new page
            $page_data = array(
                'post_title' => 'Reset Password',
                'post_name' => 'reset-password',
                'post_status' => 'publish',
                'post_type' => 'page',
                'post_content' => '[dit_reset_password_form]', // Use shortcode instead of template
            );

            $page_id = wp_insert_post($page_data);

            if ($page_id) {
                // Set custom template
                update_post_meta($page_id, '_wp_page_template', 'reset-password.php');
            }
        }
    }

    /**
     * Register custom page templates
     */
    public static function register_page_templates($templates)
    {
        $templates['reset-password.php'] = 'Reset Password';
        return $templates;
    }
}
