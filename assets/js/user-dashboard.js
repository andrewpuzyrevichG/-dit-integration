/**
 * User Dashboard JavaScript
 * Extends the main dashboard functionality for User role
 */

(function ($) {
    'use strict';

    // Extend DITDashboard with user-specific functionality
    $.extend(DITDashboard, {
        // User-specific properties
        currentUserId: dit_ajax.user_id,

        // Initialize user dashboard
        initUserDashboard: function () {
            this.bindUserEvents();
        },

        // Bind user-specific events
        bindUserEvents: function () {
            // Navigation between sections
            $(document).on('click', '.nav-item', function (e) {
                e.preventDefault();
                var section = $(this).data('section');
                DITDashboard.showSection(section);
            });

            // Tool launch buttons
            $(document).on('click', '.tool-launch-btn', function (e) {
                e.preventDefault();
                var toolId = $(this).data('tool-id') || $(this).attr('onclick').match(/'([^']+)'/)[1];
                DITDashboard.launchTool(toolId);
            });
        },

        // Show specific section
        showSection: function (section) {
            // Update navigation
            $('.nav-item').removeClass('active');
            $('.nav-item[data-section="' + section + '"]').addClass('active');

            // Show section content
            $('.content-section').removeClass('active');
            $('#' + section + '-section').addClass('active');

            // Load section-specific data
            switch (section) {
                case 'tools':
                    // Tools are static, no loading needed
                    break;
                case 'account':
                    this.loadCustomerData();
                    break;
            }
        },

        // Launch tool
        launchTool: function (toolId) {
            var toolNames = {
                'data-integrity': 'Data Integrity Tool',
                'audit-trail': 'Audit Trail',
                'compliance-checker': 'Compliance Checker',
                'report-generator': 'Report Generator'
            };

            var toolName = toolNames[toolId] || toolId;
            $('#tool-modal-title').text('Launching ' + toolName);
            $('#tool-launch-modal').show();
            $('#tool-loading').show();
            $('#tool-content').hide();

            var self = this;

            // Simulate tool loading
            setTimeout(function () {
                $('#tool-loading').hide();
                $('#tool-content').html(
                    '<div class="tool-launch-content">' +
                    '<h4>' + toolName + '</h4>' +
                    '<p>Tool is being initialized...</p>' +
                    '<div class="tool-status">' +
                    '<span class="status-badge active">Active</span>' +
                    '</div>' +
                    '<p>This tool will be fully integrated with the DIT API in the next update.</p>' +
                    '</div>'
                ).show();
            }, 2000);
        },

        // Close modal
        closeModal: function (modalId) {
            $('#' + modalId).hide();
        },

        // Load customer data for account settings
        loadCustomerData: function () {
            var self = this;
            console.log('DIT Dashboard: Loading customer data for user ID: ' + (dit_ajax.user_id || 'unknown'));

            $.ajax({
                url: dit_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'dit_get_customer_data',
                    nonce: dit_ajax.nonce
                },
                success: function (response) {
                    if (response.success) {
                        console.log('Customer data received:', response.data);

                        // Populate form fields with customer data
                        $('#first_name').val(response.data.first_name || '');
                        $('#last_name').val(response.data.last_name || '');

                        console.log('Form fields populated - First Name: "' + response.data.first_name + '", Last Name: "' + response.data.last_name + '"');

                        // Update welcome message if we have name data
                        if (response.data.first_name && response.data.last_name) {
                            var userId = dit_ajax.user_id || 'Unknown';
                            $('.dashboard-header p').text('Welcome, ' + response.data.first_name + ' ' + response.data.last_name + ' | User ID: ' + userId);
                        }
                    } else {
                        console.log('Failed to load customer data: ' + (response.data || 'Unknown error'));
                    }
                },
                error: function () {
                    console.log('Failed to load customer data. Please try again.');
                }
            });
        },

        // Update account information
        updateAccount: function () {
            var firstName = $('#first_name').val().trim();
            var lastName = $('#last_name').val().trim();
            var newPassword = $('#new_password').val();
            var confirmPassword = $('#confirm_password').val();

            // Validation
            if (!firstName) {
                this.showMessage('Please enter your first name.', 'error');
                return;
            }

            if (!lastName) {
                this.showMessage('Please enter your last name.', 'error');
                return;
            }

            // Password validation (only if password is provided)
            if (newPassword) {
                if (newPassword.length < 6) {
                    this.showMessage('Password must be at least 6 characters long.', 'error');
                    return;
                }

                if (newPassword !== confirmPassword) {
                    this.showMessage('Passwords do not match.', 'error');
                    return;
                }
            }

            var self = this;
            var $btn = $('.account-form .btn-primary');
            var originalText = $btn.text();
            $btn.addClass('loading').text('Updating...');

            $.ajax({
                url: dit_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'dit_update_account',
                    first_name: firstName,
                    last_name: lastName,
                    new_password: newPassword,
                    nonce: dit_ajax.nonce
                },
                success: function (response) {
                    $btn.removeClass('loading').text(originalText);

                    if (response.success) {
                        self.showMessage('Account updated successfully!', 'success');
                        $('#new_password, #confirm_password').val('');
                    } else {
                        self.showMessage('Failed to update account: ' + (response.data || 'Unknown error'), 'error');
                    }
                },
                error: function () {
                    $btn.removeClass('loading').text(originalText);
                    self.showMessage('Failed to update account. Please try again.', 'error');
                }
            });
        },

        // Update password (kept for backward compatibility)
        updatePassword: function () {
            var newPassword = $('#new_password').val();
            var confirmPassword = $('#confirm_password').val();

            // Validation
            if (!newPassword) {
                this.showMessage('Please enter a new password.', 'error');
                return;
            }

            if (newPassword.length < 6) {
                this.showMessage('Password must be at least 6 characters long.', 'error');
                return;
            }

            if (newPassword !== confirmPassword) {
                this.showMessage('Passwords do not match.', 'error');
                return;
            }

            var self = this;
            var $btn = $('.account-form .btn-primary');
            var originalText = $btn.text();
            $btn.addClass('loading').text('Updating...');

            $.ajax({
                url: dit_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'dit_update_password',
                    new_password: newPassword,
                    nonce: dit_ajax.nonce
                },
                success: function (response) {
                    $btn.removeClass('loading').text(originalText);

                    if (response.success) {
                        self.showMessage('Password updated successfully!', 'success');
                        $('#new_password, #confirm_password').val('');
                    } else {
                        self.showMessage('Failed to update password: ' + (response.data || 'Unknown error'), 'error');
                    }
                },
                error: function () {
                    $btn.removeClass('loading').text(originalText);
                    self.showMessage('Failed to update password. Please try again.', 'error');
                }
            });
        },

        // Get user activity
        getUserActivity: function () {
            var self = this;

            $.ajax({
                url: dit_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'dit_get_user_activity',
                    user_id: this.currentUserId,
                    nonce: dit_ajax.nonce
                },
                success: function (response) {
                    if (response.success) {
                        self.renderUserActivity(response.data);
                    }
                },
                error: function () {
                    // Activity loading failed, but don't show error to user
                    console.log('Failed to load user activity');
                }
            });
        },

        // Render user activity
        renderUserActivity: function (activities) {
            var container = $('.activity-list');

            if (!activities || activities.length === 0) {
                return;
            }

            // For now, we'll keep the static activity items
            // In the future, this can be replaced with dynamic data
        }
    });

    // Initialize user dashboard when document is ready
    $(document).ready(function () {
        DITDashboard.initUserDashboard();
    });

})(jQuery); 