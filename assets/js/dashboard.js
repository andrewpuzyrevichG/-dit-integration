/**
 * DIT Integration Dashboard JavaScript
 */

(function ($) {
    'use strict';

    // Dashboard object
    var DITDashboard = {
        init: function () {
            this.bindEvents();
            this.initTooltips();
            this.initSessionTimeout();
        },

        bindEvents: function () {
            // Logout button
            $(document).on('click', '.logout-btn', this.handleLogout);

            // Account form submission
            $(document).on('submit', '.account-form', this.handleAccountUpdate);

            // Navigation links
            $(document).on('click', '.nav-item', this.handleNavigation);

            // Auto-refresh session activity
            $(document).on('click mousemove keypress', this.refreshSessionActivity);
        },

        handleLogout: function (e) {
            e.preventDefault();
            console.log('DIT Dashboard: Logout button clicked');

            if (confirm('Are you sure you want to logout?')) {
                var $btn = $(this);
                $btn.addClass('loading').text('Logging out...');
                console.log('DIT Dashboard: Sending logout request...');

                $.ajax({
                    url: dit_ajax.ajax_url,
                    type: 'POST',
                    data: {
                        action: 'dit_logout',
                        nonce: dit_ajax.nonce
                    },
                    success: function (response) {
                        console.log('DIT Dashboard: Logout response:', response);
                        if (response.success) {
                            window.location.href = response.redirect_url;
                        } else {
                            alert('Logout failed. Please try again.');
                            $btn.removeClass('loading').text('Logout');
                        }
                    },
                    error: function (xhr, status, error) {
                        console.error('DIT Dashboard: Logout error:', error);
                        alert('Logout failed. Please try again.');
                        $btn.removeClass('loading').text('Logout');
                    }
                });
            }
        },

        handleAccountUpdate: function (e) {
            e.preventDefault();

            var $form = $(this);
            var $submitBtn = $form.find('.btn-primary');
            var originalText = $submitBtn.text();

            // Basic validation
            var newPassword = $form.find('#new_password').val();
            var confirmPassword = $form.find('#confirm_password').val();

            if (newPassword && newPassword !== confirmPassword) {
                this.showMessage('Passwords do not match.', 'error');
                return false;
            }

            if (newPassword && newPassword.length < 6) {
                this.showMessage('Password must be at least 6 characters long.', 'error');
                return false;
            }

            $submitBtn.addClass('loading').text('Updating...');

            // Here you would typically send the form data to the server
            // For now, we'll just show a success message
            setTimeout(function () {
                $submitBtn.removeClass('loading').text(originalText);
                DITDashboard.showMessage('Account updated successfully!', 'success');
                $form[0].reset();
            }, 1000);

            return false;
        },

        handleNavigation: function (e) {
            // Add loading state to navigation
            var $link = $(this);
            $link.addClass('loading');

            // Remove loading state after navigation
            setTimeout(function () {
                $link.removeClass('loading');
            }, 500);
        },

        refreshSessionActivity: function () {
            // Send heartbeat to keep session alive
            $.ajax({
                url: dit_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'dit_session_heartbeat',
                    nonce: dit_ajax.nonce
                },
                timeout: 5000
            });
        },

        initTooltips: function () {
            // Initialize tooltips if using a tooltip library
            if (typeof $.fn.tooltip !== 'undefined') {
                $('[data-toggle="tooltip"]').tooltip();
            }
        },

        initSessionTimeout: function () {
            // Check session timeout every 5 minutes
            setInterval(function () {
                $.ajax({
                    url: dit_ajax.ajax_url,
                    type: 'POST',
                    data: {
                        action: 'dit_check_session',
                        nonce: dit_ajax.nonce
                    },
                    success: function (response) {
                        if (!response.valid) {
                            alert('Your session has expired. You will be redirected to the login page.');
                            window.location.href = response.redirect_url;
                        }
                    }
                });
            }, 5 * 60 * 1000); // 5 minutes
        },

        showMessage: function (message, type) {
            var $message = $('<div class="message ' + type + '-message">' + message + '</div>');

            // Remove existing messages
            $('.message').remove();

            // Add new message
            $('.dit-dashboard').prepend($message);

            // Auto-remove after 5 seconds
            setTimeout(function () {
                $message.fadeOut(function () {
                    $(this).remove();
                });
            }, 5000);
        },

        // Utility functions
        formatTime: function (seconds) {
            var hours = Math.floor(seconds / 3600);
            var minutes = Math.floor((seconds % 3600) / 60);
            var secs = seconds % 60;

            return hours + 'h ' + minutes + 'm ' + secs + 's';
        },

        formatCurrency: function (amount) {
            return '$' + parseFloat(amount).toFixed(2);
        },

        // API helper functions
        apiCall: function (action, data, callback) {
            var requestData = {
                action: action,
                nonce: dit_ajax.nonce
            };

            if (data) {
                requestData = $.extend(requestData, data);
            }

            $.ajax({
                url: dit_ajax.ajax_url,
                type: 'POST',
                data: requestData,
                success: function (response) {
                    if (callback) {
                        callback(response);
                    }
                },
                error: function (xhr, status, error) {
                    console.error('API call failed:', error);
                    DITDashboard.showMessage('An error occurred. Please try again.', 'error');
                }
            });
        }
    };

    // Initialize dashboard when document is ready
    $(document).ready(function () {
        console.log('DIT Dashboard: Initializing...');
        console.log('DIT Dashboard: dit_ajax available:', typeof dit_ajax !== 'undefined');
        if (typeof dit_ajax !== 'undefined') {
            console.log('DIT Dashboard: dit_ajax data:', dit_ajax);
        }
        DITDashboard.init();
        console.log('DIT Dashboard: Initialized successfully');
    });

    // Make dashboard object globally available
    window.DITDashboard = DITDashboard;

    // Debug: Check if DITDashboard is available
    console.log('DIT Dashboard: Object available globally:', typeof window.DITDashboard !== 'undefined');

})(jQuery);

/**
 * Additional utility functions for dashboard
 */

// Session management utilities
var DITSession = {
    // Check if user is logged in
    isLoggedIn: function () {
        return typeof dit_ajax !== 'undefined' && dit_ajax.user_id;
    },

    // Get user role
    getUserRole: function () {
        return typeof dit_ajax !== 'undefined' ? dit_ajax.user_role : null;
    },

    // Check if user is customer
    isCustomer: function () {
        return this.getUserRole() === 'customer';
    },

    // Check if user is regular user
    isUser: function () {
        return this.getUserRole() === 'user';
    },

    // Get user ID
    getUserId: function () {
        return typeof dit_ajax !== 'undefined' ? dit_ajax.user_id : null;
    }
};

// Dashboard navigation utilities
var DITNavigation = {
    // Navigate to dashboard section
    goTo: function (section) {
        var url = dit_ajax.dashboard_url + '/' + section;
        window.location.href = url;
    },

    // Refresh current page
    refresh: function () {
        window.location.reload();
    },

    // Go back
    back: function () {
        window.history.back();
    }
};

// Dashboard data utilities
var DITData = {
    // Format license time
    formatLicenseTime: function (seconds) {
        if (!seconds || seconds <= 0) {
            return 'No active license';
        }

        var hours = Math.floor(seconds / 3600);
        var minutes = Math.floor((seconds % 3600) / 60);

        if (hours > 24) {
            var days = Math.floor(hours / 24);
            hours = hours % 24;
            return days + 'd ' + hours + 'h ' + minutes + 'm';
        } else {
            return hours + 'h ' + minutes + 'm';
        }
    },

    // Format date
    formatDate: function (timestamp) {
        return new Date(timestamp * 1000).toLocaleDateString();
    },

    // Format datetime
    formatDateTime: function (timestamp) {
        return new Date(timestamp * 1000).toLocaleString();
    }
};

// Dashboard UI utilities
var DITUI = {
    // Show loading spinner
    showLoading: function (element) {
        $(element).addClass('loading');
    },

    // Hide loading spinner
    hideLoading: function (element) {
        $(element).removeClass('loading');
    },

    // Show success message
    showSuccess: function (message) {
        DITDashboard.showMessage(message, 'success');
    },

    // Show error message
    showError: function (message) {
        DITDashboard.showMessage(message, 'error');
    },

    // Show info message
    showInfo: function (message) {
        DITDashboard.showMessage(message, 'info');
    },

    // Confirm action
    confirm: function (message, callback) {
        if (confirm(message)) {
            if (callback) {
                callback();
            }
        }
    },

    // Prompt for input
    prompt: function (message, defaultValue, callback) {
        var value = prompt(message, defaultValue);
        if (callback) {
            callback(value);
        }
    }
};
