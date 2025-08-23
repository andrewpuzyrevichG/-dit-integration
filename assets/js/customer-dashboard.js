/**
 * Customer Dashboard JavaScript
 * Extends the main dashboard functionality for Customer role
 */

(function ($) {
    'use strict';

    // Extend DITDashboard with customer-specific functionality
    $.extend(DITDashboard, {
        // Customer-specific properties
        currentCustomerId: dit_ajax.customer_id,
        selectedUserId: null,

        // Initialize customer dashboard
        initCustomerDashboard: function () {
            this.loadUsers();
            this.loadCustomerData(); // Load customer data on initialization
            this.bindCustomerEvents();
        },

        // Bind customer-specific events
        bindCustomerEvents: function () {
            // Navigation between sections
            $(document).on('click', '.nav-item', function (e) {
                e.preventDefault();
                var section = $(this).data('section');
                DITDashboard.showSection(section);
            });

            // Form submissions
            $(document).on('submit', '#add-user-form', function (e) {
                e.preventDefault();
                DITDashboard.addUser();
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
                case 'users':
                    this.loadUsers();
                    break;
                case 'tools':
                    // Tools are static, no loading needed
                    break;
                case 'account':
                    this.loadCustomerData();
                    break;
            }
        },

        // Load customer data for account settings
        loadCustomerData: function () {
            var self = this;
            console.log('DIT Dashboard: Loading customer data for customer ID: ' + (dit_ajax.customer_id || 'unknown'));

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
                        console.log('Raw response data keys:', Object.keys(response.data));

                        // Log field values before population
                        console.log('Field values BEFORE population:');
                        console.log('first_name field value:', $('#first_name').val());
                        console.log('last_name field value:', $('#last_name').val());
                        console.log('company field value:', $('#company').val());

                        // Populate form fields with customer data
                        $('#first_name').val(response.data.first_name || '');
                        $('#last_name').val(response.data.last_name || '');
                        $('#company').val(response.data.company || '');

                        // Log field values after population
                        console.log('Field values AFTER population:');
                        console.log('first_name field value:', $('#first_name').val());
                        console.log('last_name field value:', $('#last_name').val());
                        console.log('company field value:', $('#company').val());

                        console.log('Form fields populated - First Name: "' + response.data.first_name + '", Last Name: "' + response.data.last_name + '", Company: "' + response.data.company + '"');

                        // Update welcome message if we have name data
                        if (response.data.first_name && response.data.last_name) {
                            var customerId = dit_ajax.customer_id;
                            $('.dashboard-header p').text('Welcome, ' + response.data.first_name + ' ' + response.data.last_name + ' | Customer ID: ' + customerId);
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

        // Load users for the customer
        loadUsers: function () {
            var self = this;

            $('#users-loading').show();
            $('#users-container').hide();

            // Show sync indicator
            $('#users-loading .spinner').after('<p class="sync-indicator">Syncing with API...</p>');

            var ajaxData = {
                action: 'dit_get_customer_users',
                customer_id: this.currentCustomerId,
                nonce: dit_ajax.nonce
            };

            console.log('DIT Dashboard: Loading users with data:', ajaxData);
            console.log('DIT Dashboard: AJAX URL:', dit_ajax.ajax_url);
            console.log('DIT Dashboard: dit_ajax object:', dit_ajax);

            // Test basic AJAX connection first
            $.ajax({
                url: dit_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'dit_test',
                    nonce: dit_ajax.nonce
                },
                success: function (response) {
                    console.log('DIT Dashboard: Basic test AJAX response:', response);
                },
                error: function (xhr, status, error) {
                    console.log('DIT Dashboard: Basic test AJAX error:', { xhr: xhr, status: status, error: error });
                }
            });

            // Test AJAX connection first
            $.ajax({
                url: dit_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'dit_get_customer_users',
                    test: 'ping',
                    nonce: dit_ajax.nonce
                },
                success: function (response) {
                    console.log('DIT Dashboard: Test AJAX response:', response);
                },
                error: function (xhr, status, error) {
                    console.log('DIT Dashboard: Test AJAX error:', { xhr: xhr, status: status, error: error });
                }
            });

            // Debug AJAX connection
            $.ajax({
                url: dit_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'dit_get_customer_users',
                    debug: 'true',
                    nonce: dit_ajax.nonce
                },
                success: function (response) {
                    console.log('DIT Dashboard: Debug AJAX response:', response);
                },
                error: function (xhr, status, error) {
                    console.log('DIT Dashboard: Debug AJAX error:', { xhr: xhr, status: status, error: error });
                }
            });

            $.ajax({
                url: dit_ajax.ajax_url,
                type: 'POST',
                data: ajaxData,
                success: function (response) {
                    $('#users-loading').hide();
                    console.log('DIT Dashboard: AJAX response:', response);

                    if (response.success) {
                        // Update sync indicator to show success
                        $('.sync-indicator').text('Data synced successfully!').addClass('sync-success');
                        setTimeout(function () {
                            $('.sync-indicator').fadeOut();
                        }, 2000);

                        self.renderUsers(response.data);
                    } else {
                        // Show sync error
                        $('.sync-indicator').text('Sync failed: ' + (response.data || 'Unknown error')).addClass('sync-error');
                        setTimeout(function () {
                            $('.sync-indicator').fadeOut();
                        }, 3000);

                        self.showMessage('Failed to load users: ' + (response.data || 'Unknown error'), 'error');
                        $('#users-container').html('<p class="error-message">Failed to load users</p>').show();
                    }
                },
                error: function (xhr, status, error) {
                    $('#users-loading').hide();
                    console.log('DIT Dashboard: AJAX error:', { xhr: xhr, status: status, error: error });

                    // Show sync error
                    $('.sync-indicator').text('Sync failed: Network error').addClass('sync-error');
                    setTimeout(function () {
                        $('.sync-indicator').fadeOut();
                    }, 3000);

                    self.showMessage('Failed to load users. Please try again.', 'error');
                    $('#users-container').html('<p class="error-message">Failed to load users</p>').show();
                }
            });
        },

        // Render users list
        renderUsers: function (users) {
            var container = $('#users-container');

            if (!users || users.length === 0) {
                container.html('<p class="no-users">No users found. Add your first user to get started.</p>').show();
                return;
            }

            var html = '<div class="users-table">';
            html += '<table>';
            html += '<thead><tr><th>Name</th><th>Email</th><th>Tools Access</th><th>Status</th><th>Actions</th></tr></thead>';
            html += '<tbody>';

            users.forEach(function (user) {
                var fullName = (user.first_name || '') + ' ' + (user.last_name || '');
                fullName = fullName.trim() || 'N/A';

                html += '<tr data-user-id="' + user.id + '">';
                html += '<td>' + fullName + '</td>';
                html += '<td>' + user.email + '</td>';
                html += '<td>' + (user.tools ? user.tools.join(', ') : 'All tools') + '</td>';
                html += '<td><span class="status-badge ' + (user.active ? 'active' : 'inactive') + '">' + (user.active ? 'Active' : 'Inactive') + '</span></td>';
                html += '<td>';
                html += '<button class="btn-small btn-edit" onclick="DITDashboard.editUser(' + user.id + ')">Edit</button>';
                html += '<button class="btn-small btn-danger" onclick="DITDashboard.deleteUserConfirm(' + user.id + ', \'' + fullName + '\')">Delete</button>';
                html += '</td>';
                html += '</tr>';
            });

            html += '</tbody></table></div>';
            container.html(html).show();
        },

        // Show add user modal
        showAddUserModal: function () {
            $('#add-user-form')[0].reset();
            $('#edit_user_id').val(''); // Clear hidden user ID
            $('#user_password').attr('placeholder', 'Enter password').prop('required', true);
            $('#add-user-modal .modal-header h3').text('Add New User');
            $('#add-user-modal .btn-primary').text('Add User').off('click').on('click', function () {
                DITDashboard.addUser();
            });
            $('#add-user-modal').show();
        },

        // Show edit user modal
        showEditModal: function () {
            $('#user_password').attr('placeholder', 'Leave blank to keep current password').prop('required', false);
            $('#add-user-modal .modal-header h3').text('Edit User');
            $('#add-user-modal .btn-primary').text('Update User').off('click').on('click', function () {
                DITDashboard.updateUser();
            });
            $('#add-user-modal').show();
        },

        // Populate edit form with user data
        populateEditForm: function (userData) {
            console.log('DIT Dashboard: Populating form with user data:', userData);
            console.log('DIT Dashboard: userData.email:', userData.email);
            console.log('DIT Dashboard: userData.first_name:', userData.first_name);
            console.log('DIT Dashboard: userData.last_name:', userData.last_name);
            console.log('DIT Dashboard: userData.id:', userData.id);

            // Set form values
            $('#user_email').val(userData.email || '');
            $('#user_first_name').val(userData.first_name || userData.nameFirst || '');
            $('#user_last_name').val(userData.last_name || userData.nameLast || '');

            console.log('DIT Dashboard: Form field values after setting:');
            console.log('DIT Dashboard: #user_email.val():', $('#user_email').val());
            console.log('DIT Dashboard: #user_first_name.val():', $('#user_first_name').val());
            console.log('DIT Dashboard: #user_last_name.val():', $('#user_last_name').val());

            // Clear password field for editing
            $('#user_password').val('').attr('placeholder', 'Leave blank to keep current password');

            // Set tools checkboxes
            $('.checkbox-group input[type="checkbox"]').prop('checked', false);

            if (userData.tools && Array.isArray(userData.tools)) {
                userData.tools.forEach(function (toolId) {
                    $('.checkbox-group input[value="' + toolId + '"]').prop('checked', true);
                });
            }

            // Store user ID for update
            this.selectedUserId = userData.id || userData.userId;
            $('#edit_user_id').val(this.selectedUserId);

            console.log('DIT Dashboard: Form populated, selected user ID:', this.selectedUserId);
        },

        // Close modal
        closeModal: function (modalId) {
            $('#' + modalId).hide();
        },

        // Update existing user
        updateUser: function () {
            if (!this.selectedUserId) {
                this.showMessage('No user selected for update.', 'error');
                return;
            }

            var form = $('#add-user-form')[0];
            var formData = new FormData(form);

            // Get selected tools
            var selectedTools = [];
            $('.checkbox-group input:checked').each(function () {
                selectedTools.push($(this).val());
            });

            var userData = {
                user_id: this.selectedUserId,
                email: $('#user_email').val(),
                password: $('#user_password').val(),
                first_name: $('#user_first_name').val(),
                last_name: $('#user_last_name').val(),
                tools: selectedTools,
                customer_id: this.currentCustomerId
            };

            // Log user data (without password for security)
            console.log('DIT Dashboard: Updating user with data:', {
                user_id: userData.user_id,
                email: userData.email,
                first_name: userData.first_name,
                last_name: userData.last_name,
                tools: userData.tools,
                customer_id: userData.customer_id,
                password_provided: userData.password.length > 0
            });

            // Log full user data for debugging (including password length)
            console.log('DIT Dashboard: Full user data being sent:', {
                ...userData,
                password: userData.password ? '[HIDDEN - length: ' + userData.password.length + ']' : '[NOT PROVIDED]'
            });

            // Validation
            if (!userData.email || !userData.first_name || !userData.last_name) {
                console.log('DIT Dashboard: Validation failed - missing fields');
                this.showMessage('Please fill in all required fields.', 'error');
                return;
            }

            var self = this;
            var $btn = $('#add-user-modal .btn-primary');
            var originalText = $btn.text();
            $btn.addClass('loading').text('Updating User...');

            console.log('DIT Dashboard: Sending AJAX request to update user');

            $.ajax({
                url: dit_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'dit_update_user',
                    user_data: userData,
                    nonce: dit_ajax.nonce
                },
                success: function (response) {
                    $btn.removeClass('loading').text(originalText);
                    console.log('DIT Dashboard: Update user response:', response);
                    console.log('DIT Dashboard: Response success:', response.success);
                    console.log('DIT Dashboard: Response data:', response.data);
                    console.log('DIT Dashboard: Response data type:', typeof response.data);
                    console.log('DIT Dashboard: Response data keys:', response.data ? Object.keys(response.data) : 'No data');

                    if (response.success) {
                        console.log('DIT Dashboard: Update successful, showing success message');
                        self.showMessage('User updated successfully!', 'success');
                        self.closeModal('add-user-modal');
                        console.log('DIT Dashboard: Reloading users list');
                        self.loadUsers(); // Reload users list
                    } else {
                        console.log('DIT Dashboard: Update failed, showing error message');
                        self.showMessage('Failed to update user: ' + (response.data || 'Unknown error'), 'error');
                    }
                },
                error: function (xhr, status, error) {
                    $btn.removeClass('loading').text(originalText);
                    console.log('DIT Dashboard: Update user error:', { xhr: xhr, status: status, error: error });
                    console.log('DIT Dashboard: XHR status:', xhr.status);
                    console.log('DIT Dashboard: XHR statusText:', xhr.statusText);
                    console.log('DIT Dashboard: XHR responseText:', xhr.responseText);
                    console.log('DIT Dashboard: Error status:', status);
                    console.log('DIT Dashboard: Error message:', error);
                    self.showMessage('Failed to update user. Please try again.', 'error');
                }
            });
        },

        // Add new user
        addUser: function () {
            var form = $('#add-user-form')[0];
            var formData = new FormData(form);

            // Get selected tools
            var selectedTools = [];
            $('.checkbox-group input:checked').each(function () {
                selectedTools.push($(this).val());
            });

            var userData = {
                email: $('#user_email').val(),
                password: $('#user_password').val(),
                first_name: $('#user_first_name').val(),
                last_name: $('#user_last_name').val(),
                tools: selectedTools,
                customer_id: this.currentCustomerId
            };

            // Log user data (without password for security)
            console.log('DIT Dashboard: Adding user with data:', {
                email: userData.email,
                first_name: userData.first_name,
                last_name: userData.last_name,
                tools: userData.tools,
                customer_id: userData.customer_id,
                password_length: userData.password.length
            });

            // Validation
            if (!userData.email || !userData.password || !userData.first_name || !userData.last_name) {
                console.log('DIT Dashboard: Validation failed - missing fields');
                this.showMessage('Please fill in all required fields.', 'error');
                return;
            }

            if (userData.password.length < 6) {
                console.log('DIT Dashboard: Validation failed - password too short');
                this.showMessage('Password must be at least 6 characters long.', 'error');
                return;
            }

            var self = this;
            var $btn = $('#add-user-modal .btn-primary');
            var originalText = $btn.text();
            $btn.addClass('loading').text('Adding User...');

            console.log('DIT Dashboard: Sending AJAX request to add user');

            $.ajax({
                url: dit_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'dit_add_user',
                    user_data: userData,
                    nonce: dit_ajax.nonce
                },
                success: function (response) {
                    $btn.removeClass('loading').text(originalText);

                    console.log('DIT Dashboard: AJAX response received:', {
                        success: response.success,
                        data: response.data,
                        response_type: typeof response.data
                    });

                    if (response.success) {
                        console.log('DIT Dashboard: User added successfully');
                        self.showMessage('User added successfully!', 'success');
                        self.closeModal('add-user-modal');
                        self.loadUsers(); // Reload users list
                    } else {
                        console.log('DIT Dashboard: Failed to add user:', response.data);
                        self.showMessage('Failed to add user: ' + (response.data || 'Unknown error'), 'error');
                    }
                },
                error: function (xhr, status, error) {
                    $btn.removeClass('loading').text(originalText);
                    console.log('DIT Dashboard: AJAX error:', {
                        status: status,
                        error: error,
                        xhr_status: xhr.status,
                        xhr_statusText: xhr.statusText
                    });
                    self.showMessage('Failed to add user. Please try again.', 'error');
                }
            });
        },

        // Edit user
        editUser: function (userId) {
            var self = this;

            console.log('DIT Dashboard: Editing user with ID:', userId);

            // Show loading state
            this.showMessage('Loading user data...', 'info');

            $.ajax({
                url: dit_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'dit_get_user',
                    user_id: userId,
                    customer_id: this.currentCustomerId,
                    nonce: dit_ajax.nonce
                },
                success: function (response) {
                    console.log('DIT Dashboard: Get user response:', response);
                    console.log('DIT Dashboard: Response data:', response.data);
                    console.log('DIT Dashboard: Response data keys:', Object.keys(response.data || {}));

                    if (response.success && response.data) {
                        console.log('DIT Dashboard: About to populate form with data:', response.data);
                        self.populateEditForm(response.data);
                        self.showEditModal();
                    } else {
                        self.showMessage('Failed to load user data: ' + (response.data || 'Unknown error'), 'error');
                    }
                },
                error: function (xhr, status, error) {
                    console.log('DIT Dashboard: Get user error:', { xhr: xhr, status: status, error: error });
                    self.showMessage('Failed to load user data. Please try again.', 'error');
                }
            });
        },

        // Confirm user deletion
        deleteUserConfirm: function (userId, userName) {
            this.selectedUserId = userId;
            $('#delete-user-name').text(userName || 'this user');
            $('#delete-user-modal').show();
        },

        // Delete user
        deleteUser: function () {
            if (!this.selectedUserId) {
                this.showMessage('No user selected for deletion.', 'error');
                return;
            }

            var self = this;
            var $btn = $('#delete-user-modal .btn-danger');
            var originalText = $btn.text();
            $btn.addClass('loading').text('Deleting...');

            $.ajax({
                url: dit_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'dit_delete_user',
                    user_id: this.selectedUserId,
                    customer_id: this.currentCustomerId,
                    nonce: dit_ajax.nonce
                },
                success: function (response) {
                    $btn.removeClass('loading').text(originalText);

                    if (response.success) {
                        self.showMessage('User deleted successfully!', 'success');
                        self.closeModal('delete-user-modal');
                        self.loadUsers(); // Reload users list
                    } else {
                        self.showMessage('Failed to delete user: ' + (response.data || 'Unknown error'), 'error');
                    }
                },
                error: function () {
                    $btn.removeClass('loading').text(originalText);
                    self.showMessage('Failed to delete user. Please try again.', 'error');
                }
            });
        },

        // Update account information
        updateAccount: function () {
            var firstName = $('#first_name').val().trim();
            var lastName = $('#last_name').val().trim();
            var company = $('#company').val().trim();
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
                    company: company,
                    new_password: newPassword,
                    nonce: dit_ajax.nonce
                },
                success: function (response) {
                    $btn.removeClass('loading').text(originalText);

                    if (response.success) {
                        self.showMessage('Account updated successfully!', 'success');
                        $('#new_password, #confirm_password').val('');

                        // Update the welcome message in the header
                        var firstName = $('#first_name').val();
                        var lastName = $('#last_name').val();
                        var email = $('#current_email').val();
                        var customerId = dit_ajax.customer_id;

                        if (firstName && lastName) {
                            $('.dashboard-header p').text('Welcome, ' + firstName + ' ' + lastName + ' | Customer ID: ' + customerId);
                        } else {
                            $('.dashboard-header p').text('Welcome, ' + email + ' | Customer ID: ' + customerId);
                        }
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
        }
    });

    // Initialize customer dashboard when document is ready
    $(document).ready(function () {
        DITDashboard.initCustomerDashboard();
    });

})(jQuery); 