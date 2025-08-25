<?php

namespace DIT;

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class Logger
 * Handles detailed logging for DIT Integration
 */
class Logger
{
    /**
     * Log file path
     */
    private $log_file;

    /**
     * Constructor
     */
    public function __construct()
    {
        $upload_dir = wp_upload_dir();
        $log_dir = $upload_dir['basedir'] . '/dit-logs';

        // Create logs directory if it doesn't exist
        if (!file_exists($log_dir)) {
            wp_mkdir_p($log_dir);
        }

        $this->log_file = $log_dir . '/dit-integration-logs.txt';

        // Create log file if it doesn't exist
        if (!file_exists($this->log_file)) {
            file_put_contents($this->log_file, "DIT Integration Logs\n" . str_repeat("=", 50) . "\n\n");
        }
    }

    /**
     * Log API interaction
     *
     * @param string $action Action being performed
     * @param array $data Data being sent/received
     * @param string $status Success/Error status
     * @param string $message Additional message
     */
    public function log_api_interaction($action, $data = [], $status = 'info', $message = '')
    {
        // $settings = get_option('dit_settings');
        // if (empty($settings['debug_mode'])) {
        //     return;
        // }

        $timestamp = current_time('Y-m-d H:i:s');
        $log_entry = sprintf(
            "[%s] %s: %s - %s\n",
            $timestamp,
            strtoupper($status),
            $action,
            $message
        );

        if (!empty($data)) {
            $log_entry .= "Data: " . json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
        }

        $log_entry .= "----------------------------------------\n";

        // Write to file
        file_put_contents($this->log_file, $log_entry, FILE_APPEND | LOCK_EX);
    }

    /**
     * Log form submission
     *
     * @param int $form_id Form ID
     * @param array $user_data User data extracted from form
     * @param string $status Success/Error status
     * @param string $message Additional message
     */
    public function log_form_submission($form_id, $user_data = [], $status = 'info', $message = '')
    {
        // $settings = get_option('dit_settings');
        // if (empty($settings['debug_mode'])) {
        //     return;
        // }

        $timestamp = current_time('Y-m-d H:i:s');
        $log_entry = sprintf(
            "[%s] FORM SUBMISSION: Form ID %d - %s - %s\n",
            $timestamp,
            $form_id,
            strtoupper($status),
            $message
        );

        if (!empty($user_data)) {
            // Mask sensitive data
            $masked_data = $user_data;
            if (isset($masked_data['password'])) {
                $masked_data['password'] = '***MASKED***';
            }
            if (isset($masked_data['password_hash'])) {
                $masked_data['password_hash'] = '***MASKED***';
            }

            $log_entry .= "User Data: " . json_encode($masked_data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
        }

        $log_entry .= "----------------------------------------\n";

        // Write to file
        file_put_contents($this->log_file, $log_entry, FILE_APPEND | LOCK_EX);
    }

    /**
     * Get log file path
     *
     * @return string
     */
    public function get_log_file_path()
    {
        return $this->log_file;
    }

    /**
     * Get recent logs
     *
     * @param int $lines Number of lines to retrieve
     * @return string
     */
    public function get_recent_logs($lines = 50)
    {
        if (!file_exists($this->log_file)) {
            return 'No logs found.';
        }

        $file = new \SplFileObject($this->log_file);
        $file->seek(PHP_INT_MAX);
        $total_lines = $file->key();

        $start_line = max(0, $total_lines - $lines);
        $logs = [];

        $file->seek($start_line);
        while (!$file->eof()) {
            $logs[] = $file->current();
            $file->next();
        }

        return implode('', $logs);
    }

    /**
     * Clear logs
     */
    public function clear_logs()
    {
        if (file_exists($this->log_file)) {
            unlink($this->log_file);
        }
    }

    /**
     * Clear the debug log file
     *
     * @return bool True if successful, false otherwise
     */
    public function clear_log(): bool
    {
        try {
            $log_file = $this->get_log_file_path();
            if (file_exists($log_file)) {
                return file_put_contents($log_file, '') !== false;
            }
            return true; // File doesn't exist, so it's already "clear"
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Get log file size in bytes
     *
     * @return int File size in bytes, 0 if file doesn't exist
     */
    public function get_log_size(): int
    {
        $log_file = $this->get_log_file_path();
        return file_exists($log_file) ? filesize($log_file) : 0;
    }
}
