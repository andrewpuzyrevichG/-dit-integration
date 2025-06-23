<?php

namespace DIT;

// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class Stripe
 * Handles Stripe payment processing
 */
class Stripe
{
    /**
     * Initialize Stripe integration
     */
    public function init()
    {
        // Add any initialization logic here
        // For example, we could verify Stripe API keys are set
        $settings = get_option('dit_settings');
        if (empty($settings['stripe_secret_key']) || empty($settings['stripe_publishable_key'])) {
            error_log('DIT Integration: Stripe API keys are not configured');
        }
    }

    /**
     * Create a payment intent.
     *
     * @param float $amount Payment amount.
     * @param string $currency Payment currency.
     * @param array $metadata Additional metadata.
     * @return array|WP_Error Payment intent data or WP_Error on failure.
     */
    public function create_payment_intent($amount, $currency = 'usd', $metadata = [])
    {
        if (!class_exists('WPForms_Stripe')) {
            return new \WP_Error('stripe_error', __('Stripe is not available.', 'dit-integration'));
        }

        try {
            $stripe = \wpforms_stripe();
            $intent = $stripe->create_payment_intent([
                'amount' => $amount * 100, // Convert to cents
                'currency' => $currency,
                'metadata' => $metadata,
            ]);

            return [
                'client_secret' => $intent->client_secret,
                'publishable_key' => $stripe->get_publishable_key(),
            ];
        } catch (\Exception $e) {
            return new \WP_Error('stripe_error', $e->getMessage());
        }
    }

    /**
     * Handle successful payment.
     *
     * @param string $payment_intent_id Payment intent ID.
     * @return array|WP_Error Payment data or WP_Error on failure.
     */
    public function handle_successful_payment($payment_intent_id)
    {
        if (!class_exists('WPForms_Stripe')) {
            return new \WP_Error('stripe_error', __('Stripe is not available.', 'dit-integration'));
        }

        try {
            $stripe = \wpforms_stripe();
            $intent = $stripe->retrieve_payment_intent($payment_intent_id);

            if ($intent->status !== 'succeeded') {
                return new \WP_Error('payment_failed', __('Payment was not successful.', 'dit-integration'));
            }

            return [
                'id' => $intent->id,
                'amount' => $intent->amount / 100, // Convert from cents
                'currency' => $intent->currency,
                'status' => $intent->status,
                'metadata' => $intent->metadata,
            ];
        } catch (\Exception $e) {
            return new \WP_Error('stripe_error', $e->getMessage());
        }
    }

    /**
     * Get payment status.
     *
     * @param string $payment_intent_id Payment intent ID.
     * @return string|WP_Error Payment status or WP_Error on failure.
     */
    public function get_payment_status($payment_intent_id)
    {
        if (!class_exists('WPForms_Stripe')) {
            return new \WP_Error('stripe_error', __('Stripe is not available.', 'dit-integration'));
        }

        try {
            $stripe = \wpforms_stripe();
            $intent = $stripe->retrieve_payment_intent($payment_intent_id);
            return $intent->status;
        } catch (\Exception $e) {
            return new \WP_Error('stripe_error', $e->getMessage());
        }
    }

    /**
     * Refund a payment.
     *
     * @param string $payment_intent_id Payment intent ID.
     * @param float $amount Amount to refund (optional).
     * @return array|WP_Error Refund data or WP_Error on failure.
     */
    public function refund_payment($payment_intent_id, $amount = null)
    {
        if (!class_exists('WPForms_Stripe')) {
            return new \WP_Error('stripe_error', __('Stripe is not available.', 'dit-integration'));
        }

        try {
            $stripe = \wpforms_stripe();
            $refund_data = ['payment_intent' => $payment_intent_id];

            if ($amount !== null) {
                $refund_data['amount'] = $amount * 100; // Convert to cents
            }

            $refund = $stripe->create_refund($refund_data);

            return [
                'id' => $refund->id,
                'amount' => $refund->amount / 100, // Convert from cents
                'status' => $refund->status,
            ];
        } catch (\Exception $e) {
            return new \WP_Error('stripe_error', $e->getMessage());
        }
    }

    /**
     * Get Stripe configuration status.
     *
     * @return bool True if Stripe is configured.
     */
    public function is_configured()
    {
        return class_exists('WPForms_Stripe');
    }
}
