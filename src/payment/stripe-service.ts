/**
 * Stripe Payment Service
 * 
 * Handles all Stripe-related functionality including:
 * - Customer management
 * - Subscription creation and management
 * - Payment processing
 * - Webhook handling
 */

import Stripe from 'stripe';
import { Logger } from '../shared/logger';
import { CAMError } from '../shared/errors';

export interface StripeServiceOptions {
  apiKey: string;
  webhookSecret: string;
  productMapping?: {
    community: string;
    professional: string;
    enterprise: string;
  };
  priceMapping?: {
    community: string;
    professional: string;
    enterprise: string;
  };
}

export interface CustomerData {
  email: string;
  name?: string;
  metadata?: Record<string, string>;
}

export interface SubscriptionData {
  customerId: string;
  planType: 'community' | 'professional' | 'enterprise';
  trialDays?: number;
  metadata?: Record<string, string>;
}

export interface CheckoutSessionOptions {
  customerId: string;
  planType: 'community' | 'professional' | 'enterprise';
  successUrl: string;
  cancelUrl: string;
  trialDays?: number;
  metadata?: Record<string, string>;
}

export class StripeService {
  private stripe: Stripe;
  private logger: Logger;
  private productMapping: Record<string, string>;
  private priceMapping: Record<string, string>;
  private webhookSecret: string;

  constructor(options: StripeServiceOptions) {
    this.stripe = new Stripe(options.apiKey, {
      apiVersion: '2023-10-16' as any, // Cast to any to avoid type errors with Stripe version
    });
    this.logger = new Logger('info'); // Initialize with a valid LogLevel
    this.webhookSecret = options.webhookSecret;
    
    // Default product and price mappings
    this.productMapping = options.productMapping || {
      community: '',
      professional: '',
      enterprise: ''
    };
    
    this.priceMapping = options.priceMapping || {
      community: '',
      professional: '',
      enterprise: ''
    };
    
    this.logger.info('Stripe service initialized');
  }

  /**
   * Create a new customer in Stripe
   */
  async createCustomer(customerData: CustomerData): Promise<string> {
    try {
      // Prepare customer data with proper handling of optional fields
      const customerParams: any = {
        email: customerData.email
      };
      
      // Only add non-undefined fields
      if (customerData.name) customerParams.name = customerData.name;
      if (customerData.metadata) customerParams.metadata = customerData.metadata;
      
      const customer = await this.stripe.customers.create(customerParams);
      
      this.logger.info('Customer created successfully', { customerId: customer.id });
      return customer.id;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error('Failed to create customer', { errorMessage, data: customerData });
      throw new CAMError('Payment service error: Failed to create customer', errorMessage);
    }
  }

  /**
   * Create a subscription for a customer
   */
  async createSubscription(subscriptionData: SubscriptionData): Promise<any> {
    try {
      // Prepare subscription data with proper handling of optional fields
      const subscriptionParams: any = {
        customer: subscriptionData.customerId,
        items: [
          {
            price: this.getPriceId(subscriptionData.planType)
          }
        ]
      };
      
      // Only add non-undefined fields
      if (subscriptionData.trialDays) subscriptionParams.trial_period_days = subscriptionData.trialDays;
      if (subscriptionData.metadata) subscriptionParams.metadata = subscriptionData.metadata;
      
      const subscription = await this.stripe.subscriptions.create(subscriptionParams);
      
      this.logger.info('Subscription created successfully', { 
        subscriptionId: subscription.id,
        customerId: subscriptionData.customerId,
        planType: subscriptionData.planType
      });
      
      return subscription;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error('Failed to create subscription', { errorMessage, subscriptionData });
      throw new CAMError('Payment service error: Failed to create subscription', errorMessage);
    }
  }

  /**
   * Create a checkout session for a customer
   */
  async createCheckoutSession(sessionData: CheckoutSessionOptions): Promise<any> {
    try {
      // Prepare session data with proper handling of optional fields
      const sessionParams: any = {
        customer: sessionData.customerId,
        payment_method_types: ['card'],
        line_items: [
          {
            price: this.getPriceId(sessionData.planType),
            quantity: 1
          }
        ],
        mode: sessionData.planType === 'community' ? 'payment' : 'subscription',
        success_url: sessionData.successUrl,
        cancel_url: sessionData.cancelUrl
      };
      
      // Only add non-undefined fields
      if (sessionData.metadata) sessionParams.metadata = sessionData.metadata;
      
      const session = await this.stripe.checkout.sessions.create(sessionParams);
      
      this.logger.info('Checkout session created successfully', { 
        sessionId: session.id,
        customerId: sessionData.customerId,
        planType: sessionData.planType
      });
      
      return session;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error('Failed to create checkout session', { errorMessage, sessionData });
      throw new CAMError('Payment service error: Failed to create checkout session', errorMessage);
    }
  }

  /**
   * Handle a webhook event from Stripe
   */
  async handleWebhookEvent(body: string, signature: string): Promise<Stripe.Event> {
    try {
      const event = this.stripe.webhooks.constructEvent(
        body,
        signature,
        this.webhookSecret
      );
      
      this.logger.info('Webhook event received', { eventType: event.type });
      return event;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error('Failed to verify webhook signature', { errorMessage });
      throw new CAMError('Payment service error: Invalid webhook signature', 'WEBHOOK_SIGNATURE_ERROR', { details: { errorMessage } });
    }
  }

  /**
   * Get customer details
   */
  async getCustomer(customerId: string): Promise<Stripe.Customer> {
    try {
      const customer = await this.stripe.customers.retrieve(customerId);
      
      if (customer.deleted) {
        throw new CAMError(`Customer ${customerId} has been deleted`, 'CUSTOMER_DELETED', { details: { customerId } });
      }
      
      return customer as Stripe.Customer;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error('Failed to get customer', { errorMessage, customerId });
      throw new CAMError('Payment service error: Failed to get customer', errorMessage);
    }
  }

  /**
   * Get subscription details
   */
  async getSubscription(subscriptionId: string): Promise<Stripe.Subscription> {
    try {
      return await this.stripe.subscriptions.retrieve(subscriptionId);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error('Failed to get subscription', { errorMessage, subscriptionId });
      throw new CAMError('Payment service error: Failed to get subscription', errorMessage);
    }
  }

  /**
   * Update subscription plan
   */
  async updateSubscription(subscriptionId: string, updateData: { planType: 'community' | 'professional' | 'enterprise' }): Promise<Stripe.Subscription> {
    try {
      const priceId = this.getPriceId(updateData.planType);
      
      if (!priceId) {
        throw new CAMError(`No price ID configured for plan type: ${updateData.planType}`, 'PRICE_ID_NOT_FOUND', { details: { planType: updateData.planType } });
      }
      
      const subscription = await this.stripe.subscriptions.retrieve(subscriptionId);
      
      // Make sure subscription items exist
      if (!subscription.items?.data || subscription.items.data.length === 0) {
        throw new CAMError(`Subscription ${subscriptionId} has no items`, 'SUBSCRIPTION_NO_ITEMS', { details: { subscriptionId } });
      }
      
      // Update the subscription items
      return await this.stripe.subscriptions.update(subscriptionId, {
        items: [
          {
            id: subscription.items.data[0]?.id || '',
            price: priceId,
          },
        ],
        metadata: {
          ...subscription.metadata,
          planType: updateData.planType
        }
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error('Failed to update subscription', { errorMessage, subscriptionId, updateData });
      throw new CAMError('Payment service error: Failed to update subscription', errorMessage);
    }
  }

  /**
   * Cancel a subscription
   */
  async cancelSubscription(subscriptionId: string): Promise<Stripe.Subscription> {
    try {
      return await this.stripe.subscriptions.cancel(subscriptionId);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error('Failed to cancel subscription', { errorMessage, subscriptionId });
      throw new CAMError('Payment service error: Failed to cancel subscription', errorMessage);
    }
  }

  /**
   * Get a list of invoices for a customer
   */
  async getCustomerInvoices(customerId: string): Promise<Stripe.Invoice[]> {
    try {
      const invoices = await this.stripe.invoices.list({
        customer: customerId,
        limit: 10,
      });
      
      return invoices.data;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error('Failed to retrieve customer invoices', { errorMessage, customerId });
      throw new CAMError('Payment service error: Failed to retrieve invoices', 'INVOICE_RETRIEVAL_ERROR', { details: { customerId, errorMessage } });
    }
  }

  /**
   * Set the product and price mappings
   */
  setProductMapping(mapping: Record<string, string>): void {
    this.productMapping = {
      ...this.productMapping,
      ...mapping
    };
  }

  /**
   * Set the price mappings
   */
  setPriceMapping(mapping: Record<string, string>): void {
    this.priceMapping = {
      ...this.priceMapping,
      ...mapping
    };
  }

  /**
   * Get the price ID for a plan type
   */
  private getPriceId(planType: 'community' | 'professional' | 'enterprise'): string {
    const priceId = this.priceMapping[planType];
    if (!priceId) {
      throw new CAMError(`No price ID configured for plan type: ${planType}`, 'PRICE_ID_NOT_FOUND', { details: { planType } });
    }
    return priceId;
  }
}
