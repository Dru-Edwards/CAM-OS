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
      apiVersion: '2023-10-16',
    });
    this.logger = new Logger('payment');
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
  async createCustomer(data: CustomerData): Promise<Stripe.Customer> {
    try {
      const customer = await this.stripe.customers.create({
        email: data.email,
        name: data.name,
        metadata: data.metadata
      });
      
      this.logger.info('Customer created successfully', { customerId: customer.id });
      return customer;
    } catch (error) {
      this.logger.error('Failed to create customer', { error, data });
      throw new CAMError('Payment service error: Failed to create customer', error as Error);
    }
  }

  /**
   * Create a subscription for a customer
   */
  async createSubscription(data: SubscriptionData): Promise<Stripe.Subscription> {
    try {
      const priceId = this.getPriceId(data.planType);
      
      if (!priceId) {
        throw new CAMError(`No price ID configured for plan type: ${data.planType}`);
      }
      
      const subscription = await this.stripe.subscriptions.create({
        customer: data.customerId,
        items: [{ price: priceId }],
        trial_period_days: data.trialDays,
        metadata: data.metadata
      });
      
      this.logger.info('Subscription created successfully', { 
        subscriptionId: subscription.id,
        customerId: data.customerId,
        planType: data.planType
      });
      
      return subscription;
    } catch (error) {
      this.logger.error('Failed to create subscription', { error, data });
      throw new CAMError('Payment service error: Failed to create subscription', error as Error);
    }
  }

  /**
   * Create a checkout session for a customer
   */
  async createCheckoutSession(options: CheckoutSessionOptions): Promise<Stripe.Checkout.Session> {
    try {
      const priceId = this.getPriceId(options.planType);
      
      if (!priceId) {
        throw new CAMError(`No price ID configured for plan type: ${options.planType}`);
      }
      
      const session = await this.stripe.checkout.sessions.create({
        customer: options.customerId,
        payment_method_types: ['card'],
        line_items: [
          {
            price: priceId,
            quantity: 1,
          },
        ],
        mode: options.planType === 'community' ? 'payment' : 'subscription',
        success_url: options.successUrl,
        cancel_url: options.cancelUrl,
        metadata: options.metadata
      });
      
      this.logger.info('Checkout session created successfully', { 
        sessionId: session.id,
        customerId: options.customerId,
        planType: options.planType
      });
      
      return session;
    } catch (error) {
      this.logger.error('Failed to create checkout session', { error, options });
      throw new CAMError('Payment service error: Failed to create checkout session', error as Error);
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
      this.logger.error('Failed to verify webhook signature', { error });
      throw new CAMError('Payment service error: Invalid webhook signature', error as Error);
    }
  }

  /**
   * Get customer details
   */
  async getCustomer(customerId: string): Promise<Stripe.Customer> {
    try {
      const customer = await this.stripe.customers.retrieve(customerId);
      
      if (customer.deleted) {
        throw new CAMError(`Customer ${customerId} has been deleted`);
      }
      
      return customer as Stripe.Customer;
    } catch (error) {
      this.logger.error('Failed to retrieve customer', { error, customerId });
      throw new CAMError('Payment service error: Failed to retrieve customer', error as Error);
    }
  }

  /**
   * Get subscription details
   */
  async getSubscription(subscriptionId: string): Promise<Stripe.Subscription> {
    try {
      return await this.stripe.subscriptions.retrieve(subscriptionId);
    } catch (error) {
      this.logger.error('Failed to retrieve subscription', { error, subscriptionId });
      throw new CAMError('Payment service error: Failed to retrieve subscription', error as Error);
    }
  }

  /**
   * Update subscription plan
   */
  async updateSubscription(subscriptionId: string, planType: 'community' | 'professional' | 'enterprise'): Promise<Stripe.Subscription> {
    try {
      const priceId = this.getPriceId(planType);
      
      if (!priceId) {
        throw new CAMError(`No price ID configured for plan type: ${planType}`);
      }
      
      const subscription = await this.stripe.subscriptions.retrieve(subscriptionId);
      
      // Update the subscription items
      return await this.stripe.subscriptions.update(subscriptionId, {
        items: [
          {
            id: subscription.items.data[0].id,
            price: priceId,
          },
        ],
        metadata: {
          ...subscription.metadata,
          planType
        }
      });
    } catch (error) {
      this.logger.error('Failed to update subscription', { error, subscriptionId, planType });
      throw new CAMError('Payment service error: Failed to update subscription', error as Error);
    }
  }

  /**
   * Cancel a subscription
   */
  async cancelSubscription(subscriptionId: string): Promise<Stripe.Subscription> {
    try {
      return await this.stripe.subscriptions.cancel(subscriptionId);
    } catch (error) {
      this.logger.error('Failed to cancel subscription', { error, subscriptionId });
      throw new CAMError('Payment service error: Failed to cancel subscription', error as Error);
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
      this.logger.error('Failed to retrieve customer invoices', { error, customerId });
      throw new CAMError('Payment service error: Failed to retrieve invoices', error as Error);
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
      throw new CAMError(`No price ID configured for plan type: ${planType}`);
    }
    return priceId;
  }
}
