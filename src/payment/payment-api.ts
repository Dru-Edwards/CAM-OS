/**
 * Payment API
 * 
 * Exposes payment and subscription functionality through a RESTful API
 * using Fastify for high-performance request handling.
 */

import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { StripeService } from './stripe-service';
import { SubscriptionManager, SubscriptionTier } from './subscription-manager';
import { Logger } from '../shared/logger';
import { CAMError } from '../shared/errors';

export interface PaymentAPIOptions {
  stripeService: StripeService;
  subscriptionManager: SubscriptionManager;
}

export class PaymentAPI {
  private logger: Logger;
  private stripeService: StripeService;
  private subscriptionManager: SubscriptionManager;

  constructor(options: PaymentAPIOptions) {
    this.logger = new Logger('info'); // Initialize with a valid LogLevel
    this.stripeService = options.stripeService;
    this.subscriptionManager = options.subscriptionManager;
    
    this.logger.info('Payment API initialized');
  }

  /**
   * Register the payment API routes with a Fastify instance
   */
  registerRoutes(fastify: FastifyInstance): void {
    // Customer endpoints
    fastify.post('/api/payment/customers', this.createCustomer.bind(this));
    fastify.get('/api/payment/customers/:id', this.getCustomer.bind(this));
    
    // Subscription endpoints
    fastify.get('/api/payment/subscriptions/:id', this.getSubscription.bind(this));
    fastify.post('/api/payment/subscriptions', this.createSubscription.bind(this));
    fastify.put('/api/payment/subscriptions/:id', this.updateSubscription.bind(this));
    fastify.delete('/api/payment/subscriptions/:id', this.cancelSubscription.bind(this));
    
    // Checkout endpoints
    fastify.post('/api/payment/checkout', this.createCheckoutSession.bind(this));
    
    // Webhook endpoint
    fastify.post('/api/payment/webhook', this.handleWebhook.bind(this));
    
    // Billing endpoints
    fastify.get('/api/payment/invoices/:customerId', this.getInvoices.bind(this));
    
    // Usage endpoints
    fastify.get('/api/payment/usage/:customerId', this.getUsage.bind(this));
    
    this.logger.info('Payment API routes registered');
  }

  /**
   * Create a new customer
   */
  async createCustomer(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    try {
      const { email, name, metadata } = request.body as any;
      
      if (!email) {
        reply.code(400).send({ error: 'Email is required' });
        return;
      }
      
      const customer = await this.stripeService.createCustomer({
        email,
        name,
        metadata
      });
      
      reply.code(201).send({ customer });
    } catch (error) {
      this.logger.error('Failed to create customer', { error });
      reply.code(500).send({ error: 'Failed to create customer' });
    }
  }

  /**
   * Get customer details
   */
  async getCustomer(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    try {
      const { id } = request.params as any;
      
      if (!id) {
        reply.code(400).send({ error: 'Customer ID is required' });
        return;
      }
      
      const customer = await this.stripeService.getCustomer(id);
      const subscription = await this.subscriptionManager.getSubscriptionInfo(id);
      
      reply.send({ customer, subscription });
    } catch (error) {
      this.logger.error('Failed to get customer', { error });
      reply.code(500).send({ error: 'Failed to get customer' });
    }
  }

  /**
   * Get subscription details
   */
  async getSubscription(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    try {
      const { id } = request.params as any;
      
      if (!id) {
        reply.code(400).send({ error: 'Subscription ID is required' });
        return;
      }
      
      const subscription = await this.stripeService.getSubscription(id);
      reply.send({ subscription });
    } catch (error) {
      this.logger.error('Failed to get subscription', { error });
      reply.code(500).send({ error: 'Failed to get subscription' });
    }
  }

  /**
   * Create a new subscription
   */
  async createSubscription(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    try {
      const { customerId, planType, trialDays, metadata } = request.body as any;
      
      if (!customerId || !planType) {
        reply.code(400).send({ error: 'Customer ID and plan type are required' });
        return;
      }
      
      const subscription = await this.stripeService.createSubscription({
        customerId,
        planType,
        trialDays,
        metadata
      });
      
      reply.code(201).send({ subscription });
    } catch (error) {
      this.logger.error('Failed to create subscription', { error });
      reply.code(500).send({ error: 'Failed to create subscription' });
    }
  }

  /**
   * Update a subscription
   */
  async updateSubscription(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    try {
      const { id } = request.params as any;
      const { planType } = request.body as any;
      
      if (!id || !planType) {
        reply.code(400).send({ error: 'Subscription ID and plan type are required' });
        return;
      }
      
      const subscription = await this.subscriptionManager.upgradeSubscription(
        id,
        planType as SubscriptionTier
      );
      
      reply.send({ subscription });
    } catch (error) {
      this.logger.error('Failed to update subscription', { error });
      reply.code(500).send({ error: 'Failed to update subscription' });
    }
  }

  /**
   * Cancel a subscription
   */
  async cancelSubscription(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    try {
      const { id } = request.params as any;
      
      if (!id) {
        reply.code(400).send({ error: 'Subscription ID is required' });
        return;
      }
      
      await this.subscriptionManager.cancelSubscription(id);
      reply.send({ success: true });
    } catch (error) {
      this.logger.error('Failed to cancel subscription', { error });
      reply.code(500).send({ error: 'Failed to cancel subscription' });
    }
  }

  /**
   * Create a checkout session
   */
  async createCheckoutSession(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    try {
      const { customerId, planType, successUrl, cancelUrl } = request.body as any;
      
      if (!customerId || !planType || !successUrl || !cancelUrl) {
        reply.code(400).send({ 
          error: 'Customer ID, plan type, success URL, and cancel URL are required' 
        });
        return;
      }
      
      const checkoutUrl = await this.subscriptionManager.createCheckoutSession(
        customerId,
        planType as SubscriptionTier,
        successUrl,
        cancelUrl
      );
      
      reply.send({ url: checkoutUrl });
    } catch (error) {
      this.logger.error('Failed to create checkout session', { error });
      reply.code(500).send({ error: 'Failed to create checkout session' });
    }
  }

  /**
   * Handle Stripe webhook events
   */
  async handleWebhook(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    try {
      const signature = request.headers['stripe-signature'] as string;
      
      if (!signature) {
        reply.code(400).send({ error: 'Stripe signature is required' });
        return;
      }
      
      const rawBody = request.body as string;
      const event = await this.stripeService.handleWebhookEvent(rawBody, signature);
      
      // Process the event based on its type
      switch (event.type) {
        case 'customer.subscription.created':
        case 'customer.subscription.updated':
          this.logger.info('Subscription event received', { type: event.type });
          // Handle subscription updates
          break;
          
        case 'invoice.payment_succeeded':
          this.logger.info('Invoice payment succeeded', { invoiceId: event.data.object.id });
          // Handle successful payment
          break;
          
        case 'invoice.payment_failed':
          this.logger.info('Invoice payment failed', { invoiceId: event.data.object.id });
          // Handle failed payment
          break;
          
        default:
          this.logger.info('Unhandled event type', { type: event.type });
      }
      
      reply.send({ received: true });
    } catch (error) {
      this.logger.error('Failed to handle webhook', { error });
      reply.code(400).send({ error: 'Failed to handle webhook' });
    }
  }

  /**
   * Get invoices for a customer
   */
  async getInvoices(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    try {
      const { customerId } = request.params as any;
      
      if (!customerId) {
        reply.code(400).send({ error: 'Customer ID is required' });
        return;
      }
      
      const invoices = await this.stripeService.getCustomerInvoices(customerId);
      reply.send({ invoices });
    } catch (error) {
      this.logger.error('Failed to get invoices', { error });
      reply.code(500).send({ error: 'Failed to get invoices' });
    }
  }

  /**
   * Get usage statistics for a customer
   */
  async getUsage(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    try {
      const { customerId } = request.params as any;
      
      if (!customerId) {
        reply.code(400).send({ error: 'Customer ID is required' });
        return;
      }
      
      const usage = await this.subscriptionManager.getUsageStats(customerId);
      reply.send({ usage });
    } catch (error) {
      this.logger.error('Failed to get usage', { error });
      reply.code(500).send({ error: 'Failed to get usage' });
    }
  }
}
