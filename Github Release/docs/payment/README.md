# Payment Integration Module

The CAM Protocol payment integration module provides a complete solution for managing subscriptions, processing payments, and controlling access to features based on subscription tiers.

## Overview

The payment module consists of the following components:

1. **Stripe Service**: Handles all interactions with the Stripe API
2. **Subscription Manager**: Manages subscription tiers and feature access
3. **Payment API**: Exposes payment functionality through a RESTful API

## Getting Started

### Prerequisites

- Stripe account with API keys
- Configured products and prices in Stripe dashboard

### Installation

The payment module is included in the Complete Arbitration Mesh package:

```bash
npm install @cam-protocol/complete-arbitration-mesh
```

### Configuration

To use the payment module, you need to configure it with your Stripe API keys:

```typescript
import { 
  CompleteArbitrationMesh, 
  StripeService,
  SubscriptionManager,
  PaymentAPI
} from '@cam-protocol/complete-arbitration-mesh';

// Initialize Stripe service
const stripeService = new StripeService({
  apiKey: process.env.STRIPE_SECRET_KEY,
  webhookSecret: process.env.STRIPE_WEBHOOK_SECRET,
  productMapping: {
    community: process.env.STRIPE_COMMUNITY_PRODUCT_ID,
    professional: process.env.STRIPE_PROFESSIONAL_PRODUCT_ID,
    enterprise: process.env.STRIPE_ENTERPRISE_PRODUCT_ID
  },
  priceMapping: {
    community: process.env.STRIPE_COMMUNITY_PRICE_ID,
    professional: process.env.STRIPE_PROFESSIONAL_PRICE_ID,
    enterprise: process.env.STRIPE_ENTERPRISE_PRICE_ID
  }
});

// Initialize subscription manager
const subscriptionManager = new SubscriptionManager({
  stripeService
});

// Initialize payment API
const paymentAPI = new PaymentAPI({
  stripeService,
  subscriptionManager
});

// Register payment API routes with your Fastify instance
import fastify from 'fastify';
const app = fastify();
paymentAPI.registerRoutes(app);
```

## Subscription Tiers

The CAM Protocol offers four subscription tiers:

| Feature | Community | Growth | Professional | Enterprise |
|---------|:---------:|:------:|:------------:|:----------:|
| **AI Model Arbitration** | ✅ | ✅ | ✅ | ✅ |
| **Agent Collaboration** | Basic | Standard | Advanced | Comprehensive |
| **Policy Management** | Limited | Standard | Advanced | Enterprise-grade |
| **Support** | Community | Email | Business Hours | 24/7 Premium |
| **SLA** | None | 99.9% | 99.95% | 99.99% |
| **Price** | Free | [Contact Us](mailto:edwardstechpros@outlook.com) | [Contact Us](mailto:edwardstechpros@outlook.com) | [Contact Us](mailto:edwardstechpros@outlook.com) |

## API Reference

### Stripe Service

The Stripe Service provides methods for interacting with the Stripe API:

```typescript
// Create a customer
const customer = await stripeService.createCustomer({
  email: 'customer@example.com',
  name: 'Example Customer'
});

// Create a subscription
const subscription = await stripeService.createSubscription({
  customerId: customer.id,
  planType: 'professional',
  trialDays: 14
});

// Create a checkout session
const session = await stripeService.createCheckoutSession({
  customerId: customer.id,
  planType: 'professional',
  successUrl: 'https://example.com/success',
  cancelUrl: 'https://example.com/cancel'
});
```

### Subscription Manager

The Subscription Manager provides methods for managing subscriptions and feature access:

```typescript
// Get subscription information
const subscription = await subscriptionManager.getSubscriptionInfo(customerId);

// Check if a feature is available
const hasFeature = await subscriptionManager.hasFeature(
  customerId, 
  'advancedCollaboration'
);

// Upgrade a subscription
const updatedSubscription = await subscriptionManager.upgradeSubscription(
  subscriptionId,
  'enterprise'
);

// Get usage statistics
const usage = await subscriptionManager.getUsageStats(customerId);
```

### Payment API

The Payment API exposes RESTful endpoints for payment functionality:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/payment/customers` | POST | Create a new customer |
| `/api/payment/customers/:id` | GET | Get customer details |
| `/api/payment/subscriptions/:id` | GET | Get subscription details |
| `/api/payment/subscriptions` | POST | Create a new subscription |
| `/api/payment/subscriptions/:id` | PUT | Update a subscription |
| `/api/payment/subscriptions/:id` | DELETE | Cancel a subscription |
| `/api/payment/checkout` | POST | Create a checkout session |
| `/api/payment/webhook` | POST | Handle Stripe webhook events |
| `/api/payment/invoices/:customerId` | GET | Get customer invoices |
| `/api/payment/usage/:customerId` | GET | Get usage statistics |

## Webhook Integration

To handle Stripe webhook events, you need to configure a webhook endpoint in your Stripe dashboard and set up the webhook handler in your application:

1. Go to the Stripe Dashboard > Developers > Webhooks
2. Add a new endpoint with your application's URL (e.g., `https://example.com/api/payment/webhook`)
3. Select the events you want to receive (e.g., `customer.subscription.created`, `invoice.payment_succeeded`)
4. Copy the webhook signing secret and set it as `STRIPE_WEBHOOK_SECRET` in your environment variables

The Payment API will automatically handle webhook events and update subscription status accordingly.

## Security Considerations

- Always use environment variables for API keys and secrets
- Never expose your Stripe secret key in client-side code
- Use HTTPS for all API endpoints
- Validate webhook signatures to prevent unauthorized requests
- Implement proper authentication and authorization for payment endpoints

## Testing

You can use Stripe's test mode to test payment integration without making real charges:

1. Use Stripe's test API keys
2. Use test card numbers (e.g., `4242 4242 4242 4242` for successful payments)
3. Test webhook events using the Stripe CLI or dashboard

For more information, see the [Stripe Testing Documentation](https://stripe.com/docs/testing).
