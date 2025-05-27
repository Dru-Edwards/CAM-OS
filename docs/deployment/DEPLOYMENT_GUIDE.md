# Deployment Guide for Complete Arbitration Mesh

This guide provides step-by-step instructions for deploying the Complete Arbitration Mesh (CAM) Protocol in various environments.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Setup](#environment-setup)
3. [Deployment Options](#deployment-options)
   - [Docker Deployment](#docker-deployment)
   - [Kubernetes Deployment](#kubernetes-deployment)
   - [Cloud Provider Deployments](#cloud-provider-deployments)
4. [Payment Integration Setup](#payment-integration-setup)
5. [Post-Deployment Verification](#post-deployment-verification)
6. [Monitoring and Maintenance](#monitoring-and-maintenance)

## Prerequisites

Before deploying the CAM Protocol, ensure you have the following:

- Node.js 18.x or higher
- npm 8.x or higher
- Docker (for containerized deployments)
- Kubernetes (for orchestrated deployments)
- Stripe account with API keys (for payment processing)
- API keys for AI providers (OpenAI, Anthropic, etc.)

## Environment Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/cam-protocol/complete-arbitration-mesh.git
   cd complete-arbitration-mesh
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Create an environment file:
   ```bash
   cp .env.example .env
   ```

4. Edit the `.env` file with your configuration values:
   ```
   # Required environment variables
   NODE_ENV=production
   PORT=8080
   JWT_SECRET=your-secure-jwt-secret
   
   # Stripe configuration
   STRIPE_SECRET_KEY=sk_live_your_stripe_key
   STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret
   STRIPE_PROFESSIONAL_PRICE_ID=price_your_professional_price_id
   STRIPE_ENTERPRISE_PRICE_ID=price_your_enterprise_price_id
   
   # AI provider keys
   OPENAI_API_KEY=your_openai_key
   ANTHROPIC_API_KEY=your_anthropic_key
   # Add other provider keys as needed
   ```

5. Build the project:
   ```bash
   npm run build
   ```

## Deployment Options

### Docker Deployment

1. Build the Docker image:
   ```bash
   docker build -t cam-protocol/complete-arbitration-mesh:latest .
   ```

2. Run the container:
   ```bash
   docker run -d -p 8080:8080 --env-file .env cam-protocol/complete-arbitration-mesh:latest
   ```

### Kubernetes Deployment

1. Create a Kubernetes secret for environment variables:
   ```bash
   kubectl create secret generic cam-env --from-env-file=.env
   ```

2. Apply the Kubernetes deployment configuration:
   ```bash
   kubectl apply -f deployment/kubernetes/cam-deployment.yaml
   ```

3. Apply the service configuration:
   ```bash
   kubectl apply -f deployment/kubernetes/cam-service.yaml
   ```

4. (Optional) Apply the ingress configuration:
   ```bash
   kubectl apply -f deployment/kubernetes/cam-ingress.yaml
   ```

### Cloud Provider Deployments

#### AWS Deployment

1. Configure AWS CLI:
   ```bash
   aws configure
   ```

2. Deploy using the provided CloudFormation template:
   ```bash
   aws cloudformation deploy \
     --template-file deployment/aws/cam-cloudformation.yaml \
     --stack-name cam-protocol \
     --parameter-overrides \
       Environment=production \
       StripeSecretKey=${STRIPE_SECRET_KEY} \
       StripeWebhookSecret=${STRIPE_WEBHOOK_SECRET}
   ```

#### Azure Deployment

1. Login to Azure:
   ```bash
   az login
   ```

2. Deploy using the provided Azure template:
   ```bash
   az deployment group create \
     --resource-group your-resource-group \
     --template-file deployment/azure/cam-template.json \
     --parameters @deployment/azure/cam-parameters.json
   ```

#### Google Cloud Deployment

1. Login to Google Cloud:
   ```bash
   gcloud auth login
   ```

2. Deploy to Google Cloud Run:
   ```bash
   gcloud run deploy cam-protocol \
     --source . \
     --platform managed \
     --region us-central1 \
     --set-env-vars "NODE_ENV=production,JWT_SECRET=${JWT_SECRET}"
   ```

## Payment Integration Setup

After deploying the CAM Protocol, you need to configure Stripe for payment processing:

1. Create products and prices in the Stripe dashboard:
   - Community tier (free)
   - Growth tier (contact sales)
   - Professional tier (contact sales)
   - Enterprise tier (contact sales)

For pricing information, please contact: [edwardstechpros+cam@outlook.com](mailto:edwardstechpros+cam@outlook.com)

2. Update your environment variables with the product and price IDs.

3. Configure the Stripe webhook:
   - Go to the Stripe Dashboard > Developers > Webhooks
   - Add a new endpoint with your application's URL (e.g., `https://your-domain.com/api/payment/webhook`)
   - Select the events to listen for:
     - `customer.subscription.created`
     - `customer.subscription.updated`
     - `customer.subscription.deleted`
     - `invoice.payment_succeeded`
     - `invoice.payment_failed`
   - Copy the webhook signing secret and update your environment variables

4. Test the payment flow:
   - Create a test customer
   - Subscribe to a plan using test card details
   - Verify webhook events are received and processed

## Post-Deployment Verification

After deployment, verify that everything is working correctly:

1. Check the health endpoint:
   ```bash
   curl https://your-domain.com/health
   ```

2. Verify the API is accessible:
   ```bash
   curl https://your-domain.com/api/version
   ```

3. Test the routing functionality:
   ```bash
   curl -X POST https://your-domain.com/api/arbitration/route \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_API_KEY" \
     -d '{"prompt": "Test prompt", "requirements": {"cost": "optimize"}}'
   ```

4. Test the collaboration functionality:
   ```bash
   curl -X POST https://your-domain.com/api/collaboration/initiate \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer YOUR_API_KEY" \
     -d '{"task": "Test task", "requirements": ["data-analyst"]}'
   ```

## Monitoring and Maintenance

1. Set up monitoring using your preferred solution:
   - Prometheus and Grafana
   - Datadog
   - New Relic
   - AWS CloudWatch
   - Google Cloud Monitoring

2. Configure alerts for:
   - High error rates
   - Increased latency
   - Resource utilization (CPU, memory)
   - Payment failures

3. Regular maintenance tasks:
   - Update dependencies
   - Rotate API keys
   - Backup configuration
   - Review logs for potential issues

4. Scaling considerations:
   - Horizontal scaling for increased load
   - Database scaling for increased data volume
   - Caching for improved performance

For additional support or questions, please contact support@cam-protocol.com or visit our [community forum](https://community.cam-protocol.com).
