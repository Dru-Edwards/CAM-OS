// Main entry point for the Complete Arbitration Mesh
export { CompleteArbitrationMesh } from './core/complete-arbitration-mesh';
export { CAMClient } from './client/cam-client';

// Core types and interfaces
export type {
  // Routing types
  AICoreRequest,
  AICoreResponse,
  ProviderRequirements,
  ProviderInfo,
  PolicyValidationRequest,
  PolicyValidationResult,
  
  // Collaboration types
  CollaborationRequest,
  CollaborationSession,
  CollaborationResult,
  AgentCapabilities,
  AgentInfo,
  ComplexTask,
  TaskComponents,
  CollaborationWorkflow,
  
  // Shared types
  ConfigurationUpdate,
  ConfigurationResult,
  MetricsQuery,
  MetricsData,
  AuthToken,
  Session
} from './shared/types';

// Utilities and helpers
export { Logger } from './shared/logger';
export { Config } from './shared/config';
export { validateRequest } from './shared/validation';

// Error classes
export {
  CAMError,
  RoutingError,
  CollaborationError,
  AuthenticationError,
  ValidationError
} from './shared/errors';

// Constants
export { VERSION, API_VERSION } from './shared/constants';

// Payment and subscription exports
export {
  StripeService,
  SubscriptionManager,
  PaymentAPI
} from './payment';

export type {
  StripeServiceOptions,
  CustomerData,
  SubscriptionData,
  CheckoutSessionOptions,
  SubscriptionTier,
  SubscriptionFeatures,
  SubscriptionInfo,
  SubscriptionManagerOptions,
  PaymentAPIOptions
} from './payment';
