import fetch from 'cross-fetch';
import * as Types from './types';
import * as Errors from './errors';
import {
  validateRequest,
  validateCollaborationRequest,
  formatHeaders,
  parseResponse,
  createRetryWrapper,
  generateRequestSignature,
  deepMerge
} from './utils';

const DEFAULT_OPTIONS: Partial<Types.CAMClientOptions> = {
  endpoint: 'https://api.cam.example.com',
  timeout: 30000,
  maxRetries: 3,
  retryDelay: 1000
};

export class CAMClient {
  private options: Types.CAMClientOptions;

  constructor(options: Types.CAMClientOptions) {
    if (!options || !options.apiKey) {
      throw new Errors.CAMConfigurationError('API key is required', 'apiKey');
    }

    this.options = deepMerge(
      DEFAULT_OPTIONS as Types.CAMClientOptions,
      options
    );
  }

  /** Route a request to the optimal provider */
  async route(request: Types.RouteRequest): Promise<Types.RouteResponse> {
    validateRequest(request.request);
    return this.request<Types.RouteResponse>('POST', '/v2/route', request);
  }

  /** Route multiple requests in a single batch */
  async batchRoute(
    requests: Types.RouteRequest[]
  ): Promise<Types.RouteResponse[]> {
    requests.forEach(r => validateRequest(r.request));
    return this.request<Types.RouteResponse[]>(
      'POST',
      '/v2/route/batch',
      { requests }
    );
  }

  /** Start a collaboration workflow */
  async collaborate(
    request: Types.CollaborationRequest
  ): Promise<Types.CollaborationResponse> {
    validateCollaborationRequest(request);
    return this.request<Types.CollaborationResponse>(
      'POST',
      '/v2/collaborate',
      request
    );
  }

  /** Stream responses for a request */
  async *stream(
    request: Types.StreamRequest
  ): AsyncGenerator<Types.StreamChunk> {
    validateRequest(request.request);
    const response = (await this.request<Response>(
      'POST',
      '/v2/stream',
      request,
      true
    )) as Response;

    if (!response.body) {
      throw new Errors.CAMNetworkError('No response body', new Error('empty'));
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let index;
      while ((index = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, index).trim();
        buffer = buffer.slice(index + 1);
        if (line) {
          yield JSON.parse(line) as Types.StreamChunk;
        }
      }
    }

    const remaining = buffer.trim();
    if (remaining) {
      yield JSON.parse(remaining) as Types.StreamChunk;
    }
  }

  /** Retrieve available models */
  async getModels(): Promise<any[]> {
    return this.request<any[]>('GET', '/v2/models');
  }

  /** Retrieve usage statistics */
  async getUsage(options?: any): Promise<any> {
    return this.request<any>('GET', '/v2/usage', options);
  }

  private async request<T>(
    method: string,
    path: string,
    body?: any,
    raw = false
  ): Promise<T | Response> {
    const url = `${this.options.endpoint}${path}`;
    const headers = formatHeaders(this.options.apiKey, { contentType: 'application/json' });

    if (this.options.security?.signRequests) {
      const timestamp = Date.now();
      const signature = generateRequestSignature(
        method,
        path,
        body ? JSON.stringify(body) : '',
        timestamp,
        this.options.apiKey
      );
      headers['X-Signature'] = signature;
      headers['X-Timestamp'] = timestamp.toString();
    }

    const init: RequestInit = {
      method,
      headers,
      signal: AbortSignal.timeout(this.options.timeout)
    };

    if (body && method !== 'GET') {
      init.body = JSON.stringify(body);
    }

    const doFetch = async (): Promise<T | Response> => {
      const res = await fetch(url, init);
      if (raw) return res;
      return parseResponse<T>(res);
    };

    const wrapped = createRetryWrapper(doFetch, this.options.maxRetries, this.options.retryDelay);
    return wrapped();
  }
}

export default CAMClient;
