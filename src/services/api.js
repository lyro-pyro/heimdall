/**
 * API service for communicating with the backend /analyze endpoint.
 */
import axios from 'axios';

// Use relative path in production (Vercel rewrites to /api) and localhost for dev
const API_BASE = import.meta.env.PROD ? '' : (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000');

const apiClient = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 120000,
});

/**
 * Send content for analysis.
 * @param {Object} payload - { input_type, content, options }
 * @returns {Promise<Object>} Analysis response
 */
export async function analyzeContent(payload) {
  try {
    const response = await apiClient.post('/analyze', payload, {
      headers: {
        'X-API-KEY': 'heimdall-secret-key',
      },
    });
    return response.data;
  } catch (error) {
    if (error.response) {
      const detail = error.response.data?.detail;
      throw new Error(
        typeof detail === 'string'
          ? detail
          : JSON.stringify(detail) || `Server error: ${error.response.status}`
      );
    }
    throw new Error('Network error — is the backend running?');
  }
}

/**
 * Check backend health.
 * @returns {Promise<Object>}
 */
export async function checkHealth() {
  const response = await apiClient.get('/health');
  return response.data;
}
