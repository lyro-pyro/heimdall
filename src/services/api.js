/**
 * API service for communicating with the backend.
 * Endpoints: /analyze, /logs (ingest), /logs (retrieve), /health
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

const AUTH_HEADERS = { 'X-API-KEY': 'heimdall-secret-key' };

/**
 * Send content for analysis.
 * @param {Object} payload - { input_type, content, options }
 * @returns {Promise<Object>} Analysis response (includes structured_logs when input is log type)
 */
export async function analyzeContent(payload) {
  try {
    const response = await apiClient.post('/analyze', payload, {
      headers: AUTH_HEADERS,
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
 * Ingest raw or structured logs via POST /logs.
 * @param {Object} payload - { raw_content?, logs?, file_name? }
 * @returns {Promise<Object>} { logs, total, parse_errors, parse_warnings }
 */
export async function ingestLogs(payload) {
  try {
    const response = await apiClient.post('/logs', payload, {
      headers: AUTH_HEADERS,
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
 * Retrieve stored structured logs via GET /logs.
 * @param {Object} filters - { level?, service?, limit? }
 * @returns {Promise<Object>} { logs, total }
 */
export async function fetchLogs(filters = {}) {
  try {
    const params = {};
    if (filters.level) params.level = filters.level;
    if (filters.service) params.service = filters.service;
    if (filters.limit) params.limit = filters.limit;

    const response = await apiClient.get('/logs', {
      headers: AUTH_HEADERS,
      params,
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
