import axios from 'axios'

// Use the environment variable or default to the backend URL
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001'

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  },
  withCredentials: true,
  timeout: 300000, // 5 minute timeout for large uploads
})

// Add request interceptor for error handling
api.interceptors.request.use(
  (config) => {
    console.log(`🔄 API Request: ${config.method?.toUpperCase()} ${config.url}`)
    return config
  },
  (error) => {
    console.error('❌ API Request Error:', error)
    return Promise.reject(error)
  }
)

// Add response interceptor for error handling
api.interceptors.response.use(
  (response) => {
    console.log(`✅ API Response: ${response.status} ${response.config.url}`)
    return response
  },
  (error) => {
    console.error('❌ API Response Error:', error.response?.status, error.message)
    
    // Handle specific error cases
    if (error.code === 'ECONNREFUSED') {
      console.error('❌ Backend server is not running. Please start it with: ./start-backend.sh')
    } else if (error.response?.status === 404) {
      console.error('❌ API endpoint not found')
    } else if (error.response?.status >= 500) {
      console.error('❌ Server error occurred')
    }
    
    return Promise.reject(error)
  }
)

// CSE Domains
export const fetchCSEDomains = () => api.get('/api/cse-domains')
export const addCSEDomain = (data) => api.post('/api/cse-domains', data)
export const bulkAddCSEDomains = (domains) => api.post('/api/cse-domains/bulk', { domains })
export const deleteCSEDomain = (id) => api.delete(`/api/cse-domains/${id}`)

// Phishing Detections
export const fetchPhishingDetections = (params = {}) => 
  api.get('/api/phishing-detections', { params })
export const fetchPhishingDetection = (id) => 
  api.get(`/api/phishing-detections/${id}`)
export const deletePhishingDetection = (id) => 
  api.delete(`/api/phishing-detections/${id}`)
export const fetchAllDetectionsForTrend = () => 
  api.get('/api/phishing-detections/all-for-trend')

// Statistics
export const fetchStats = () => api.get('/api/stats')

// Manual Check
export const manualCheckDomain = (domain) => 
  api.post('/api/manual-check', { domain })

// Reports
export const getScreenshot = (id) => 
  `${API_BASE_URL}/api/screenshots/${id}`

export default api

