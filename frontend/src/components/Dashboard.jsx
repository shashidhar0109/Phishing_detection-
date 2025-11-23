import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { fetchPhishingDetections, fetchStats, deletePhishingDetection, fetchAllDetectionsForTrend } from '../api'
import { 
  AlertTriangle, Shield, TrendingUp, Clock, 
  ExternalLink, Download, Eye, Search, Image, FileText, Trash2
} from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import StatsCards from './StatsCards'
import RiskBadge from './RiskBadge'
import MonitoringControl from './MonitoringControl'
import AnalyticsChart from './AnalyticsChart'
import ExportButton from './ExportButton'
import { getScreenshot } from '../api'
// Real-time features removed for stability

function Dashboard() {
  const navigate = useNavigate()
  const [detections, setDetections] = useState([])
  const [trendDetections, setTrendDetections] = useState([])
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('all')
  const [searchTerm, setSearchTerm] = useState('')
  const [screenshotModal, setScreenshotModal] = useState(null)
  // Real-time features removed for stability

  useEffect(() => {
    loadData()
    // Only refresh every 30 minutes to reduce unnecessary calls
    const interval = setInterval(loadData, 1800000)
    return () => clearInterval(interval)
  }, [filter])

  // Real-time WebSocket handling removed for stability

  const loadData = async () => {
    try {
      const params = {}
      if (filter !== 'all') {
        params.risk_level = filter
      }
      
      const [detectionsRes, trendRes, statsRes] = await Promise.all([
        fetchPhishingDetections(params),
        fetchAllDetectionsForTrend(),
        fetchStats()
      ])
      
      // Ensure we always have arrays
      const detData = Array.isArray(detectionsRes?.data) ? detectionsRes.data : []
      const trendData = Array.isArray(trendRes?.data) ? trendRes.data : []
      const statsData = (statsRes && typeof statsRes.data === 'object') ? statsRes.data : null

      console.log('Loaded data:', { 
        detections: detData.length, 
        trends: trendData.length, 
        stats: statsData,
        detectionsType: typeof detData,
        trendsType: typeof trendData
      })
      
      setDetections(detData)
      setTrendDetections(trendData)
      setStats(statsData)
      setLoading(false)
    } catch (error) {
      console.error('Failed to load data:', error)
      // Set empty arrays on error to prevent crashes
      setDetections([])
      setTrendDetections([])
      setStats(null)
      setLoading(false)
    }
  }

  const handleDelete = async (id) => {
    if (window.confirm('Are you sure you want to delete this phishing detection?')) {
      try {
        await deletePhishingDetection(id)
        loadData() // Reload data after deletion
        window.showToast?.('Detection deleted successfully', 'success')
      } catch (error) {
        console.error('Failed to delete detection:', error)
        window.showToast?.('Failed to delete detection', 'error')
      }
    }
  }

  const safeDetections = Array.isArray(detections) ? detections : []
  const filteredDetections = safeDetections.filter(detection => {
    if (!detection || typeof detection !== 'object') return false
    return (detection.phishing_domain || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
           ((detection.legitimate_domain || '').toLowerCase().includes(searchTerm.toLowerCase()))
  })

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Stats Cards */}
      <StatsCards stats={stats} />

      {/* Real-time features removed for stability */}

      {/* Analytics Charts */}
      <AnalyticsChart stats={stats} detections={trendDetections} />

      {/* Monitoring Control */}
      <MonitoringControl />

      {/* Filters and Search */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4">
        <div className="flex flex-col sm:flex-row justify-between items-center gap-4">
          <div className="flex gap-2 flex-wrap">
            <button
              onClick={() => setFilter('all')}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                filter === 'all'
                  ? 'bg-primary-600 text-white'
                  : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
              }`}
            >
              All
            </button>
            <button
              onClick={() => setFilter('HIGH')}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                filter === 'HIGH'
                  ? 'bg-danger-600 text-white'
                  : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
              }`}
            >
              High Risk
            </button>
            <button
              onClick={() => setFilter('MEDIUM')}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                filter === 'MEDIUM'
                  ? 'bg-warning-600 text-white'
                  : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
              }`}
            >
              Medium Risk
            </button>
            <button
              onClick={() => setFilter('LOW')}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                filter === 'LOW'
                  ? 'bg-success-600 text-white'
                  : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
              }`}
            >
              Low Risk
            </button>
            <ExportButton data={filteredDetections} filename="phishing-detections" />
          </div>
          
          <div className="relative w-full sm:w-64">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 dark:text-gray-500 h-5 w-5" />
            <input
              type="text"
              placeholder="Search domains..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-colors"
            />
          </div>
        </div>
      </div>

      {/* Detections Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
              Recent Phishing Detections
            </h2>
            <span className="text-sm text-gray-500 dark:text-gray-400">
              {filteredDetections.length} {filteredDetections.length === 1 ? 'detection' : 'detections'}
            </span>
          </div>
        </div>
        
        <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead className="bg-gray-50 dark:bg-gray-900 sticky top-0 z-10">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider bg-gray-50 dark:bg-gray-900">
                  Risk
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider bg-gray-50 dark:bg-gray-900">
                  Phishing Domain
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider bg-gray-50 dark:bg-gray-900">
                  Legitimate Domain
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider bg-gray-50 dark:bg-gray-900">
                  Detected
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider bg-gray-50 dark:bg-gray-900">
                  Country
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider bg-gray-50 dark:bg-gray-900">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
              {filteredDetections.length === 0 ? (
                <tr>
                  <td colSpan="6" className="px-6 py-8 text-center text-gray-500 dark:text-gray-400">
                    No phishing detections found
                  </td>
                </tr>
              ) : (
                filteredDetections.map((detection) => (
                  <tr key={detection.id} className="hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <RiskBadge level={detection.risk_level} score={detection.risk_score} />
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center">
                        <AlertTriangle className="h-4 w-4 text-danger-500 mr-2" />
                        <span className="text-sm font-medium text-gray-900">
                          {detection.phishing_domain}
                        </span>
                      </div>
                      <div className="text-xs text-gray-500 mt-1">
                        {detection.variation_type}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center">
                        <Shield className="h-4 w-4 text-success-500 mr-2" />
                        <span className="text-sm text-gray-900">
                          {detection.legitimate_domain || 'Unknown'}
                        </span>
                      </div>
                      <div className="text-xs text-gray-500 mt-1">
                        {detection.organization_name}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center text-sm text-gray-500">
                        <Clock className="h-4 w-4 mr-1" />
                        {formatDistanceToNow(new Date(detection.detected_at), { addSuffix: true })}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {detection.country || 'Unknown'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={(e) => {
                            e.preventDefault()
                            console.log('Navigating to detection:', detection.id)
                            navigate(`/detection/${detection.id}`)
                          }}
                          className="text-primary-600 hover:text-primary-900 cursor-pointer"
                          title="View Details"
                          aria-label={`View details for ${detection.phishing_domain}`}
                        >
                          <Eye className="h-5 w-5" />
                        </button>
                        {detection.screenshot_path && (
                          <button
                            onClick={() => setScreenshotModal(detection)}
                            className="text-purple-600 hover:text-purple-900"
                            title="View Screenshot"
                            aria-label={`View screenshot for ${detection.phishing_domain}`}
                          >
                            <Image className="h-5 w-5" />
                          </button>
                        )}
                        <button
                          onClick={() => handleDelete(detection.id)}
                          className="text-danger-600 hover:text-danger-900"
                          title="Delete Detection"
                          aria-label={`Delete detection for ${detection.phishing_domain}`}
                        >
                          <Trash2 className="h-5 w-5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Screenshot Modal */}
      {screenshotModal && (
        <div 
          className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50 p-4"
          onClick={() => setScreenshotModal(null)}
        >
          <div className="relative max-w-6xl max-h-full bg-white rounded-lg shadow-xl overflow-hidden">
            <div className="sticky top-0 bg-white border-b border-gray-200 px-6 py-4 flex justify-between items-center">
              <div>
                <h3 className="text-lg font-semibold text-gray-900">
                  Screenshot: {screenshotModal.phishing_domain}
                </h3>
                <p className="text-sm text-gray-500">
                  Risk: <span className={`font-medium ${
                    screenshotModal.risk_level === 'HIGH' ? 'text-danger-600' :
                    screenshotModal.risk_level === 'MEDIUM' ? 'text-warning-600' :
                    'text-success-600'
                  }`}>{screenshotModal.risk_level}</span> ({Math.round(screenshotModal.risk_score)}/100)
                </p>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => setScreenshotModal(null)}
                  className="px-3 py-2 bg-gray-100 text-gray-700 rounded-md hover:bg-gray-200"
                >
                  Close
                </button>
              </div>
            </div>
            <div className="p-6 overflow-auto max-h-[80vh]">
              <img
                src={getScreenshot(screenshotModal.id)}
                alt={`Screenshot of ${screenshotModal.phishing_domain}`}
                className="w-full border border-gray-300 rounded-lg"
                onClick={(e) => e.stopPropagation()}
                onError={(e) => {
                  e.target.style.display = 'none'
                  e.target.nextSibling.style.display = 'flex'
                }}
              />
              <div 
                className="hidden w-full h-64 border border-gray-300 rounded-lg bg-gray-100 items-center justify-center flex-col"
                style={{ display: 'none' }}
              >
                <div className="text-center">
                  <div className="text-2xl font-bold text-gray-500 mb-2">Screenshot Unavailable</div>
                  <div className="text-sm text-gray-600">Domain: {screenshotModal.phishing_domain}</div>
                  <div className="text-sm text-gray-600">Time: {new Date(screenshotModal.detected_at).toLocaleString()}</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default Dashboard

