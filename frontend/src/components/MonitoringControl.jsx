import React, { useState, useEffect } from 'react'
import { Play, Square, Loader2, Activity, AlertCircle } from 'lucide-react'
import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL || ''

function MonitoringControl() {
  const [status, setStatus] = useState({
    worker_running: false,
    beat_running: false,
    monitoring_active: false
  })
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState('')

  useEffect(() => {
    fetchStatus()
    // Check status every 2 minutes instead of 10 seconds
    const interval = setInterval(fetchStatus, 120000)
    return () => clearInterval(interval)
  }, [])

  const fetchStatus = async () => {
    try {
      const response = await axios.get(`${API_URL}/api/monitoring/status`)
      setStatus(response.data)
    } catch (error) {
      console.error('Failed to fetch monitoring status:', error)
    }
  }

  const handleStart = async () => {
    setLoading(true)
    setMessage('')
    try {
      const response = await axios.post(`${API_URL}/api/monitoring/start`)
      if (response.data.success) {
        setMessage('✅ Monitoring started successfully!')
        await fetchStatus()
      } else {
        setMessage(`❌ ${response.data.message}`)
      }
    } catch (error) {
      setMessage(`❌ Failed to start monitoring: ${error.message}`)
    }
    setLoading(false)
    setTimeout(() => setMessage(''), 5000)
  }

  const handleStop = async () => {
    setLoading(true)
    setMessage('')
    try {
      const response = await axios.post(`${API_URL}/api/monitoring/stop`)
      setMessage('✅ Monitoring stopped')
      await fetchStatus()
    } catch (error) {
      setMessage(`❌ Failed to stop monitoring: ${error.message}`)
    }
    setLoading(false)
    setTimeout(() => setMessage(''), 5000)
  }

  return (
    <div className="bg-white rounded-lg shadow p-4 border-l-4 border-primary-500">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-full ${status.monitoring_active ? 'bg-success-100' : 'bg-gray-100'}`}>
            <Activity className={`h-6 w-6 ${status.monitoring_active ? 'text-success-600' : 'text-gray-400'}`} />
          </div>
          <div>
            <h3 className="text-lg font-semibold text-gray-900">Background Monitoring</h3>
            <p className="text-sm text-gray-500">
              {status.monitoring_active ? (
                <span className="text-success-600 font-medium">● Active - Scanning every 15 minutes</span>
              ) : (
                <span className="text-gray-500">○ Inactive - Manual mode</span>
              )}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {loading ? (
            <button
              disabled
              className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-gray-400 cursor-not-allowed"
            >
              <Loader2 className="h-5 w-5 mr-2 animate-spin" />
              Processing...
            </button>
          ) : status.monitoring_active ? (
            <button
              onClick={handleStop}
              className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-danger-600 hover:bg-danger-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-danger-500"
            >
              <Square className="h-5 w-5 mr-2" />
              Stop Monitoring
            </button>
          ) : (
            <button
              onClick={handleStart}
              className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-success-600 hover:bg-success-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-success-500"
            >
              <Play className="h-5 w-5 mr-2" />
              Start Monitoring
            </button>
          )}
        </div>
      </div>

      {/* Status Details */}
      <div className="mt-4 pt-4 border-t border-gray-200">
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div className="flex items-center justify-between">
            <span className="text-gray-600">Worker:</span>
            <span className={`font-medium ${status.worker_running ? 'text-success-600' : 'text-gray-400'}`}>
              {status.worker_running ? '● Running' : '○ Stopped'}
            </span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-gray-600">Scheduler:</span>
            <span className={`font-medium ${status.beat_running ? 'text-success-600' : 'text-gray-400'}`}>
              {status.beat_running ? '● Running' : '○ Stopped'}
            </span>
          </div>
        </div>
      </div>

      {/* Message Display */}
      {message && (
        <div className="mt-4 p-3 rounded-md bg-primary-50 border border-primary-200">
          <div className="flex items-center">
            <AlertCircle className="h-5 w-5 text-primary-600 mr-2" />
            <p className="text-sm text-primary-800">{message}</p>
          </div>
        </div>
      )}

      {/* Info */}
      {!status.monitoring_active && !message && (
        <div className="mt-4 p-3 rounded-md bg-gray-50 border border-gray-200">
          <p className="text-xs text-gray-600">
            <strong>Note:</strong> Starting monitoring will automatically scan for phishing variations 
            of all CSE domains every 15 minutes. Stop it when not needed to save resources.
          </p>
        </div>
      )}
    </div>
  )
}

export default MonitoringControl

