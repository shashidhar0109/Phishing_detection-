import React, { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { fetchPhishingDetection, getScreenshot } from '../api'
import { 
  ArrowLeft, Download, Globe, Server, Shield, 
  Calendar, MapPin, FileText, AlertTriangle 
} from 'lucide-react'
import RiskBadge from './RiskBadge'
import { formatDistanceToNow } from 'date-fns'

function DetectionDetails() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [detection, setDetection] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadDetection()
  }, [id])

  const loadDetection = async () => {
    try {
      const response = await fetchPhishingDetection(id)
      setDetection(response.data)
      setLoading(false)
    } catch (error) {
      console.error('Failed to load detection:', error)
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  if (!detection) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-500">Detection not found</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white rounded-lg shadow p-6">
        <button
          onClick={() => navigate('/')}
          className="flex items-center text-sm text-gray-500 hover:text-gray-700 mb-4"
        >
          <ArrowLeft className="h-4 w-4 mr-1" />
          Back to Dashboard
        </button>
        
        <div className="flex justify-between items-start">
          <div>
            <div className="flex items-center gap-3">
              <AlertTriangle className="h-8 w-8 text-danger-500" />
              <h1 className="text-2xl font-bold text-gray-900">
                {detection.phishing_domain}
              </h1>
            </div>
            <p className="mt-2 text-sm text-gray-500">
              Detected {formatDistanceToNow(new Date(detection.detected_at), { addSuffix: true })}
            </p>
          </div>
          
          <div className="flex items-center gap-4">
            <RiskBadge level={detection.risk_level} score={detection.risk_score} />
          </div>
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Domain Information */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">
            Domain Information
          </h2>
          <dl className="space-y-3">
            <div className="flex justify-between">
              <dt className="text-sm font-medium text-gray-500">Legitimate Domain</dt>
              <dd className="text-sm text-gray-900 flex items-center">
                <Shield className="h-4 w-4 text-success-500 mr-1" />
                {detection.legitimate_domain || 'Unknown'}
              </dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-sm font-medium text-gray-500">Organization</dt>
              <dd className="text-sm text-gray-900">{detection.organization_name || 'Unknown'}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-sm font-medium text-gray-500">Variation Type</dt>
              <dd className="text-sm text-gray-900">
                <span className="px-2 py-1 bg-gray-100 rounded text-xs">
                  {detection.variation_type}
                </span>
              </dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-sm font-medium text-gray-500">Domain Created</dt>
              <dd className="text-sm text-gray-900 flex items-center">
                <Calendar className="h-4 w-4 mr-1 text-gray-400" />
                {detection.domain_created_at 
                  ? new Date(detection.domain_created_at).toLocaleDateString()
                  : 'Unknown'}
              </dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-sm font-medium text-gray-500">Registrar</dt>
              <dd className="text-sm text-gray-900">{detection.registrar || 'Unknown'}</dd>
            </div>
          </dl>
        </div>

        {/* Network Information */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">
            Network Information
          </h2>
          <dl className="space-y-3">
            <div className="flex justify-between">
              <dt className="text-sm font-medium text-gray-500">IP Address</dt>
              <dd className="text-sm text-gray-900 flex items-center">
                <Server className="h-4 w-4 mr-1 text-gray-400" />
                {detection.ip_address || 'Unknown'}
              </dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-sm font-medium text-gray-500">Country</dt>
              <dd className="text-sm text-gray-900 flex items-center">
                <MapPin className="h-4 w-4 mr-1 text-gray-400" />
                {detection.country || 'Unknown'}
              </dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-sm font-medium text-gray-500">ASN</dt>
              <dd className="text-sm text-gray-900">{detection.asn || 'Unknown'}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-sm font-medium text-gray-500">SSL Issuer</dt>
              <dd className="text-sm text-gray-900">{detection.ssl_issuer || 'None'}</dd>
            </div>
            {detection.mx_records && detection.mx_records.length > 0 && (
              <div className="flex justify-between">
                <dt className="text-sm font-medium text-gray-500">MX Records</dt>
                <dd className="text-sm text-gray-900">
                  {detection.mx_records.length} record(s)
                </dd>
              </div>
            )}
          </dl>
        </div>

        {/* Analysis Results */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">
            Analysis Results
          </h2>
          <dl className="space-y-3">
            <div className="flex justify-between items-center">
              <dt className="text-sm font-medium text-gray-500">Visual Similarity</dt>
              <dd className="text-sm text-gray-900">
                <div className="flex items-center">
                  <div className="w-32 bg-gray-200 rounded-full h-2 mr-2">
                    <div
                      className="bg-primary-600 h-2 rounded-full"
                      style={{ width: `${detection.visual_similarity_score}%` }}
                    ></div>
                  </div>
                  <span className="font-medium">{Math.round(detection.visual_similarity_score)}%</span>
                </div>
              </dd>
            </div>
            <div className="flex justify-between items-center">
              <dt className="text-sm font-medium text-gray-500">Content Similarity</dt>
              <dd className="text-sm text-gray-900">
                <div className="flex items-center">
                  <div className="w-32 bg-gray-200 rounded-full h-2 mr-2">
                    <div
                      className="bg-primary-600 h-2 rounded-full"
                      style={{ width: `${detection.content_similarity_score}%` }}
                    ></div>
                  </div>
                  <span className="font-medium">{Math.round(detection.content_similarity_score)}%</span>
                </div>
              </dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-sm font-medium text-gray-500">Login Form Detected</dt>
              <dd className="text-sm">
                <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                  detection.has_login_form 
                    ? 'bg-danger-100 text-danger-800' 
                    : 'bg-gray-100 text-gray-800'
                }`}>
                  {detection.has_login_form ? 'Yes' : 'No'}
                </span>
              </dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-sm font-medium text-gray-500">Payment Form Detected</dt>
              <dd className="text-sm">
                <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                  detection.has_payment_form 
                    ? 'bg-danger-100 text-danger-800' 
                    : 'bg-gray-100 text-gray-800'
                }`}>
                  {detection.has_payment_form ? 'Yes' : 'No'}
                </span>
              </dd>
            </div>
          </dl>
        </div>

        {/* External Verification */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">
            External Verification
          </h2>
          <dl className="space-y-3">
            <div className="flex justify-between">
              <dt className="text-sm font-medium text-gray-500">PhishTank</dt>
              <dd className={`text-sm font-medium ${
                detection.in_phishtank ? 'text-danger-600' : 'text-gray-400'
              }`}>
                {detection.in_phishtank ? 'Listed' : 'Not Listed'}
              </dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-sm font-medium text-gray-500">OpenPhish</dt>
              <dd className={`text-sm font-medium ${
                detection.in_openphish ? 'text-danger-600' : 'text-gray-400'
              }`}>
                {detection.in_openphish ? 'Listed' : 'Not Listed'}
              </dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-sm font-medium text-gray-500">URLhaus</dt>
              <dd className={`text-sm font-medium ${
                detection.in_urlhaus ? 'text-danger-600' : 'text-gray-400'
              }`}>
                {detection.in_urlhaus ? 'Listed' : 'Not Listed'}
              </dd>
            </div>
          </dl>
        </div>
      </div>

      {/* Screenshot */}
      {detection.screenshot_path && (
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">
            Screenshot
          </h2>
          <img
            src={getScreenshot(detection.id)}
            alt="Phishing site screenshot"
            className="w-full border border-gray-200 rounded-lg"
            onError={(e) => {
              e.target.style.display = 'none'
              e.target.nextSibling.style.display = 'flex'
            }}
          />
          <div 
            className="hidden w-full h-64 border border-gray-200 rounded-lg bg-gray-100 items-center justify-center flex-col"
            style={{ display: 'none' }}
          >
            <div className="text-center">
              <div className="text-xl font-bold text-gray-500 mb-2">Screenshot Unavailable</div>
              <div className="text-sm text-gray-600">Domain: {detection.phishing_domain}</div>
              <div className="text-sm text-gray-600">Time: {new Date(detection.detected_at).toLocaleString()}</div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default DetectionDetails

