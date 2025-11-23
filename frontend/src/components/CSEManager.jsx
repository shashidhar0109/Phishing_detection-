import React, { useState, useEffect } from 'react'
import { fetchCSEDomains, addCSEDomain, deleteCSEDomain, bulkAddCSEDomains } from '../api'
import { Plus, Trash2, Building2, Globe, Upload, FileSpreadsheet, RefreshCw } from 'lucide-react'

// Function to categorize domains based on common patterns
const categorizeDomain = (domain) => {
  const domainLower = domain.toLowerCase()
  
  // Banking and Financial Services
  if (domainLower.includes('bank') || domainLower.includes('sbi') || domainLower.includes('hdfc') || 
      domainLower.includes('icici') || domainLower.includes('pnb') || domainLower.includes('bob') ||
      domainLower.includes('axis') || domainLower.includes('kotak') || domainLower.includes('yes') ||
      domainLower.includes('union') || domainLower.includes('canara') || domainLower.includes('indian') ||
      domainLower.includes('paytm') || domainLower.includes('phonepe') || domainLower.includes('gpay') ||
      domainLower.includes('paypal') || domainLower.includes('razorpay') || domainLower.includes('cashfree')) {
    return { sector: 'BFSI', organization: 'Banking/Financial Services' }
  }
  
  // Government
  if (domainLower.includes('.gov') || domainLower.includes('nic') || domainLower.includes('india') ||
      domainLower.includes('ministry') || domainLower.includes('department') || domainLower.includes('portal')) {
    return { sector: 'Government', organization: 'Government of India' }
  }
  
  // E-commerce
  if (domainLower.includes('shop') || domainLower.includes('store') || domainLower.includes('market') ||
      domainLower.includes('amazon') || domainLower.includes('flipkart') || domainLower.includes('myntra') ||
      domainLower.includes('snapdeal') || domainLower.includes('nykaa') || domainLower.includes('zomato') ||
      domainLower.includes('swiggy') || domainLower.includes('uber') || domainLower.includes('ola')) {
    return { sector: 'E-commerce', organization: 'E-commerce Platform' }
  }
  
  // Telecom
  if (domainLower.includes('airtel') || domainLower.includes('jio') || domainLower.includes('vi') ||
      domainLower.includes('bsnl') || domainLower.includes('vodafone') || domainLower.includes('idea')) {
    return { sector: 'Telecom', organization: 'Telecom Service Provider' }
  }
  
  // Healthcare
  if (domainLower.includes('health') || domainLower.includes('medical') || domainLower.includes('hospital') ||
      domainLower.includes('pharma') || domainLower.includes('medicine') || domainLower.includes('doctor')) {
    return { sector: 'Healthcare', organization: 'Healthcare Provider' }
  }
  
  // Education
  if (domainLower.includes('edu') || domainLower.includes('university') || domainLower.includes('college') ||
      domainLower.includes('school') || domainLower.includes('institute') || domainLower.includes('academy')) {
    return { sector: 'Education', organization: 'Educational Institution' }
  }
  
  // Technology
  if (domainLower.includes('tech') || domainLower.includes('software') || domainLower.includes('it') ||
      domainLower.includes('digital') || domainLower.includes('app') || domainLower.includes('cloud')) {
    return { sector: 'Technology', organization: 'Technology Company' }
  }
  
  // Default categorization based on TLD
  if (domainLower.endsWith('.gov.in') || domainLower.endsWith('.nic.in')) {
    return { sector: 'Government', organization: 'Government of India' }
  }
  
  if (domainLower.endsWith('.edu') || domainLower.endsWith('.ac.in')) {
    return { sector: 'Education', organization: 'Educational Institution' }
  }
  
  if (domainLower.endsWith('.org') || domainLower.endsWith('.org.in')) {
    return { sector: 'Non-Profit', organization: 'Non-Profit Organization' }
  }
  
  // Default fallback
  return { sector: 'Other', organization: 'Unknown Organization' }
}

function CSEManager() {
  const [domains, setDomains] = useState([])
  const [loading, setLoading] = useState(true)
  const [showAddForm, setShowAddForm] = useState(false)
  const [showUploadForm, setShowUploadForm] = useState(false)
  const [uploadStatus, setUploadStatus] = useState('')
  const [uploading, setUploading] = useState(false)
  const [addDomainError, setAddDomainError] = useState('')
  const [addDomainSuccess, setAddDomainSuccess] = useState('')
  const [currentPage, setCurrentPage] = useState(0)
  const [totalDomains, setTotalDomains] = useState(0)
  const [hasMorePages, setHasMorePages] = useState(false)
  const [formData, setFormData] = useState({
    sector: '',
    organization_name: '',
    domain: ''
  })

  useEffect(() => {
    loadDomains()
  }, [])
  
  // Add a manual refresh function instead of automatic refresh
  const refreshDomains = () => {
    loadDomains(currentPage)
  }

  // Function to update sectors for existing domains
  const updateSectors = async () => {
    try {
      setLoading(true)
      const response = await fetch(`${import.meta.env.VITE_API_URL || ''}/api/cse-domains/update-sectors`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      })
      
      if (response.ok) {
        const result = await response.json()
        setAddDomainSuccess(`✅ ${result.message}`)
        // Refresh the domains list
        loadDomains(currentPage)
      } else {
        setAddDomainError('❌ Failed to update sectors')
      }
    } catch (error) {
      console.error('Failed to update sectors:', error)
      setAddDomainError('❌ Failed to update sectors')
    }
    setLoading(false)
  }

  const loadDomains = async (page = 0) => {
    try {
      setLoading(true)
      const response = await fetchCSEDomains({ skip: page * 50, limit: 50 })
      // Ensure domains is always an array, even if response.data is null/undefined
      const domainsData = Array.isArray(response?.data) ? response.data : []
      setDomains(domainsData)
      setCurrentPage(page)
      // Check if there are more pages (if we got exactly 50 domains, there might be more)
      setHasMorePages(domainsData.length === 50)
      setLoading(false)
    } catch (error) {
      console.error('Failed to load domains:', error)
      // Set domains to empty array on error to prevent .map errors
      setDomains([])
      setLoading(false)
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setAddDomainError('')
    setAddDomainSuccess('')
    
    try {
      await addCSEDomain(formData)
      setAddDomainSuccess(`✅ Successfully added ${formData.domain} for monitoring!`)
      setFormData({ sector: '', organization_name: '', domain: '' })
      
      // Auto-close after 2 seconds on success
      setTimeout(() => {
        setShowAddForm(false)
        setAddDomainSuccess('')
      }, 2000)
      
      loadDomains()
    } catch (error) {
      console.error('Failed to add domain:', error)
      const errorMessage = error.response?.data?.detail || error.message
      
      // Format the error message nicely
      if (errorMessage.includes('TYPOSQUATTING') || errorMessage.includes('typosquatting')) {
        // Typosquatting error - show as-is (already well formatted)
        setAddDomainError(errorMessage)
      } else if (errorMessage.includes('PHISHING') || errorMessage.includes('malicious')) {
        // Phishing/malicious domain error - show as-is
        setAddDomainError(errorMessage)
      } else if (errorMessage.includes('already exists') || errorMessage.includes('already being monitored')) {
        setAddDomainError(`ℹ️ This domain is already being monitored.`)
      } else {
        setAddDomainError(`❌ ${errorMessage}`)
      }
    }
  }

  const handleDelete = async (id) => {
    if (window.confirm('Are you sure you want to remove this domain from monitoring?')) {
      try {
        await deleteCSEDomain(id)
        loadDomains()
      } catch (error) {
        console.error('Failed to delete domain:', error)
      }
    }
  }

  const handleFileUpload = async (event) => {
    const file = event.target.files[0]
    if (!file) return

    setUploading(true)
    setUploadStatus('Processing CSV file...')

    try {
      const text = await file.text()
      const lines = text.split('\n')
      const domainsToAdd = []

      let currentSector = ''
      let currentOrg = ''

      // Check if this is a simple domain list (single column) or multi-column CSV
      const firstDataLine = lines[1] || ''
      const isSimpleDomainList = !firstDataLine.includes(',')

      if (isSimpleDomainList) {
        // Simple domain list format - just domains
        for (let i = 1; i < lines.length; i++) {
          const line = lines[i].trim()
          if (!line) continue

          // Skip if it's a header
          if (line.toLowerCase().includes('domain') || line.toLowerCase().includes('user')) continue

          // Categorize domains based on common patterns
          const { sector, organization } = categorizeDomain(line)
          
          domainsToAdd.push({
            sector: sector,
            organization_name: organization,
            domain: line
          })
        }
      } else {
        // Multi-column CSV format
        for (let i = 1; i < lines.length; i++) {
          const line = lines[i].trim()
          if (!line) continue

          // Parse CSV (handle quotes)
          const columns = line.match(/(".*?"|[^",\s]+)(?=\s*,|\s*$)/g) || []
          const cleanColumns = columns.map(col => col.replace(/^"|"$/g, '').trim())

          // Format: domain, organization, sector
          const domain = cleanColumns[0] || ''
          const orgName = cleanColumns[1] || ''
          const sector = cleanColumns[2] || ''

          // Update current sector/org if provided
          if (sector) currentSector = sector
          if (orgName) currentOrg = orgName

          // Skip if no domain or if it's a header
          if (!domain || domain.toLowerCase().includes('domain')) continue

          domainsToAdd.push({
            sector: sector || currentSector || 'Unknown',
            organization_name: orgName || currentOrg || 'Unknown',
            domain: domain
          })
        }
      }

      setUploadStatus(`Uploading ${domainsToAdd.length} domains... This may take a few minutes for large files.`)

      // Send to backend with progress tracking
      const response = await bulkAddCSEDomains(domainsToAdd)
      
      // Build detailed status message
      const result = response.data
      let statusMessage = `✅ ${result.message || `Successfully added ${result.length || response.data.length} domains!`}`
      
      // Add note about two-phase processing
      statusMessage += `\n\n📋 Note: Domains are stored quickly without scanning. Domain classification and malicious detection will happen when you start monitoring.`
      
      // Add details about existing domains
      if (result.skipped_existing && result.skipped_existing.length > 0) {
        statusMessage += `\n\nℹ️ Already monitoring: ${result.skipped_existing.join(', ')}`
      }
      
      setUploadStatus(statusMessage)
      
      // Auto-close only if no warnings
      if (!result.skipped_malicious || result.skipped_malicious.length === 0) {
        setTimeout(() => {
          setUploadStatus('')
          setShowUploadForm(false)
        }, 3000)
      }

      loadDomains()
    } catch (error) {
      console.error('Failed to upload CSV:', error)
      setUploadStatus(`❌ Error: ${error.response?.data?.detail || error.message}`)
    } finally {
      setUploading(false)
      // Reset file input
      event.target.value = ''
    }
  }

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">CSE Domain Manager</h1>
            <p className="mt-1 text-sm text-gray-500">
              Manage Critical Sector Entity domains for phishing monitoring
            </p>
          </div>
          <div className="flex gap-3">
            <button
              onClick={() => {
                setShowUploadForm(!showUploadForm)
                setShowAddForm(false)
              }}
              className="inline-flex items-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
            >
              <Upload className="h-5 w-5 mr-2" />
              Upload CSV
            </button>
            <button
              onClick={() => {
                setShowAddForm(!showAddForm)
                setShowUploadForm(false)
              }}
              className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
            >
              <Plus className="h-5 w-5 mr-2" />
              Add Domain
            </button>
          </div>
        </div>

        {/* Add Form */}
        {showAddForm && (
          <form onSubmit={handleSubmit} className="mt-6 border-t pt-6">
            {/* Info Banner */}
            <div className="mb-4 p-4 bg-blue-50 border border-blue-200 rounded-md">
              <div className="flex">
                <div className="flex-shrink-0">
                  <svg className="h-5 w-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                  </svg>
                </div>
                <div className="ml-3">
                  <h3 className="text-sm font-medium text-blue-800">
                    ⚡ Security Validation Active
                  </h3>
                  <div className="mt-2 text-sm text-blue-700">
                    <p>The system will validate that the domain is:</p>
                    <ul className="list-disc list-inside mt-1 ml-2">
                      <li>NOT listed in malicious domain databases</li>
                      <li>NOT using suspicious patterns or characteristics</li>
                      <li>A legitimate, registered domain</li>
                    </ul>
                    <p className="mt-2 font-medium">Only verified legitimate domains can be added for monitoring.</p>
                  </div>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Sector
                </label>
                <input
                  type="text"
                  value={formData.sector}
                  onChange={(e) => setFormData({ ...formData, sector: e.target.value })}
                  className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Organization Name
                </label>
                <input
                  type="text"
                  value={formData.organization_name}
                  onChange={(e) => setFormData({ ...formData, organization_name: e.target.value })}
                  className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Domain (without http://)
                </label>
                <input
                  type="text"
                  value={formData.domain}
                  onChange={(e) => setFormData({ ...formData, domain: e.target.value })}
                  placeholder="example.com"
                  className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                  required
                />
              </div>
            </div>

            {/* Error Message */}
            {addDomainError && (
              <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-md">
                <div className="flex">
                  <div className="flex-shrink-0">
                    <svg className="h-5 w-5 text-red-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                      <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                    </svg>
                  </div>
                  <div className="ml-3">
                    <pre className="text-sm font-medium text-red-800 whitespace-pre-wrap font-sans">{addDomainError}</pre>
                  </div>
                </div>
              </div>
            )}

            {/* Success Message */}
            {addDomainSuccess && (
              <div className="mt-4 p-4 bg-green-50 border border-green-200 rounded-md">
                <div className="flex">
                  <div className="flex-shrink-0">
                    <svg className="h-5 w-5 text-green-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                      <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                    </svg>
                  </div>
                  <div className="ml-3">
                    <p className="text-sm font-medium text-green-800">{addDomainSuccess}</p>
                  </div>
                </div>
              </div>
            )}

            <div className="mt-4 flex justify-end gap-3">
              <button
                type="button"
                onClick={() => {
                  setShowAddForm(false)
                  setAddDomainError('')
                  setAddDomainSuccess('')
                }}
                className="px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700"
              >
                Add Domain
              </button>
            </div>
          </form>
        )}

        {/* CSV Upload Form */}
        {showUploadForm && (
          <div className="mt-6 border-t pt-6">
            <div className="bg-gray-50 rounded-lg p-6 border-2 border-dashed border-gray-300">
              <div className="text-center">
                <FileSpreadsheet className="mx-auto h-12 w-12 text-gray-400" />
                <h3 className="mt-2 text-sm font-medium text-gray-900">Upload CSV File</h3>
                <p className="mt-1 text-sm text-gray-500">
                  CSV format: Domain, Organization, Sector
                </p>
                
                <div className="mt-4">
                  <label className="cursor-pointer">
                    <input
                      type="file"
                      accept=".csv"
                      onChange={handleFileUpload}
                      disabled={uploading}
                      className="hidden"
                    />
                    <span className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:bg-gray-400">
                      {uploading ? (
                        <>
                          <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                          </svg>
                          Processing...
                        </>
                      ) : (
                        <>
                          <Upload className="h-4 w-4 mr-2" />
                          Choose CSV File
                        </>
                      )}
                    </span>
                  </label>
                </div>

                {uploadStatus && (
                  <div className={`mt-4 p-4 rounded-md ${
                    uploadStatus.startsWith('✅') 
                      ? 'bg-success-50 border border-success-200 text-success-800'
                      : uploadStatus.startsWith('❌')
                      ? 'bg-danger-50 border border-danger-200 text-danger-800'
                      : 'bg-primary-50 border border-primary-200 text-primary-800'
                  }`}>
                    <pre className="text-sm font-medium whitespace-pre-wrap font-sans">{uploadStatus}</pre>
                  </div>
                )}

                <div className="mt-4 text-xs text-gray-500 text-left">
                  <p className="font-medium mb-2">Supported CSV Formats:</p>
                  
                  <div className="mb-3">
                    <p className="font-medium text-gray-700">Format 1: Simple Domain List</p>
                    <pre className="bg-white p-2 rounded border border-gray-200 overflow-x-auto">
Domain User Form
div29.gent
krausey.com
satmathstats.com
dyczzs.com</pre>
                  </div>
                  
                  <div className="mb-3">
                    <p className="font-medium text-gray-700">Format 2: Multi-column CSV</p>
                    <pre className="bg-white p-2 rounded border border-gray-200 overflow-x-auto">
Domain,Organization,Sector
sbi.co.in,State Bank of India,BFSI
onlinesbi.sbi,,
sbicard.com,,
icicibank.com,ICICI Bank,BFSI</pre>
                  </div>
                  
                  <p className="mt-2 text-gray-600">
                    • System automatically detects the format<br/>
                    • First row is treated as header and skipped<br/>
                    • For simple lists, Organization and Sector will be set to "Unknown"
                  </p>
                </div>
              </div>
            </div>
            
            <div className="mt-4 flex justify-end">
              <button
                type="button"
                onClick={() => {
                  setShowUploadForm(false)
                  setUploadStatus('')
                }}
                className="px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
              >
                Close
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Domains List */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200">
          <div className="flex justify-between items-center">
            <h2 className="text-lg font-semibold text-gray-900">
              Monitored Domains (Page {currentPage + 1})
            </h2>
            <div className="flex gap-2">
              <button
                onClick={refreshDomains}
                className="px-3 py-1 text-sm bg-blue-100 hover:bg-blue-200 text-blue-700 rounded flex items-center gap-1"
              >
                <RefreshCw className="w-4 h-4" />
                Refresh
              </button>
              <button
                onClick={updateSectors}
                className="px-3 py-1 text-sm bg-green-100 hover:bg-green-200 text-green-700 rounded flex items-center gap-1"
              >
                <Building2 className="w-4 h-4" />
                Fix Sectors
              </button>
              <button
                onClick={() => loadDomains(currentPage - 1)}
                disabled={currentPage === 0}
                className="px-3 py-1 text-sm bg-gray-100 hover:bg-gray-200 disabled:opacity-50 disabled:cursor-not-allowed rounded"
              >
                Previous
              </button>
              <button
                onClick={() => loadDomains(currentPage + 1)}
                disabled={!hasMorePages}
                className="px-3 py-1 text-sm bg-gray-100 hover:bg-gray-200 disabled:opacity-50 disabled:cursor-not-allowed rounded"
              >
                Next
              </button>
            </div>
          </div>
        </div>
        
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Domain
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Organization
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Sector
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Added
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {Array.isArray(domains) && domains.length > 0 ? domains.map((domain) => (
                <tr key={domain.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4">
                    <div className="flex items-center">
                      <Globe className="h-5 w-5 text-primary-500 mr-2" />
                      <span className="text-sm font-medium text-gray-900">
                        {domain.domain}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center">
                      <Building2 className="h-4 w-4 text-gray-400 mr-2" />
                      <span className="text-sm text-gray-900">
                        {domain.organization_name}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-primary-100 text-primary-800">
                      {domain.sector}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {new Date(domain.added_at).toLocaleDateString()}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <button
                      onClick={() => handleDelete(domain.id)}
                      className="text-danger-600 hover:text-danger-900"
                    >
                      <Trash2 className="h-5 w-5" />
                    </button>
                  </td>
                </tr>
              )) : (
                <tr>
                  <td colSpan="5" className="px-6 py-4 text-center text-gray-500">
                    No domains found. Add a domain to get started.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

export default CSEManager

