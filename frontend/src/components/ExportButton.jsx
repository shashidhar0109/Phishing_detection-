import React, { useState } from 'react'
import { Download, FileText, FileSpreadsheet, Package } from 'lucide-react'

function ExportButton({ data, filename = 'phishing-detections' }) {
  const [isOpen, setIsOpen] = useState(false)

  const exportToCSV = () => {
    if (!data || data.length === 0) {
      window.showToast?.('No data to export', 'error')
      return
    }

    const headers = [
      'Phishing Domain',
      'Legitimate Domain',
      'Risk Level',
      'Risk Score',
      'Variation Type',
      'Organization',
      'Country',
      'Detected At'
    ]

    const csvContent = [
      headers.join(','),
      ...data.map(d => [
        d.phishing_domain,
        d.legitimate_domain || '',
        d.risk_level,
        d.risk_score,
        d.variation_type || '',
        d.organization_name || '',
        d.country || '',
        d.detected_at
      ].map(field => `"${field}"`).join(','))
    ].join('\n')

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
    const link = document.createElement('a')
    const url = URL.createObjectURL(blob)
    
    link.setAttribute('href', url)
    link.setAttribute('download', `${filename}.csv`)
    link.style.visibility = 'hidden'
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)

    window.showToast?.('Data exported successfully', 'success')
    setIsOpen(false)
  }

  const exportToJSON = () => {
    if (!data || data.length === 0) {
      window.showToast?.('No data to export', 'error')
      return
    }

    const jsonContent = JSON.stringify(data, null, 2)
    const blob = new Blob([jsonContent], { type: 'application/json' })
    const link = document.createElement('a')
    const url = URL.createObjectURL(blob)
    
    link.setAttribute('href', url)
    link.setAttribute('download', `${filename}.json`)
    link.style.visibility = 'hidden'
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)

    window.showToast?.('Data exported successfully', 'success')
    setIsOpen(false)
  }

  const exportPS02Submission = async () => {
    if (!data || data.length === 0) {
      window.showToast?.('No data to export', 'error')
      return
    }

    window.showToast?.('Generating PS-02 submission package...', 'info')
    setIsOpen(false)

    try {
      // Call backend API to generate PS-02 submission package
      const API_URL = import.meta.env.VITE_API_URL || ''
      const response = await fetch(`${API_URL}/api/export/ps02-submission`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          application_id: 'AIGR-108366',
          participant_id: 'AIGR-S82274'
        })
      })

      if (!response.ok) {
        const errorText = await response.text()
        throw new Error(`Server error: ${response.status} - ${errorText}`)
      }

      // Download the ZIP file
      const blob = await response.blob()
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = 'PS-02_AIGR-108366_Submission.zip'
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      URL.revokeObjectURL(url)

      window.showToast?.('PS-02 submission package generated successfully!', 'success')
    } catch (error) {
      console.error('Export error:', error)
      window.showToast?.(`Failed to generate submission package: ${error.message}`, 'error')
    }
  }

  return (
    <div className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="inline-flex items-center px-4 py-2 border border-transparent rounded-lg text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 dark:bg-primary-500 dark:hover:bg-primary-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 transition-colors"
      >
        <Download className="h-4 w-4 mr-2" />
        Export Data
      </button>

      {isOpen && (
        <>
          <div 
            className="fixed inset-0 z-10" 
            onClick={() => setIsOpen(false)}
          />
          <div className="absolute right-0 mt-2 w-64 rounded-lg shadow-lg bg-white dark:bg-gray-800 ring-1 ring-black ring-opacity-5 z-20">
            <div className="py-1">
              <button
                onClick={exportToCSV}
                className="flex items-center w-full px-4 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700"
              >
                <FileSpreadsheet className="h-4 w-4 mr-3 text-green-600" />
                Export as CSV
              </button>
              <button
                onClick={exportToJSON}
                className="flex items-center w-full px-4 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700"
              >
                <FileText className="h-4 w-4 mr-3 text-blue-600" />
                Export as JSON
              </button>
              <div className="border-t border-gray-200 dark:border-gray-700 my-1"></div>
              <button
                onClick={exportPS02Submission}
                className="flex items-center w-full px-4 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700"
              >
                <Package className="h-4 w-4 mr-3 text-purple-600" />
                <div className="flex flex-col items-start">
                  <span className="font-medium">PS-02 Submission</span>
                  <span className="text-xs text-gray-500 dark:text-gray-400">AI Grand Challenge</span>
                </div>
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

export default ExportButton

