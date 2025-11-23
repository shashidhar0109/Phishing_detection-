import React from 'react'

function RiskBadge({ level, score }) {
  const getColor = () => {
    switch (level) {
      case 'HIGH':
        return 'bg-danger-100 text-danger-800 border-danger-200'
      case 'MEDIUM':
        return 'bg-warning-100 text-warning-800 border-warning-200'
      case 'LOW':
        return 'bg-success-100 text-success-800 border-success-200'
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200'
    }
  }

  return (
    <div className="flex flex-col" role="img" aria-label={`Risk level: ${level || 'UNKNOWN'}, Score: ${score !== undefined ? Math.round(score) : 'N/A'} out of 100`}>
      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getColor()}`}>
        {level || 'UNKNOWN'}
      </span>
      {score !== undefined && (
        <span className="text-xs text-gray-500 mt-1">
          {Math.round(score)}/100
        </span>
      )}
    </div>
  )
}

export default RiskBadge

