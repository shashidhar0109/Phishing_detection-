import React from 'react'
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, Legend } from 'recharts'
import { TrendingUp, Activity } from 'lucide-react'
import { format, subDays, parseISO } from 'date-fns'

function AnalyticsChart({ stats, detections }) {
  // Calculate real trend data from actual detections
  const calculateTrendData = () => {
    if (!detections || !Array.isArray(detections) || detections.length === 0) {
      return []
    }

    // Get all unique dates from detections
    const detectionDates = [...new Set(detections.map(d => format(parseISO(d.detected_at), 'yyyy-MM-dd')))].sort()
    
    if (detectionDates.length === 0) {
      return []
    }

    // Create data points for all detection dates
    const trendData = detectionDates.map(dateStr => {
      const date = parseISO(dateStr)
      const count = Array.isArray(detections) ? detections.filter(d => format(parseISO(d.detected_at), 'yyyy-MM-dd') === dateStr).length : 0
      
      return {
        date: format(date, 'MMM dd'),
        fullDate: dateStr,
        detections: count
      }
    })

    return trendData
  }

  const trendData = calculateTrendData()
  const hasData = trendData.length > 0 && trendData.some(d => d.detections > 0)

  const riskDistribution = [
    { risk: 'High', count: stats?.high_risk_count || 0, fill: '#ef4444' },
    { risk: 'Medium', count: stats?.medium_risk_count || 0, fill: '#f59e0b' },
    { risk: 'Low', count: stats?.low_risk_count || 0, fill: '#22c55e' },
  ]

  const hasRiskData = riskDistribution.some(r => r.count > 0)

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
      {/* Trend Chart */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6 animate-fade-in">
        <div className="flex items-center mb-4">
          <TrendingUp className="h-5 w-5 text-primary-600 dark:text-primary-400 mr-2" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Detection Trend (All Time)</h3>
        </div>
        {hasData ? (
          <ResponsiveContainer width="100%" height={250}>
            <AreaChart data={trendData}>
              <defs>
                <linearGradient id="colorDetections" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#0ea5e9" stopOpacity={0.8}/>
                  <stop offset="95%" stopColor="#0ea5e9" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
              <XAxis dataKey="date" stroke="#6b7280" />
              <YAxis stroke="#6b7280" allowDecimals={false} />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: '#fff', 
                  border: '1px solid #e5e7eb',
                  borderRadius: '0.5rem',
                  boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)'
                }}
              />
              <Area 
                type="monotone" 
                dataKey="detections" 
                stroke="#0ea5e9" 
                fillOpacity={1} 
                fill="url(#colorDetections)" 
              />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="flex items-center justify-center h-[250px] text-gray-500 dark:text-gray-400">
            <div className="text-center">
              <TrendingUp className="h-12 w-12 mx-auto mb-2 opacity-30" />
              <p>No detection data available yet</p>
              <p className="text-sm mt-1">Start monitoring CSE domains to see trends</p>
            </div>
          </div>
        )}
      </div>

      {/* Risk Distribution */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6 animate-fade-in">
        <div className="flex items-center mb-4">
          <Activity className="h-5 w-5 text-primary-600 dark:text-primary-400 mr-2" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Risk Distribution</h3>
        </div>
        {hasRiskData ? (
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={riskDistribution}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
              <XAxis dataKey="risk" stroke="#6b7280" />
              <YAxis stroke="#6b7280" allowDecimals={false} />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: '#fff', 
                  border: '1px solid #e5e7eb',
                  borderRadius: '0.5rem',
                  boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)'
                }}
              />
              <Legend />
              <Bar dataKey="count" fill="#0ea5e9" radius={[8, 8, 0, 0]}>
                {riskDistribution.map((entry, index) => (
                  <Bar key={`cell-${index}`} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <div className="flex items-center justify-center h-[250px] text-gray-500 dark:text-gray-400">
            <div className="text-center">
              <Activity className="h-12 w-12 mx-auto mb-2 opacity-30" />
              <p>No risk data available yet</p>
              <p className="text-sm mt-1">Detections will appear here by risk level</p>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default AnalyticsChart

