import React from 'react'
import { Shield, AlertTriangle, TrendingUp, Activity } from 'lucide-react'

function StatsCards({ stats }) {
  if (!stats) return null

  const cards = [
    {
      title: 'Total CSE Domains',
      value: stats.total_cse_domains,
      icon: Shield,
      color: 'text-primary-600',
      bgColor: 'bg-primary-100',
      subtitle: `${stats.detections_today} `
    },
    {
      title: 'Phishing Detected',
      value: stats.total_phishing_detected,
      icon: AlertTriangle,
      color: 'text-red-600',
      bgColor: 'bg-red-100',
      subtitle: `${stats.detections_today} today`
    },
    {
      title: 'High Risk',
      value: stats.high_risk_count,
      icon: TrendingUp,
      color: 'text-orange-600',
      bgColor: 'bg-orange-100',
      subtitle: `${stats.detections_today} `
    },
    {
      title: 'Monitoring Status',
      value: stats.active_monitoring ? 'Active' : 'Inactive',
      icon: Activity,
      color: stats.active_monitoring ? 'text-green-600' : 'text-gray-500',
      bgColor: stats.active_monitoring ? 'bg-green-100' : 'bg-gray-100',
      subtitle: `${stats.detections_this_week} this week`
    }
  ]

  return (
    <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
      {cards.map((card, index) => (
        <div
          key={index}
          className="bg-white shadow rounded-xl border border-gray-100 transition-all hover:shadow-md"
        >
          <div className="flex items-center gap-4 p-6">
            {/* Icon container */}
            <div
              className={`flex items-center justify-center h-12 w-12 rounded-lg ${card.bgColor}`}
            >
              <card.icon className={`h-6 w-6 ${card.color}`} />
            </div>

            {/* Text container */}
            <div className="flex flex-col justify-center">
              <dt className="text-sm font-medium text-gray-500">
                {card.title}
              </dt>
              <dd className="text-2xl font-semibold text-gray-900">
                {card.value}
              </dd>
              {card.subtitle && (
                <span className="text-xs text-gray-500 mt-0.5">
                  {card.subtitle}
                </span>
              )}
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}

export default StatsCards