import React, { useState, useEffect } from 'react'
import { CheckCircle, AlertCircle, Info, X } from 'lucide-react'

function Toast({ message, type = 'info', duration = 5000, onClose }) {
  const [isVisible, setIsVisible] = useState(true)

  useEffect(() => {
    const timer = setTimeout(() => {
      setIsVisible(false)
      setTimeout(onClose, 300) // Wait for fade out animation
    }, duration)

    return () => clearTimeout(timer)
  }, [duration, onClose])

  const icons = {
    success: <CheckCircle className="h-5 w-5 text-success-500" />,
    error: <AlertCircle className="h-5 w-5 text-danger-500" />,
    info: <Info className="h-5 w-5 text-primary-500" />,
  }

  const colors = {
    success: 'bg-success-50 border-success-200 dark:bg-success-900/20 dark:border-success-800',
    error: 'bg-danger-50 border-danger-200 dark:bg-danger-900/20 dark:border-danger-800',
    info: 'bg-primary-50 border-primary-200 dark:bg-primary-900/20 dark:border-primary-800',
  }

  return (
    <div
      className={`fixed top-20 right-4 z-50 max-w-md transition-all duration-300 ${
        isVisible ? 'opacity-100 translate-x-0' : 'opacity-0 translate-x-full'
      }`}
    >
      <div className={`flex items-center p-4 border rounded-lg shadow-lg ${colors[type]}`}>
        <div className="flex-shrink-0">{icons[type]}</div>
        <div className="ml-3 flex-1">
          <p className="text-sm font-medium text-gray-900 dark:text-white">{message}</p>
        </div>
        <button
          onClick={() => {
            setIsVisible(false)
            setTimeout(onClose, 300)
          }}
          className="ml-4 flex-shrink-0 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
        >
          <X className="h-5 w-5" />
        </button>
      </div>
    </div>
  )
}

export function ToastContainer() {
  const [toasts, setToasts] = useState([])

  const addToast = (message, type = 'info') => {
    const id = Date.now()
    setToasts(prev => [...prev, { id, message, type }])
  }

  const removeToast = (id) => {
    setToasts(prev => prev.filter(toast => toast.id !== id))
  }

  // Expose addToast globally
  useEffect(() => {
    window.showToast = addToast
  }, [])

  return (
    <>
      {toasts.map((toast, index) => (
        <div key={toast.id} style={{ top: `${80 + index * 80}px` }} className="fixed right-4 z-50">
          <Toast
            message={toast.message}
            type={toast.type}
            onClose={() => removeToast(toast.id)}
          />
        </div>
      ))}
    </>
  )
}

export default Toast

