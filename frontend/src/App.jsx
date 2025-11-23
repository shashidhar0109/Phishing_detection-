import React, { useState, Suspense, lazy } from 'react'
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom'
import ThemeToggle from './components/ThemeToggle'
import ErrorBoundary from './components/ErrorBoundary'
import { ToastContainer } from './components/Toast'
import { Shield, Database, Activity } from 'lucide-react'

// Lazy load components for better performance
const Dashboard = lazy(() => import('./components/Dashboard'))
const CSEManager = lazy(() => import('./components/CSEManager'))
const DetectionDetails = lazy(() => import('./components/DetectionDetails'))

function Navigation() {
  const location = useLocation()
  
  const isActive = (path) => {
    if (path === '/') {
      return location.pathname === '/'
    }
    return location.pathname.startsWith(path)
  }

  return (
    <nav className="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700 sticky top-0 z-40 backdrop-blur-sm bg-opacity-95 dark:bg-opacity-95">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-16">
          <div className="flex">
            <div className="flex-shrink-0 flex items-center">
              <div className="p-2 bg-gradient-to-br from-primary-500 to-primary-700 rounded-lg">
                <Shield className="h-6 w-6 text-white" />
              </div>
              <span className="ml-3 text-xl font-bold bg-gradient-to-r from-primary-600 to-primary-800 dark:from-primary-400 dark:to-primary-600 bg-clip-text text-transparent">
                Phishing Detection System
              </span>
            </div>
            <div className="hidden sm:ml-6 sm:flex sm:space-x-8">
              <Link
                to="/"
                className={`${
                  isActive('/')
                    ? 'border-primary-500 dark:border-primary-400 text-gray-900 dark:text-white'
                    : 'border-transparent text-gray-500 dark:text-gray-400 hover:border-gray-300 dark:hover:border-gray-600 hover:text-gray-700 dark:hover:text-gray-300'
                } inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium transition-colors`}
              >
                <Activity className="h-4 w-4 mr-2" />
                Dashboard
              </Link>
              <Link
                to="/cse-manager"
                className={`${
                  isActive('/cse-manager')
                    ? 'border-primary-500 dark:border-primary-400 text-gray-900 dark:text-white'
                    : 'border-transparent text-gray-500 dark:text-gray-400 hover:border-gray-300 dark:hover:border-gray-600 hover:text-gray-700 dark:hover:text-gray-300'
                } inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium transition-colors`}
              >
                <Database className="h-4 w-4 mr-2" />
                CSE Manager
              </Link>
            </div>
          </div>
          <div className="flex items-center">
            <ThemeToggle />
          </div>
        </div>
      </div>
    </nav>
  )
}

function App() {
  return (
    <ErrorBoundary>
      <Router>
        <div className="min-h-screen bg-gray-50 dark:bg-gray-900 transition-colors">
          {/* Toast Notifications */}
          <ToastContainer />
          
          {/* Navigation */}
          <Navigation />

          {/* Main Content */}
          <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
            <Suspense fallback={
              <div className="flex justify-center items-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
              </div>
            }>
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/cse-manager" element={<CSEManager />} />
                <Route path="/detection/:id" element={<DetectionDetails />} />
              </Routes>
            </Suspense>
          </main>
          
          {/* Footer */}
          <footer className="bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700 mt-12">
            <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
              <p className="text-center text-sm text-gray-500 dark:text-gray-400">
              
              </p>
            </div>
          </footer>
        </div>
      </Router>
    </ErrorBoundary>
  )
}

export default App

