import React, { lazy, Suspense } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { ToastProvider } from './components/ui/Toast';
import { AuthProvider } from './context/AuthContext';
import { ProtectedRoute } from './components/auth/ProtectedRoute';
import { AppLayout } from './components/layout/AppLayout';
import { PageSkeleton } from './components/ui/Loader';

// Lazy-loaded route components for performance optimization & code splitting
const LoginPage = lazy(() => import('./pages/LoginPage').then(m => ({ default: m.LoginPage })));
const RegisterPage = lazy(() => import('./pages/RegisterPage').then(m => ({ default: m.RegisterPage })));
const DashboardPage = lazy(() => import('./pages/DashboardPage').then(m => ({ default: m.DashboardPage })));
const ScannerPage = lazy(() => import('./pages/ScannerPage').then(m => ({ default: m.ScannerPage })));
const ReportPage = lazy(() => import('./pages/ReportPage').then(m => ({ default: m.ReportPage })));
const ScanHistoryPage = lazy(() => import('./pages/ScanHistoryPage').then(m => ({ default: m.ScanHistoryPage })));
const ScanComparisonPage = lazy(() => import('./pages/ScanComparisonPage').then(m => ({ default: m.ScanComparisonPage })));
const ProfilePage = lazy(() => import('./pages/ProfilePage').then(m => ({ default: m.ProfilePage })));

const NotFoundPage = lazy(() => import('./pages/NotFoundPage').then(m => ({ default: m.NotFoundPage })));

export function App() {
  return (
    <AuthProvider>
      <ToastProvider>
        <BrowserRouter>
          <Suspense fallback={<PageSkeleton />}>
            <Routes>
              {/* Public Authentication Pages */}
              <Route path="/login" element={<LoginPage />} />
              <Route path="/register" element={<RegisterPage />} />

              {/* Protected SecOps Dashboard Routes */}
              <Route
                path="/"
                element={
                  <ProtectedRoute>
                    <AppLayout />
                  </ProtectedRoute>
                }
              >
                <Route index element={<DashboardPage />} />
                <Route path="scanner" element={<ScannerPage />} />
                <Route path="reports/:id" element={<ReportPage />} />
                <Route path="history" element={<ScanHistoryPage />} />
                <Route path="compare" element={<ScanComparisonPage />} />
                <Route path="profile" element={<ProfilePage />} />

              </Route>

              {/* 404 Fallback */}
              <Route path="*" element={<NotFoundPage />} />
            </Routes>
          </Suspense>
        </BrowserRouter>
      </ToastProvider>
    </AuthProvider>
  );
}

export default App;
