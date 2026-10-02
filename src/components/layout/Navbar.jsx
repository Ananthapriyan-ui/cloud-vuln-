import React, { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { Search, Bell, ShieldCheck, Activity, User, ChevronDown } from 'lucide-react';
import { Input } from '../ui/Input';
import { Badge } from '../ui/Badge';
import { useAuth } from '../../context/AuthContext';
import { useToast } from '../ui/Toast';

export const Navbar = ({ collapsed }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const { addToast } = useToast();
  const [showNotifications, setShowNotifications] = useState(false);
  const [showProfileMenu, setShowProfileMenu] = useState(false);

  const pathMap = {
    '/': 'Dashboard Overview',
    '/scanner': 'Target Vulnerability Scanner',
    '/history': 'Scan History & Audit Logs',
    '/compare': 'Scan Comparison & Security Trend',
    '/profile': 'User Profile',
  };

  const currentTitle = location.pathname.startsWith('/reports')
    ? 'Detailed Scan Assessment Report'
    : (pathMap[location.pathname] || 'Cloud Vulnerability Scanner');

  const getInitials = (name) => {
    if (!name) return 'OP';
    return name
      .split(' ')
      .map((n) => n[0])
      .join('')
      .toUpperCase()
      .substring(0, 2);
  };

  return (
    <header
      className={`fixed top-0 right-0 z-30 h-16 bg-[#070a12]/90 backdrop-blur-md border-b border-slate-800/80 transition-all duration-300 flex items-center justify-between px-6 ${
        collapsed ? 'left-20' : 'left-64'
      }`}
    >
      {/* Title & Breadcrumbs */}
      <div className="flex items-center gap-4">
        <div>
          <h1 className="text-base font-bold text-slate-100 flex items-center gap-2">
            <span>{currentTitle}</span>
          </h1>
          <p className="text-[11px] font-mono text-slate-400">
          </p>
        </div>
      </div>

      {/* Global Actions */}
      <div className="flex items-center gap-4">
        {/* Global Search Bar */}
        <div className="hidden md:block w-64 lg:w-80">
          <Input
            placeholder="Search CVE, IP, Domain, or Asset..."
            icon={Search}
            className="py-1.5! text-xs bg-slate-900/80 border-slate-800 focus:border-cyan-500"
          />
        </div>

        {/* Notification Bell Dropdown */}
        <div className="relative">
          <button
            onClick={() => {
              setShowNotifications(!showNotifications);
              setShowProfileMenu(false);
            }}
            className="relative p-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-300 hover:text-cyan-400 hover:border-cyan-500/40 transition-all"
          >
            <Bell className="w-4 h-4" />
          </button>

          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 bg-[#0d1424] border border-cyan-500/30 rounded-xl shadow-[0_10px_30px_rgba(0,0,0,0.6)] backdrop-blur-xl z-50 overflow-hidden animate-fade-in-up">
              <div className="p-3 bg-slate-900/90 border-b border-slate-800 flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-200">Alerts & Notifications</span>
                <Badge variant="ghost" size="sm">0 New</Badge>
              </div>
              <div className="p-6 text-center text-xs text-slate-400">
                <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
                <p className="font-medium text-slate-300">All systems operational</p>
                <p className="text-[11px] text-slate-500 mt-1">No unread security alerts at this time.</p>
              </div>
              <div className="p-2 bg-slate-950/80 border-t border-slate-800 text-center">
                <button
                  onClick={() => {
                    setShowNotifications(false);
                    navigate('/history');
                  }}
                  className="text-[11px] text-cyan-400 hover:underline font-medium"
                >
                  View Scan Audit History
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Profile Menu Dropdown */}
        <div className="relative">
          <button
            onClick={() => {
              setShowProfileMenu(!showProfileMenu);
              setShowNotifications(false);
            }}
            className="flex items-center gap-2 p-1.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-cyan-500/40 transition-all text-xs"
          >
            <div className="w-7 h-7 rounded-lg bg-cyan-500/10 border border-cyan-400/40 flex items-center justify-center text-cyan-400 font-bold overflow-hidden">
              {user?.avatar_url ? (
                <img src={user.avatar_url} alt={user?.full_name || 'User'} className="w-full h-full object-cover" />
              ) : (
                getInitials(user?.full_name)
              )}
            </div>
            <span className="hidden lg:inline text-slate-200 font-medium">{user?.full_name || 'User'}</span>
            <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
          </button>

          {showProfileMenu && (
            <div className="absolute right-0 mt-2 w-52 bg-[#0d1424] border border-cyan-500/30 rounded-xl shadow-[0_10px_30px_rgba(0,0,0,0.6)] backdrop-blur-xl z-50 p-1.5 animate-fade-in-up">
              <button
                onClick={() => {
                  setShowProfileMenu(false);
                  navigate('/profile');
                }}
                className="w-full text-left px-3 py-2 text-xs font-medium text-slate-300 hover:text-cyan-400 hover:bg-slate-800/60 rounded-lg transition-colors flex items-center gap-2"
              >
                <User className="w-4 h-4" />
                <span>My Profile</span>
              </button>

              <div className="my-1 border-t border-slate-800" />
              <button
                onClick={() => {
                  setShowProfileMenu(false);
                  logout();
                  addToast('Logged out', 'info');
                  navigate('/login');
                }}
                className="w-full text-left px-3 py-2 text-xs font-medium text-rose-400 hover:bg-rose-500/10 rounded-lg transition-colors flex items-center gap-2"
              >
                <span>Sign Out</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
