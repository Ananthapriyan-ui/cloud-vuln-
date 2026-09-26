import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  Radar,
  FileText,
  History,
  GitCompare,
  User,
  LogOut,
  ChevronLeft,
  ChevronRight,
  Zap,
} from 'lucide-react';
import { Badge } from '../ui/Badge';
import { useAuth } from '../../context/AuthContext';
import { useToast } from '../ui/Toast';

export const Sidebar = ({ collapsed, setCollapsed }) => {
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const { addToast } = useToast();

  const navItems = [
    { label: 'Dashboard', path: '/', icon: LayoutDashboard },
    { label: 'Cloud Scanner', path: '/scanner', icon: Radar, badge: 'LIVE' },
    { label: 'Scan History', path: '/history', icon: History },
    { label: 'Scan Comparison', path: '/compare', icon: GitCompare, badge: 'NEW' },
    { label: 'Profile', path: '/profile', icon: User },
  ];

  const handleLogout = () => {
    logout();
    addToast('Logged out of SecOps session', 'info');
    navigate('/login');
  };

  const getInitials = (name) => {
    if (!name) return 'US';
    return name
      .split(' ')
      .map((n) => n[0])
      .join('')
      .toUpperCase()
      .substring(0, 2);
  };

  return (
    <aside
      className={`fixed top-0 left-0 z-40 h-screen bg-[#070a12] border-r border-slate-800/80 transition-all duration-300 flex flex-col ${
        collapsed ? 'w-20' : 'w-64'
      }`}
    >
      {/* Brand Header */}
      <div className="h-16 flex items-center justify-between px-4 border-b border-slate-800/80 bg-slate-950/40">
        <div className="flex items-center gap-3 overflow-hidden">
          <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shrink-0 shadow-[0_0_15px_rgba(0,243,255,0.2)]">
            <Shield className="w-6 h-6" />
          </div>
          {!collapsed && (
            <div className="flex flex-col">
              <span className="font-extrabold text-base tracking-wider text-slate-100 flex items-center gap-1.5">
                CLOUD<span className="text-cyan-400">VULN</span>
              </span>
            </div>
          )}
        </div>
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="text-slate-400 hover:text-cyan-400 p-1.5 rounded-lg hover:bg-slate-800 transition-colors"
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
        </button>
      </div>

      {/* Navigation Items */}
      <div className="flex-1 py-4 px-3 space-y-1.5 overflow-y-auto">
        <div className={`px-3 mb-2 text-[10px] font-mono font-semibold tracking-wider text-slate-500 uppercase ${collapsed ? 'text-center' : ''}`}>
          {collapsed ? '•••' : 'Main Menu'}
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-xl font-medium text-sm transition-all duration-200 group relative ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-[0_0_15px_rgba(0,243,255,0.15)] font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`
              }
            >
              <Icon className="w-5 h-5 shrink-0 transition-transform group-hover:scale-110" />
              {!collapsed && <span className="truncate flex-1">{item.label}</span>}
              {!collapsed && item.badge && (
                <Badge variant="cyan" size="sm" dot>
                  {item.badge}
                </Badge>
              )}
            </NavLink>
          );
        })}
      </div>

      {/* Quick Launch Card */}
      {!collapsed && (
        <div className="mx-3 mb-4 p-3.5 rounded-xl bg-linear-to-br from-slate-900/90 to-cyan-950/30 border border-cyan-500/20 text-xs text-slate-300 space-y-2">
          <div className="flex items-center gap-2 font-semibold text-cyan-300">
            <Zap className="w-4 h-4 text-cyan-400 animate-pulse" />
            <span>Target Shield Active</span>
          </div>
          <p className="text-[11px] text-slate-400">
             CLOUD VULNERABILITY SCANNER &amp; REPORT GENERATOR READY.
          </p>
        </div>
      )}

      {/* User Profile Footer */}
      <div className="p-3 border-t border-slate-800/80 bg-slate-950/60">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3 overflow-hidden">
            <div className="w-9 h-9 rounded-full bg-slate-800 border border-cyan-500/40 flex items-center justify-center text-cyan-400 font-bold text-sm shrink-0">
              {getInitials(user?.full_name)}
            </div>
            {!collapsed && (
              <div className="flex flex-col truncate">
                <span className="text-xs font-semibold text-slate-200 truncate">
                  {user?.full_name || 'SecOps User'}
                </span>
                <span className="text-[10px] text-slate-400 font-mono truncate">
                  {user?.email || 'operator@cloudvuln.io'}
                </span>
              </div>
            )}
          </div>
          {!collapsed && (
            <button
              onClick={handleLogout}
              className="text-slate-400 hover:text-rose-400 p-2 rounded-lg hover:bg-slate-800 transition-colors"
              title="Sign Out"
            >
              <LogOut className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>
    </aside>
  );
};
