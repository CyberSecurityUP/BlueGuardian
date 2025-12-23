import { Link, useLocation } from 'react-router-dom';
import { Shield, Home, Upload, List, Settings } from 'lucide-react';

interface LayoutProps {
  children: React.ReactNode;
}

export default function Layout({ children }: LayoutProps) {
  const location = useLocation();

  const navItems = [
    { path: '/', icon: Home, label: 'Dashboard' },
    { path: '/analyze', icon: Upload, label: 'Analyze' },
    { path: '/jobs', icon: List, label: 'Jobs' },
    { path: '/settings', icon: Settings, label: 'Settings' },
  ];

  const isActive = (path: string) => location.pathname === path;

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Sidebar */}
      <aside className="fixed left-0 top-0 h-full w-64 bg-blue-900 text-white">
        <div className="p-6">
          <div className="flex items-center gap-3 mb-8">
            <Shield className="w-8 h-8" />
            <div>
              <h1 className="text-xl font-bold">BlueGuardian AI</h1>
              <p className="text-xs text-blue-300">Security Analysis</p>
            </div>
          </div>

          <nav className="space-y-2">
            {navItems.map((item) => {
              const Icon = item.icon;
              const active = isActive(item.path);

              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`
                    flex items-center gap-3 px-4 py-3 rounded-lg transition-colors
                    ${
                      active
                        ? 'bg-blue-800 text-white'
                        : 'text-blue-200 hover:bg-blue-800/50 hover:text-white'
                    }
                  `}
                >
                  <Icon className="w-5 h-5" />
                  <span className="font-medium">{item.label}</span>
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Version */}
        <div className="absolute bottom-0 left-0 right-0 p-6 text-xs text-blue-300">
          <p>Version 1.0.0</p>
          <p className="mt-1">© 2024 BlueGuardian AI</p>
        </div>
      </aside>

      {/* Main content */}
      <main className="ml-64 p-8">
        {children}
      </main>
    </div>
  );
}
