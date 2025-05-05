
import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '@/contexts/AuthContext';
import Logo from './Logo';
import { Button } from '@/components/ui/button';
import { User, LogOut, LineChart, ShieldCheck } from 'lucide-react';

const Navbar: React.FC = () => {
  const { user, logout, isAdmin } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  return (
    <nav className="border-b border-gray-800 bg-crypto-darker">
      <div className="container mx-auto px-4 py-4 flex items-center justify-between">
        <Link to="/" className="flex items-center">
          <Logo />
        </Link>

        <div className="flex items-center gap-4">
          {user ? (
            <>
              {isAdmin ? (
                <Button variant="ghost" onClick={() => navigate('/admin')} className="flex gap-2 text-xs sm:text-sm">
                  <ShieldCheck size={16} />
                  <span className="hidden sm:inline">Admin Panel</span>
                </Button>
              ) : (
                <Button variant="ghost" onClick={() => navigate('/dashboard')} className="flex gap-2 text-xs sm:text-sm">
                  <LineChart size={16} />
                  <span className="hidden sm:inline">Dashboard</span>
                </Button>
              )}
              <div className="flex items-center gap-2">
                <div className="hidden md:block text-right">
                  <div className="text-sm font-medium">{user.name}</div>
                  <div className="text-xs text-muted-foreground">{user.email}</div>
                </div>
                <User className="text-crypto-accent h-5 w-5" />
              </div>
              <Button 
                variant="ghost" 
                size="icon" 
                onClick={handleLogout} 
                className="text-muted-foreground hover:text-white"
              >
                <LogOut size={18} />
              </Button>
            </>
          ) : (
            <>
              <Button 
                variant="ghost" 
                onClick={() => navigate('/login')}
                className="text-xs sm:text-sm"
              >
                Login
              </Button>
              <Button 
                onClick={() => navigate('/register')}
                className="bg-crypto-accent hover:bg-crypto-accent/80 text-xs sm:text-sm"
              >
                Register
              </Button>
            </>
          )}
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
