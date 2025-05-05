
import React, { createContext, useState, useContext } from 'react';
import { User, AuthContextType } from '../types/auth';

// Create a mock user that will always be "logged in"
const mockUser: User = {
  id: 'mock-user-id',
  email: 'user@example.com',
  name: 'Demo User',
  role: 'user',
  walletBalance: 10000,
  cryptoHoldings: []
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(mockUser);
  const [loading, setLoading] = useState<boolean>(false);
  const [savedCredentials, setSavedCredentials] = useState<{ email: string; password: string } | null>(null);

  // Mock authentication functions that don't actually do anything
  const login = async (email: string, password: string): Promise<boolean> => {
    // API call would go here
    
    //Example API call:
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      const data = await response.json();
      if (data.success) {
        setUser(data.user);
        return true;
      }
    } catch (error) {
      console.error('Login error:', error);
    }
    setUser(mockUser);
    return true;
  };

  const register = async (name: string, email: string, password: string): Promise<boolean> => {
    // API call would go here
    //Example API call:
    try {
      const response = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password }),
      });
      const data = await response.json();
      if (data.success) {
        setUser(data.user);
        return true;
      }
    } catch (error) {
      console.error('Registration error:', error);
    }
    setUser(mockUser);
    return true;
  };

  const logout = async () => {
    // API call would go here
  
   // Example API call:
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
      });
    } catch (error) {
      console.error('Logout error:', error);
    }
    // We don't actually log out in the demo mode
    console.log('Logout called but ignored in demo mode');
  };

  const value = {
    user,
    loading,
    login,
    register,
    logout,
    isAdmin: user?.role === 'admin',
    savedCredentials,
    setUser
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export type { User };
