
import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { useAuth } from '@/contexts/AuthContext';
import { Bitcoin, ShieldCheck } from 'lucide-react';
import { Checkbox } from '@/components/ui/checkbox';

const LoginPage: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const { login, savedCredentials } = useAuth();

  const redirectPath = location.state?.redirectAfterLogin || '/dashboard';
  
  // Use saved credentials if available
  useEffect(() => {
    if (savedCredentials) {
      setEmail(savedCredentials.email);
      setPassword(savedCredentials.password);
      setRememberMe(true);
    }
  }, [savedCredentials]);
  
  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setIsLoading(true);
    
    try {
      const success = await login(email, password, rememberMe);
      if (success) {
        // Check if the email is for admin
        if (email === 'admin@example.com') {
          navigate('/admin');
        } else {
          navigate(redirectPath);
        }
      } else {
        setIsLoading(false);
      }
    } catch (error) {
      console.error('Login error:', error);
      setIsLoading(false);
    }
  };

  const handleAdminLogin = async () => {
    setIsLoading(true);
    try {
      const success = await login('admin@example.com', 'password', rememberMe);
      if (success) {
        navigate('/admin');
      } else {
        setIsLoading(false);
      }
    } catch (error) {
      console.error('Admin login error:', error);
      setIsLoading(false);
    }
  };

  return (
    <div className="container max-w-md mx-auto px-4 py-12">
      <Card className="crypto-card border-gray-800">
        <CardHeader className="space-y-1 flex items-center">
          <div className="mx-auto mb-4">
            <Bitcoin size={40} className="text-crypto-accent" />
          </div>
          <CardTitle className="text-2xl text-center">Sign in to your account</CardTitle>
          <CardDescription className="text-center">
            Enter your email and password to access your account
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                placeholder="name@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="bg-crypto-darker border-gray-700"
              />
            </div>
            <div className="space-y-2">
              <div className="flex justify-between">
                <Label htmlFor="password">Password</Label>
                <Link to="/forgot-password" className="text-xs text-crypto-accent hover:underline">
                  Forgot password?
                </Link>
              </div>
              <Input
                id="password"
                type="password"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="bg-crypto-darker border-gray-700"
              />
            </div>
            <div className="flex items-center space-x-2">
              <Checkbox 
                id="remember-me" 
                checked={rememberMe} 
                onCheckedChange={() => setRememberMe(!rememberMe)}
              />
              <Label htmlFor="remember-me" className="text-sm cursor-pointer">Remember me</Label>
            </div>
            <Button 
              type="submit" 
              className="w-full bg-crypto-accent hover:bg-crypto-accent/80 text-black"
              disabled={isLoading}
            >
              {isLoading ? 'Signing in...' : 'Sign In'}
            </Button>
          </form>
          <div className="mt-4 text-center text-sm">
            Don't have an account?{' '}
            <Link to="/register" className="text-crypto-accent hover:underline">
              Register
            </Link>
          </div>
        </CardContent>
        <CardFooter>
          <Button 
            variant="outline" 
            className="w-full border-gray-700 hover:border-crypto-accent/50 hover:bg-crypto-accent/10"
            onClick={handleAdminLogin}
          >
            <ShieldCheck size={16} className="mr-2" />
            Admin Login (Demo)
          </Button>
        </CardFooter>
      </Card>
    </div>
  );
};

export default LoginPage;
