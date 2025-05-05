
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useAuth } from '@/contexts/AuthContext';
import { useCrypto } from '@/contexts/CryptoContext';
import { ArrowLeft, CreditCard, QrCode, Wallet } from 'lucide-react';
import { useToast } from "@/hooks/use-toast";

const DepositPage: React.FC = () => {
  const [amount, setAmount] = useState('');
  const [cardNumber, setCardNumber] = useState('');
  const [expiryDate, setExpiryDate] = useState('');
  const [cvc, setCvc] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  
  const navigate = useNavigate();
  const { user } = useAuth();
  const { addTransaction } = useCrypto();
  const { toast } = useToast();
  
  // Redirect if not logged in
  React.useEffect(() => {
    if (!user) {
      navigate('/login', { state: { redirectAfterLogin: '/dashboard/deposit' } });
    }
  }, [user, navigate]);
  
  if (!user) {
    return null;
  }
  
  // Format card number with spaces
  const formatCardNumber = (value: string) => {
    const v = value.replace(/\s+/g, '').replace(/[^0-9]/gi, '');
    const matches = v.match(/\d{4,16}/g);
    const match = matches && matches[0] || '';
    const parts = [];
    for (let i = 0; i < match.length; i += 4) {
      parts.push(match.substring(i, i + 4));
    }
    return parts.length > 0 ? parts.join(' ') : value;
  };
  
  // Format expiry date
  const formatExpiryDate = (value: string) => {
    const v = value.replace(/\s+/g, '').replace(/[^0-9]/gi, '');
    if (v.length > 2) {
      return `${v.substring(0, 2)}/${v.substring(2, 4)}`;
    }
    return v;
  };
  
  const handleDeposit = (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    
    if (!amount || parseFloat(amount) <= 0 || !cardNumber || !expiryDate || !cvc) {
      toast({
        title: "Invalid Information",
        description: "Please fill all required fields with valid information",
        variant: "destructive"
      });
      setIsLoading(false);
      return;
    }
    
    try {
      // Create deposit transaction
      addTransaction({
        userId: user.id,
        type: 'deposit',
        status: 'pending',
        amount: parseFloat(amount),
        paymentDetails: {
          cardNumber: cardNumber.replace(/\s/g, '').slice(-4),
          name: user.name
        }
      });
      
      toast({
        title: "Deposit Request Received",
        description: "Your deposit is being processed and will be available soon.",
      });
      
      // Navigate back to dashboard after successful submission
      setTimeout(() => {
        navigate('/dashboard');
      }, 1500);
    } catch (error) {
      console.error('Error processing deposit:', error);
      toast({
        title: "Deposit Failed",
        description: "There was an error processing your deposit. Please try again.",
        variant: "destructive"
      });
      setIsLoading(false);
    }
  };
  
  return (
    <div className="container mx-auto px-4 py-8">
      <Button 
        variant="ghost" 
        onClick={() => navigate('/dashboard')} 
        className="mb-6"
      >
        <ArrowLeft className="mr-2 h-4 w-4" />
        Back to Dashboard
      </Button>
      
      <Card className="crypto-card max-w-2xl mx-auto">
        <CardHeader>
          <CardTitle>Deposit Funds</CardTitle>
          <CardDescription>Add funds to your crypto wallet</CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="card" className="w-full">
            <TabsList className="grid w-full grid-cols-2 bg-crypto-darker">
              <TabsTrigger value="card" className="flex items-center">
                <CreditCard className="mr-2 h-4 w-4" />
                <span>Credit Card</span>
              </TabsTrigger>
              <TabsTrigger value="crypto" className="flex items-center">
                <QrCode className="mr-2 h-4 w-4" />
                <span>Crypto</span>
              </TabsTrigger>
            </TabsList>
            
            <TabsContent value="card" className="space-y-6 pt-4">
              <form onSubmit={handleDeposit} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="deposit-amount">Amount (USD)</Label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <span className="text-muted-foreground">$</span>
                    </div>
                    <Input
                      id="deposit-amount"
                      type="number"
                      placeholder="0.00"
                      value={amount}
                      onChange={(e) => setAmount(e.target.value)}
                      min="10"
                      step="1"
                      className="pl-8 bg-crypto-darker border-gray-700"
                    />
                  </div>
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="deposit-card">Card Number</Label>
                  <Input
                    id="deposit-card"
                    placeholder="1234 5678 9012 3456"
                    value={cardNumber}
                    onChange={(e) => setCardNumber(formatCardNumber(e.target.value))}
                    maxLength={19}
                    className="bg-crypto-darker border-gray-700"
                  />
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="deposit-expiry">Expiry Date</Label>
                    <Input
                      id="deposit-expiry"
                      placeholder="MM/YY"
                      value={expiryDate}
                      onChange={(e) => setExpiryDate(formatExpiryDate(e.target.value))}
                      maxLength={5}
                      className="bg-crypto-darker border-gray-700"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="deposit-cvc">CVC</Label>
                    <Input
                      id="deposit-cvc"
                      placeholder="123"
                      value={cvc}
                      onChange={(e) => setCvc(e.target.value)}
                      type="password"
                      maxLength={3}
                      className="bg-crypto-darker border-gray-700"
                    />
                  </div>
                </div>
                
                <div className="pt-2">
                  <Button 
                    type="submit" 
                    className="w-full bg-crypto-accent hover:bg-crypto-accent/80 text-black"
                    disabled={isLoading}
                  >
                    {isLoading ? 'Processing...' : 'Deposit Funds'}
                  </Button>
                </div>
              </form>
            </TabsContent>
            
            <TabsContent value="crypto" className="pt-4">
              <div className="text-center py-6 space-y-4">
                <div className="mx-auto bg-white p-4 rounded-lg w-48 h-48 flex items-center justify-center">
                  <QrCode size={160} className="text-black" />
                </div>
                
                <div>
                  <h3 className="font-medium">Deposit with cryptocurrency</h3>
                  <p className="text-sm text-muted-foreground mb-2">
                    Scan the QR code or copy the wallet address below
                  </p>
                  
                  <div className="bg-crypto-darker flex items-center rounded-md border border-gray-700 p-2">
                    <div className="bg-gray-800 p-1 rounded mr-2">
                      <Wallet size={16} className="text-crypto-accent" />
                    </div>
                    <span className="text-xs text-muted-foreground mr-2 truncate">
                      bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
                    </span>
                    <Button variant="ghost" size="sm" className="ml-auto text-crypto-accent">
                      Copy
                    </Button>
                  </div>
                </div>
                
                <div className="bg-crypto-accent/10 rounded-md p-3 text-sm text-left">
                  <p className="text-muted-foreground">
                    Cryptocurrency deposits are automatically added to your account after network confirmation (typically within 30 minutes).
                  </p>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default DepositPage;
