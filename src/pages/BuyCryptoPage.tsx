
import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useAuth } from '@/contexts/AuthContext';
import { useCrypto } from '@/contexts/CryptoContext';
import { CreditCard, ArrowLeft, Info, Loader } from 'lucide-react';
import { useToast } from "@/hooks/use-toast";
import { Progress } from "@/components/ui/progress";

const countries = [
  { code: "US", name: "United States" },
  { code: "GB", name: "United Kingdom" },
  { code: "CA", name: "Canada" },
  { code: "AU", name: "Australia" },
  { code: "DE", name: "Germany" },
  { code: "FR", name: "France" },
  { code: "JP", name: "Japan" },
  { code: "CN", name: "China" },
  { code: "IN", name: "India" },
  { code: "BR", name: "Brazil" },
];

const BuyCryptoPage: React.FC = () => {
  const { cryptoId } = useParams<{ cryptoId: string }>();
  const navigate = useNavigate();
  const { user } = useAuth();
  const { cryptocurrencies, addTransaction } = useCrypto();
  const { toast } = useToast();
  
  const [amount, setAmount] = useState<string>('100');
  const [cryptoAmount, setCryptoAmount] = useState<number>(0);
  const [name, setName] = useState<string>(user?.name || '');
  const [cardNumber, setCardNumber] = useState<string>('');
  const [expiryDate, setExpiryDate] = useState<string>('');
  const [cvc, setCvc] = useState<string>('');
  const [country, setCountry] = useState<string>('US');
  const [walletAddress, setWalletAddress] = useState<string>('');
  const [phoneNumber, setPhoneNumber] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [processingStep, setProcessingStep] = useState<number>(0);
  const [processingProgress, setProcessingProgress] = useState<number>(0);
  
  const selectedCrypto = cryptocurrencies.find(crypto => crypto.id === cryptoId);
  
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
  
  useEffect(() => {
    // Calculate crypto amount based on fiat amount
    if (selectedCrypto && amount) {
      const numAmount = parseFloat(amount);
      const commissionRate = 0.14; // 14%
      const amountAfterCommission = numAmount * (1 - commissionRate);
      setCryptoAmount(amountAfterCommission / selectedCrypto.price);
    } else {
      setCryptoAmount(0);
    }
  }, [amount, selectedCrypto]);
  
  // Redirect to login if not logged in
  useEffect(() => {
    if (!user) {
      toast({
        title: "Authentication Required",
        description: "Please log in to purchase crypto",
      });
      navigate('/login', { state: { redirectAfterLogin: `/buy/${cryptoId}` } });
    }
  }, [user, navigate, cryptoId, toast]);
  
  // Redirect if crypto not found
  useEffect(() => {
    if (!cryptoId || (!selectedCrypto && cryptocurrencies.length > 0)) {
      toast({
        title: "Cryptocurrency Not Found",
        description: "The cryptocurrency you're looking for doesn't exist",
        variant: "destructive",
      });
      navigate('/market');
    }
  }, [selectedCrypto, cryptocurrencies, cryptoId, navigate, toast]);
  
  // Process the form with steps and delay
  const processTransaction = () => {
    return new Promise<void>((resolve) => {
      // Processing steps
      const totalSteps = 5;
      let currentStep = 0;
      
      const stepLabels = [
        "Validating payment information...",
        "Processing payment...",
        "Confirming transaction...",
        "Allocating funds...",
        "Finalizing purchase..."
      ];
      
      const simulateProgress = () => {
        if (currentStep >= totalSteps) {
          resolve();
          return;
        }
        
        setProcessingStep(currentStep);
        
        // Update progress for current step (0-100%)
        const updateInterval = setInterval(() => {
          setProcessingProgress((prev) => {
            const newProgress = prev + 5;
            if (newProgress >= 100) {
              clearInterval(updateInterval);
              currentStep++;
              setTimeout(simulateProgress, 200); // Slight pause between steps
              return 0; // Reset for next step
            }
            return newProgress;
          });
        }, 50);
      };
      
      // Start the progress simulation
      simulateProgress();
    });
  };
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    
    // Simple validation
    if (!name || !cardNumber || !expiryDate || !cvc || !country || !amount || !walletAddress || !phoneNumber) {
      toast({
        title: "Missing Information",
        description: "Please fill in all fields",
        variant: "destructive",
      });
      setIsLoading(false);
      return;
    }
    
    if (cardNumber.replace(/\s/g, '').length < 16) {
      toast({
        title: "Invalid Card Number",
        description: "Please enter a valid card number",
        variant: "destructive",
      });
      setIsLoading(false);
      return;
    }
    
    if (walletAddress.length < 10) {
      toast({
        title: "Invalid Wallet Address",
        description: "Please enter a valid wallet address",
        variant: "destructive",
      });
      setIsLoading(false);
      return;
    }
    
    try {
      // Process with delay
      await processTransaction();
      
      // Create a new transaction
      addTransaction({
        userId: user!.id,
        type: 'buy',
        status: 'pending',
        amount: parseFloat(amount),
        cryptoAmount: cryptoAmount,
        cryptocurrency: selectedCrypto!.name,
        cryptoSymbol: selectedCrypto!.symbol,
        paymentDetails: {
          cardNumber: cardNumber.replace(/\s/g, '').slice(-4), // Store only last 4 digits
          name,
          walletAddress,
          country: countries.find(c => c.code === country)?.name || country,
          phoneNumber
        }
      });
      
      toast({
        title: "Purchase Request Submitted",
        description: "Your transaction is being processed. You will be notified once it's approved.",
      });
      
      // Navigate to the pending transaction page
      navigate('/transaction/pending', { state: { cryptoId, amount, cryptoAmount } });
    } catch (error) {
      console.error('Error processing transaction:', error);
      toast({
        title: "Transaction Failed",
        description: "There was an error processing your transaction. Please try again.",
        variant: "destructive",
      });
      setIsLoading(false);
    }
  };
  
  if (!selectedCrypto) {
    return <div className="container mx-auto px-4 py-8 text-center">Loading...</div>;
  }
  
  const formatPrice = (price: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: price < 1 ? 4 : 2,
      maximumFractionDigits: price < 1 ? 4 : 2
    }).format(price);
  };
  
  // Show the processing UI when transaction is loading
  const renderProcessingUI = () => {
    const stepLabels = [
      "Validating payment information...",
      "Processing payment...",
      "Confirming transaction...",
      "Allocating funds...",
      "Finalizing purchase..."
    ];
    
    return (
      <div className="space-y-6 py-4">
        <div className="flex items-center justify-center mb-8">
          <div className="animate-spin mr-2">
            <Loader className="h-8 w-8 text-crypto-accent" />
          </div>
          <h3 className="text-xl font-medium">{stepLabels[processingStep]}</h3>
        </div>
        
        <Progress value={processingProgress} className="w-full h-2" />
        
        <p className="text-center text-sm text-muted-foreground">
          Please don't close or refresh this page while your transaction is being processed.
        </p>
      </div>
    );
  };
  
  return (
    <div className="container mx-auto px-4 py-8">
      <Button 
        variant="ghost" 
        onClick={() => navigate(-1)} 
        className="mb-6"
        disabled={isLoading}
      >
        <ArrowLeft className="mr-2 h-4 w-4" />
        Back
      </Button>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="md:col-span-2">
          <Card className="crypto-card">
            <CardHeader>
              <CardTitle>Buy {selectedCrypto.name}</CardTitle>
              <CardDescription>
                Complete the form to purchase {selectedCrypto.symbol} with your bank card
              </CardDescription>
            </CardHeader>
            
            <CardContent>
              {isLoading ? (
                renderProcessingUI()
              ) : (
                <form onSubmit={handleSubmit} className="space-y-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {/* Payment Amount Section */}
                    <div className="md:col-span-2 space-y-2">
                      <Label htmlFor="amount">Amount (USD)</Label>
                      <div className="flex">
                        <Input
                          id="amount"
                          type="number"
                          value={amount}
                          onChange={(e) => setAmount(e.target.value)}
                          min="10"
                          step="1"
                          className="bg-crypto-darker border-gray-700"
                          required
                        />
                      </div>
                      <div className="flex justify-between text-sm text-muted-foreground">
                        <span>Commission (14%): ${(parseFloat(amount || '0') * 0.14).toFixed(2)}</span>
                        <span>You receive: {cryptoAmount.toFixed(8)} {selectedCrypto.symbol}</span>
                      </div>
                    </div>
                    
                    {/* Personal Info Section */}
                    <div className="space-y-2">
                      <Label htmlFor="name">Full Name</Label>
                      <Input
                        id="name"
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        className="bg-crypto-darker border-gray-700"
                        required
                      />
                    </div>
                    
                    <div className="space-y-2">
                      <Label htmlFor="walletAddress">Wallet Address</Label>
                      <Input
                        id="walletAddress"
                        placeholder="0x..."
                        value={walletAddress}
                        onChange={(e) => setWalletAddress(e.target.value)}
                        className="bg-crypto-darker border-gray-700"
                        required
                      />
                    </div>
                    
                    <div className="space-y-2">
                      <Label htmlFor="country">Country</Label>
                      <Select value={country} onValueChange={setCountry}>
                        <SelectTrigger className="bg-crypto-darker border-gray-700">
                          <SelectValue placeholder="Select country" />
                        </SelectTrigger>
                        <SelectContent>
                          {countries.map((country) => (
                            <SelectItem key={country.code} value={country.code}>
                              {country.name}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    
                    <div className="space-y-2">
                      <Label htmlFor="phoneNumber">Phone Number</Label>
                      <Input
                        id="phoneNumber"
                        placeholder="+1234567890"
                        value={phoneNumber}
                        onChange={(e) => setPhoneNumber(e.target.value)}
                        className="bg-crypto-darker border-gray-700"
                        required
                      />
                    </div>
                    
                    {/* Card Details Section */}
                    <div className="md:col-span-2">
                      <div className="flex items-center space-x-2 mb-4">
                        <div className="h-10 w-10 flex items-center justify-center rounded-full bg-crypto-accent/10">
                          <CreditCard className="h-5 w-5 text-crypto-accent" />
                        </div>
                        <div>
                          <h3 className="font-medium">Payment Method</h3>
                          <p className="text-sm text-muted-foreground">Enter your card details</p>
                        </div>
                      </div>
                      
                      <div className="space-y-4">
                        <div className="space-y-2">
                          <Label htmlFor="cardNumber">Card Number</Label>
                          <Input
                            id="cardNumber"
                            placeholder="1234 5678 9012 3456"
                            value={cardNumber}
                            onChange={(e) => setCardNumber(formatCardNumber(e.target.value))}
                            maxLength={19}
                            className="bg-crypto-darker border-gray-700"
                            required
                          />
                        </div>
                        
                        <div className="grid grid-cols-2 gap-4">
                          <div className="space-y-2">
                            <Label htmlFor="expiryDate">Expiry Date</Label>
                            <Input
                              id="expiryDate"
                              placeholder="MM/YY"
                              value={expiryDate}
                              onChange={(e) => setExpiryDate(formatExpiryDate(e.target.value))}
                              maxLength={5}
                              className="bg-crypto-darker border-gray-700"
                              required
                            />
                          </div>
                          <div className="space-y-2">
                            <Label htmlFor="cvc">CVC</Label>
                            <Input
                              id="cvc"
                              placeholder="123"
                              value={cvc}
                              onChange={(e) => setCvc(e.target.value)}
                              type="password"
                              maxLength={3}
                              className="bg-crypto-darker border-gray-700"
                              required
                            />
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                  
                  <Button
                    type="submit"
                    className="w-full bg-crypto-accent hover:bg-crypto-accent/80 text-black"
                    disabled={isLoading}
                  >
                    Buy {selectedCrypto.symbol}
                  </Button>
                </form>
              )}
            </CardContent>
          </Card>
        </div>
        
        <div>
          <Card className="crypto-card sticky top-6">
            <CardHeader>
              <CardTitle>Order Summary</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Price</span>
                <span>{formatPrice(selectedCrypto.price)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Amount</span>
                <span>{formatPrice(parseFloat(amount || '0'))}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Commission (14%)</span>
                <span>{formatPrice(parseFloat(amount || '0') * 0.14)}</span>
              </div>
              <div className="border-t border-gray-800 pt-4 flex justify-between font-medium">
                <span>You Receive</span>
                <div className="text-right">
                  <div>{cryptoAmount.toFixed(8)} {selectedCrypto.symbol}</div>
                  <div className="text-xs text-muted-foreground">
                    ≈ {formatPrice(parseFloat(amount || '0') * 0.86)}
                  </div>
                </div>
              </div>
            </CardContent>
            <CardFooter>
              <div className="bg-crypto-accent/10 rounded-md p-3 text-sm flex w-full">
                <Info className="h-5 w-5 text-crypto-accent mr-2 shrink-0" />
                <p className="text-muted-foreground">
                  Your transaction will be reviewed by our team before the {selectedCrypto.symbol} is sent to your wallet.
                </p>
              </div>
            </CardFooter>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default BuyCryptoPage;
