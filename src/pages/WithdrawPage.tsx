
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/contexts/AuthContext';
import { useCrypto } from '@/contexts/CryptoContext';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { ArrowDownLeft } from 'lucide-react';
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import * as z from 'zod';
import { toast } from '@/hooks/use-toast';

const formSchema = z.object({
  amount: z.coerce.number().positive("Amount must be greater than 0"),
  paymentDetails: z.object({
    walletAddress: z.string().min(1, "Wallet address is required"),
  }),
});

const WithdrawPage = () => {
  const { user } = useAuth();
  const { addTransaction } = useCrypto();
  const navigate = useNavigate();
  
  // Redirect if not logged in
  React.useEffect(() => {
    if (!user) {
      navigate('/login');
    }
  }, [user, navigate]);

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      amount: 0,
      paymentDetails: {
        walletAddress: '',
      },
    },
  });

  const onSubmit = (values: z.infer<typeof formSchema>) => {
    if (!user) {
      toast({
        title: "Authentication Error",
        description: "You must be logged in to withdraw funds",
        variant: "destructive",
      });
      return;
    }

    if (user.walletBalance < values.amount) {
      toast({
        title: "Insufficient Balance",
        description: "You don't have enough funds to withdraw this amount",
        variant: "destructive",
      });
      return;
    }

    addTransaction({
      userId: user.id,
      type: 'withdrawal',
      status: 'pending',
      amount: values.amount,
      paymentDetails: {
        walletAddress: values.paymentDetails.walletAddress,
      },
    });

    toast({
      title: "Withdrawal Request Submitted",
      description: "Your withdrawal request is now pending approval",
    });

    navigate('/transaction/pending');
  };

  return (
    <div className="container mx-auto px-4 py-8">
      <h1 className="text-3xl font-bold mb-8">Withdraw Funds</h1>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card className="crypto-card">
          <CardHeader>
            <CardTitle className="flex items-center">
              <ArrowDownLeft className="mr-2 h-5 w-5" />
              Withdraw Funds
            </CardTitle>
            <CardDescription>Withdraw funds to your external wallet</CardDescription>
          </CardHeader>
          <CardContent>
            <Form {...form}>
              <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
                <FormField
                  control={form.control}
                  name="amount"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Amount ($)</FormLabel>
                      <FormControl>
                        <Input 
                          placeholder="0.00" 
                          type="number" 
                          {...field} 
                          className="bg-crypto-darker"
                        />
                      </FormControl>
                      <FormDescription>
                        Available Balance: ${user?.walletBalance.toFixed(2) || '0.00'}
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                
                <FormField
                  control={form.control}
                  name="paymentDetails.walletAddress"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Wallet Address</FormLabel>
                      <FormControl>
                        <Input 
                          placeholder="Your external wallet address" 
                          {...field} 
                          className="bg-crypto-darker"
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                
                <Button type="submit" className="w-full bg-crypto-accent hover:bg-crypto-accent/80 text-black">
                  Submit Withdrawal Request
                </Button>
              </form>
            </Form>
          </CardContent>
        </Card>
        
        <Card className="crypto-card">
          <CardHeader>
            <CardTitle>Withdrawal Information</CardTitle>
            <CardDescription>Important information about withdrawals</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <h3 className="font-semibold mb-1">Processing Time</h3>
              <p className="text-sm text-muted-foreground">
                Withdrawals are typically processed within 24-48 hours after approval.
              </p>
            </div>
            
            <div>
              <h3 className="font-semibold mb-1">Minimum Withdrawal</h3>
              <p className="text-sm text-muted-foreground">
                The minimum withdrawal amount is $10.00.
              </p>
            </div>
            
            <div>
              <h3 className="font-semibold mb-1">Verification</h3>
              <p className="text-sm text-muted-foreground">
                For security purposes, large withdrawals may require additional verification.
              </p>
            </div>
            
            <div>
              <h3 className="font-semibold mb-1">Fees</h3>
              <p className="text-sm text-muted-foreground">
                A small network fee may apply to all withdrawals depending on blockchain congestion.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default WithdrawPage;
