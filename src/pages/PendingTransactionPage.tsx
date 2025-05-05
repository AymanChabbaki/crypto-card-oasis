
import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { ArrowLeft, Clock, HelpCircle, CheckCircle2, MessageCircle } from 'lucide-react';

const PendingTransactionPage: React.FC = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { cryptoId, amount, cryptoAmount } = location.state || {};
  
  const faqs = [
    {
      question: "How long does the verification process take?",
      answer: "The verification process typically takes between 15 minutes to 1 hour during business hours. During peak times or outside business hours, it may take up to 24 hours."
    },
    {
      question: "What happens if my transaction is declined?",
      answer: "If your transaction is declined, you will receive an email notification with the reason. No funds will be deducted from your account, and you can attempt another transaction after addressing the issue."
    },
    {
      question: "Can I cancel my pending transaction?",
      answer: "Once submitted, transactions cannot be cancelled during the pending state. If you need to cancel, please contact our support team."
    },
    {
      question: "How will I know when my transaction is approved?",
      answer: "You will receive an email notification once your transaction is approved. You can also check your transaction status on your dashboard."
    },
    {
      question: "Where will my cryptocurrency be sent?",
      answer: "Your cryptocurrency will be sent to the wallet address you provided during the purchase process."
    }
  ];
  
  // Default values if state is missing
  const displayAmount = amount || 0;
  const displayCryptoAmount = cryptoAmount !== undefined ? cryptoAmount : 0;
  const displayCryptoId = cryptoId || 'BTC';

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
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="md:col-span-2">
          <Card className="crypto-card">
            <CardHeader>
              <div className="flex items-center mb-2">
                <div className="h-10 w-10 rounded-full bg-yellow-500/10 flex items-center justify-center mr-3">
                  <Clock className="h-5 w-5 text-yellow-500" />
                </div>
                <div>
                  <CardTitle className="text-xl">Transaction Pending</CardTitle>
                  <CardDescription>Your purchase is being reviewed</CardDescription>
                </div>
              </div>
            </CardHeader>
            
            <CardContent className="space-y-6">
              <div className="bg-crypto-darker rounded-md p-6 space-y-4">
                <div className="flex justify-between items-center">
                  <span className="text-muted-foreground">Status</span>
                  <div className="bg-yellow-500/10 text-yellow-500 border border-yellow-500/20 px-2 py-1 rounded-full text-sm font-medium">
                    Pending
                  </div>
                </div>
                
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Amount</span>
                  <span>${displayAmount}</span>
                </div>
                
                <div className="flex justify-between">
                  <span className="text-muted-foreground">You will receive</span>
                  <span>{displayCryptoAmount.toFixed(8)} {displayCryptoId.toUpperCase()}</span>
                </div>
                
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Estimated completion</span>
                  <span>Within 24 hours</span>
                </div>
              </div>
              
              <div className="bg-crypto-darker rounded-md p-6">
                <h3 className="text-lg font-semibold mb-3 flex items-center">
                  <CheckCircle2 className="mr-2 h-5 w-5 text-crypto-accent" />
                  What happens next?
                </h3>
                <ol className="space-y-3 list-decimal list-inside text-muted-foreground">
                  <li>Our team reviews your payment information</li>
                  <li>Once approved, the cryptocurrency is sent to your wallet</li>
                  <li>You'll receive a confirmation email when complete</li>
                  <li>The transaction will appear in your dashboard history</li>
                </ol>
              </div>
              
              <div className="flex gap-3">
                <Button 
                  className="flex-1 bg-crypto-accent hover:bg-crypto-accent/80 text-black"
                  onClick={() => navigate('/dashboard')}
                >
                  View Dashboard
                </Button>
                <Button 
                  variant="outline" 
                  className="flex-1 border-gray-700"
                  onClick={() => navigate('/support')}
                >
                  <MessageCircle className="mr-2 h-4 w-4" />
                  Contact Support
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
        
        <div>
          <Card className="crypto-card">
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center">
                <HelpCircle className="mr-2 h-5 w-5 text-crypto-accent" />
                Frequently Asked Questions
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Accordion type="single" collapsible className="w-full">
                {faqs.map((faq, index) => (
                  <AccordionItem key={index} value={`item-${index}`} className="border-gray-800">
                    <AccordionTrigger className="text-sm text-left">
                      {faq.question}
                    </AccordionTrigger>
                    <AccordionContent className="text-sm text-muted-foreground">
                      {faq.answer}
                    </AccordionContent>
                  </AccordionItem>
                ))}
              </Accordion>
              
              <div className="mt-6 p-3 bg-crypto-accent/10 rounded-md">
                <p className="text-sm text-muted-foreground">
                  Need more assistance? Our support team is available 24/7 to help you with any questions.
                </p>
                <Button
                  variant="link"
                  className="p-0 h-auto text-crypto-accent"
                  onClick={() => navigate('/support')}
                >
                  Contact Support
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default PendingTransactionPage;
