
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import CryptoCard from '@/components/CryptoCard';
import ServiceCard from '@/components/ServiceCard';
import { useAuth } from '@/contexts/AuthContext';
import { useCrypto } from '@/contexts/CryptoContext';
import { Wallet, Banknote, LineChart, Bitcoin, TrendingUp, Coins, HeartPulse } from 'lucide-react';

const services = [
  {
    title: "Buy crypto",
    description: "One click to buy crypto on service",
    icon: Bitcoin,
    highlighted: true,
    key: "buy-crypto"
  },
  {
    title: "Copy trading",
    description: "One click to buy crypto on service",
    icon: HeartPulse,
    key: "copy-trading"
  },
  {
    title: "Deposit",
    description: "Fast deposit methods",
    icon: Banknote,
    key: "deposit"
  },
  {
    title: "Spot",
    description: "Trade crypto directly",
    icon: LineChart,
    key: "spot"
  },
  {
    title: "Futures",
    description: "Advanced trading options",
    icon: TrendingUp,
    key: "futures"
  },
  {
    title: "Campaign",
    description: "Special offers and rewards",
    icon: Coins,
    key: "campaign"
  }
];

const HomePage: React.FC = () => {
  const navigate = useNavigate();
  const { user } = useAuth();
  const { cryptocurrencies, loading, watchlist } = useCrypto();

  // Handle buying crypto
  const handleBuyCrypto = (cryptoId: string) => {
    if (user) {
      navigate(`/buy/${cryptoId}`);
    } else {
      navigate('/login', { state: { redirectAfterLogin: `/buy/${cryptoId}` } });
    }
  };

  const handleServiceClick = (serviceKey: string) => {
    switch (serviceKey) {
      case 'buy-crypto':
        navigate('/market');
        break;
      case 'deposit':
        if (user) {
          navigate('/dashboard/deposit');
        } else {
          navigate('/login', { state: { redirectAfterLogin: '/dashboard/deposit' } });
        }
        break;
      default:
        // For demo, just navigate to market for other services
        navigate('/market');
    }
  };

  return (
    <div className="container mx-auto px-4 pb-12">
      <section className="py-12">
        <div className="text-center max-w-3xl mx-auto">
          <h1 className="text-4xl sm:text-5xl font-bold mb-6">
            Buy and Sell Cryptocurrency with <span className="gradient-text">Bank Cards</span>
          </h1>
          <p className="text-lg text-muted-foreground mb-8">
            Fast, secure, and easy. The simplest way to buy crypto with your card or bank account.
          </p>
        </div>
        
        {/* Wallet Balance Card (only for logged-in users) */}
        {user && (
          <Card className="crypto-card mb-8">
            <CardContent className="p-5">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-muted-foreground">Your Wallet Balance</p>
                  <h3 className="text-2xl sm:text-3xl font-bold">
                    ${user.walletBalance.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}
                  </h3>
                </div>
                <div className="h-12 w-12 bg-crypto-accent/10 rounded-full flex items-center justify-center">
                  <Wallet className="h-6 w-6 text-crypto-accent" />
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Services Grid */}
        <h2 className="text-xl font-bold mb-4 uppercase text-gray-300">Services</h2>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 sm:gap-4 mb-12">
          {services.map((service) => (
            <ServiceCard
              key={service.key}
              title={service.title}
              description={service.description}
              icon={service.icon}
              highlighted={service.highlighted}
              onClick={() => handleServiceClick(service.key)}
            />
          ))}
        </div>
        
        {/* Cryptocurrency Market Section */}
        <Card className="crypto-card overflow-hidden mb-6">
          <CardHeader className="border-b border-gray-800 bg-crypto-darker px-6">
            <div className="flex items-center justify-between">
              <CardTitle className="text-xl font-bold">
                Today's Cryptocurrency Prices
              </CardTitle>
            </div>
          </CardHeader>
          <CardContent className="p-6">
            <Tabs defaultValue="all" className="w-full">
              <TabsList className="grid w-full grid-cols-3 bg-crypto-darker mb-4">
                <TabsTrigger value="all">All</TabsTrigger>
                <TabsTrigger value="gainers">Gainers</TabsTrigger>
                <TabsTrigger value="watchlist" disabled={watchlist.length === 0}>
                  Watchlist {watchlist.length > 0 && `(${watchlist.length})`}
                </TabsTrigger>
              </TabsList>
              
              <TabsContent value="all" className="mt-0">
                {loading ? (
                  <div className="py-8 text-center">
                    <p className="animate-pulse text-muted-foreground">Loading cryptocurrencies...</p>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4 mt-4">
                    {cryptocurrencies.map((crypto) => (
                      <CryptoCard 
                        key={crypto.id} 
                        crypto={crypto} 
                        onBuy={() => handleBuyCrypto(crypto.id)} 
                      />
                    ))}
                  </div>
                )}
              </TabsContent>
              
              <TabsContent value="gainers" className="mt-0">
                {loading ? (
                  <div className="py-8 text-center">
                    <p className="animate-pulse text-muted-foreground">Loading gainers...</p>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4 mt-4">
                    {cryptocurrencies
                      .filter(crypto => crypto.priceChange24h > 0)
                      .sort((a, b) => b.priceChange24h - a.priceChange24h)
                      .map((crypto) => (
                        <CryptoCard 
                          key={crypto.id} 
                          crypto={crypto} 
                          onBuy={() => handleBuyCrypto(crypto.id)} 
                        />
                      ))}
                  </div>
                )}
              </TabsContent>
              
              <TabsContent value="watchlist" className="mt-0">
                {loading ? (
                  <div className="py-8 text-center">
                    <p className="animate-pulse text-muted-foreground">Loading watchlist...</p>
                  </div>
                ) : (
                  <>
                    {watchlist.length > 0 ? (
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4 mt-4">
                        {cryptocurrencies
                          .filter(crypto => watchlist.includes(crypto.id))
                          .map((crypto) => (
                            <CryptoCard 
                              key={crypto.id} 
                              crypto={crypto} 
                              onBuy={() => handleBuyCrypto(crypto.id)} 
                            />
                          ))}
                      </div>
                    ) : (
                      <div className="py-8 text-center">
                        <p className="text-muted-foreground">No cryptocurrencies in your watchlist.</p>
                      </div>
                    )}
                  </>
                )}
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      </section>
    </div>
  );
};

export default HomePage;
