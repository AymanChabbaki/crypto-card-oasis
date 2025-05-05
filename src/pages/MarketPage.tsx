
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import CryptoCard from '@/components/CryptoCard';
import { useAuth } from '@/contexts/AuthContext';
import { useCrypto } from '@/contexts/CryptoContext';
import { Search } from 'lucide-react';

const MarketPage: React.FC = () => {
  const navigate = useNavigate();
  const { user } = useAuth();
  const { cryptocurrencies, loading, watchlist } = useCrypto();
  const [searchQuery, setSearchQuery] = useState('');
  
  const handleBuyCrypto = (cryptoId: string) => {
    if (user) {
      navigate(`/buy/${cryptoId}`);
    } else {
      navigate('/login', { state: { redirectAfterLogin: `/buy/${cryptoId}` } });
    }
  };
  
  // Filter cryptocurrencies based on search query
  const filteredCryptos = cryptocurrencies.filter(crypto => 
    crypto.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    crypto.symbol.toLowerCase().includes(searchQuery.toLowerCase())
  );
  
  // Sort cryptocurrencies by market cap
  const sortedByMarketCap = [...filteredCryptos].sort((a, b) => b.marketCap - a.marketCap);
  
  // Sort cryptocurrencies by price change (24h)
  const gainers = [...filteredCryptos].filter(crypto => crypto.priceChange24h > 0)
    .sort((a, b) => b.priceChange24h - a.priceChange24h);
  
  const losers = [...filteredCryptos].filter(crypto => crypto.priceChange24h < 0)
    .sort((a, b) => a.priceChange24h - b.priceChange24h);
  
  // Get watchlist cryptos
  const watchlistCryptos = filteredCryptos.filter(crypto => watchlist.includes(crypto.id));
  
  // This ensures we're logging what cryptocurrencies are available
  console.log('Available cryptocurrencies:', cryptocurrencies.map(crypto => `${crypto.name} (${crypto.symbol})`));
  
  return (
    <div className="container mx-auto px-4 pb-12">
      <div className="pt-8 pb-6">
        <h1 className="text-3xl font-bold mb-2">Cryptocurrency Market</h1>
        <p className="text-muted-foreground">Buy and track the latest cryptocurrency prices</p>
      </div>
      
      <Card className="crypto-card mb-6">
        <CardContent className="p-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search cryptocurrencies..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10 bg-crypto-darker border-gray-700"
            />
          </div>
        </CardContent>
      </Card>
      
      <Card className="crypto-card">
        <CardHeader className="border-b border-gray-800">
          <CardTitle>Cryptocurrency List</CardTitle>
        </CardHeader>
        <CardContent className="p-6">
          <Tabs defaultValue="all">
            <TabsList className="bg-crypto-darker mb-6">
              <TabsTrigger value="all">All</TabsTrigger>
              <TabsTrigger value="gainers">Gainers</TabsTrigger>
              <TabsTrigger value="losers">Losers</TabsTrigger>
              <TabsTrigger value="stablecoins">Stablecoins</TabsTrigger>
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
                <>
                  {sortedByMarketCap.length > 0 ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                      {sortedByMarketCap.map((crypto) => (
                        <CryptoCard 
                          key={crypto.id} 
                          crypto={crypto} 
                          onBuy={() => handleBuyCrypto(crypto.id)} 
                        />
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-8">
                      <p className="text-muted-foreground">No cryptocurrencies match your search.</p>
                    </div>
                  )}
                </>
              )}
            </TabsContent>
            
            <TabsContent value="gainers" className="mt-0">
              {loading ? (
                <div className="py-8 text-center">
                  <p className="animate-pulse text-muted-foreground">Loading gainers...</p>
                </div>
              ) : (
                <>
                  {gainers.length > 0 ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                      {gainers.map((crypto) => (
                        <CryptoCard 
                          key={crypto.id} 
                          crypto={crypto} 
                          onBuy={() => handleBuyCrypto(crypto.id)} 
                        />
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-8">
                      <p className="text-muted-foreground">No gainers found.</p>
                    </div>
                  )}
                </>
              )}
            </TabsContent>
            
            <TabsContent value="losers" className="mt-0">
              {loading ? (
                <div className="py-8 text-center">
                  <p className="animate-pulse text-muted-foreground">Loading losers...</p>
                </div>
              ) : (
                <>
                  {losers.length > 0 ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                      {losers.map((crypto) => (
                        <CryptoCard 
                          key={crypto.id} 
                          crypto={crypto} 
                          onBuy={() => handleBuyCrypto(crypto.id)} 
                        />
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-8">
                      <p className="text-muted-foreground">No losers found.</p>
                    </div>
                  )}
                </>
              )}
            </TabsContent>
            
            <TabsContent value="stablecoins" className="mt-0">
              {loading ? (
                <div className="py-8 text-center">
                  <p className="animate-pulse text-muted-foreground">Loading stablecoins...</p>
                </div>
              ) : (
                <>
                  {filteredCryptos.filter(crypto => crypto.symbol === 'USDT' || crypto.symbol === 'USDC').length > 0 ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                      {filteredCryptos
                        .filter(crypto => crypto.symbol === 'USDT' || crypto.symbol === 'USDC')
                        .map((crypto) => (
                          <CryptoCard 
                            key={crypto.id} 
                            crypto={crypto} 
                            onBuy={() => handleBuyCrypto(crypto.id)} 
                          />
                        ))}
                    </div>
                  ) : (
                    <div className="text-center py-8">
                      <p className="text-muted-foreground">No stablecoins found.</p>
                    </div>
                  )}
                </>
              )}
            </TabsContent>
            
            <TabsContent value="watchlist" className="mt-0">
              {loading ? (
                <div className="py-8 text-center">
                  <p className="animate-pulse text-muted-foreground">Loading watchlist...</p>
                </div>
              ) : (
                <>
                  {watchlistCryptos.length > 0 ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                      {watchlistCryptos.map((crypto) => (
                        <CryptoCard 
                          key={crypto.id} 
                          crypto={crypto} 
                          onBuy={() => handleBuyCrypto(crypto.id)} 
                        />
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-8">
                      <p className="text-muted-foreground">
                        {searchQuery ? "No cryptocurrencies in your watchlist match your search." : "No cryptocurrencies in your watchlist."}
                      </p>
                    </div>
                  )}
                </>
              )}
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default MarketPage;
