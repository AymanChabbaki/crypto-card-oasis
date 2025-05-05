
import React from 'react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Heart } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useCrypto } from '@/contexts/CryptoContext';
import type { Cryptocurrency } from '@/types/crypto';

interface CryptoCardProps {
  crypto: Cryptocurrency;
  onBuy?: () => void;
}

const CryptoCard: React.FC<CryptoCardProps> = ({ crypto, onBuy }) => {
  const { watchlist, addToWatchlist, removeFromWatchlist } = useCrypto();
  const isInWatchlist = watchlist.includes(crypto.id);
  
  const formatPrice = (price: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: price < 1 ? 4 : 2,
      maximumFractionDigits: price < 1 ? 4 : 2
    }).format(price);
  };

  const formatPercentage = (percentage: number) => {
    return `${percentage > 0 ? '+' : ''}${percentage.toFixed(2)}%`;
  };

  const formatVolume = (volume: number) => {
    if (volume >= 1e9) {
      return `$${(volume / 1e9).toFixed(2)}B`;
    }
    if (volume >= 1e6) {
      return `$${(volume / 1e6).toFixed(2)}M`;
    }
    return `$${volume.toFixed(2)}`;
  };

  const handleWatchlistToggle = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (isInWatchlist) {
      removeFromWatchlist(crypto.id);
    } else {
      addToWatchlist(crypto.id);
    }
  };

  // Special handling for stablecoins to display appropriate price change colors
  const isStablecoin = crypto.symbol === 'USDT' || crypto.symbol === 'USDC';
  const getPriceChangeClass = (percentage: number) => {
    if (isStablecoin && Math.abs(percentage) < 0.1) {
      return "text-gray-400"; // Neutral color for minimal changes in stablecoins
    }
    return percentage > 0 ? "text-crypto-green" : "text-crypto-red";
  };

  return (
    <div className="group">
      <Card className="crypto-card overflow-hidden hover:shadow-md hover:shadow-crypto-accent/5 transition-all duration-300">
        <div className="p-4 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 rounded-full bg-gray-700 flex items-center justify-center overflow-hidden">
              {crypto.image ? (
                <img src={crypto.image} alt={crypto.name} className="h-10 w-10 object-cover" />
              ) : (
                <span className="text-lg font-bold">{crypto.symbol.charAt(0)}</span>
              )}
            </div>
            <div>
              <h3 className="font-medium">{crypto.name}</h3>
              <p className="text-sm text-muted-foreground">{crypto.symbol}</p>
            </div>
          </div>
          
          <Button 
            variant="ghost"
            size="icon"
            className={cn(
              "opacity-0 group-hover:opacity-100 transition-opacity",
              isInWatchlist && "text-red-500 opacity-100"
            )}
            onClick={handleWatchlistToggle}
          >
            <Heart 
              size={18} 
              className={isInWatchlist ? "fill-red-500" : ""} 
            />
          </Button>
        </div>
        
        <div className="px-4 pb-2">
          <div className="text-xl font-semibold">{formatPrice(crypto.price)}</div>
          <div className="grid grid-cols-3 gap-2 my-3">
            <div>
              <p className="text-xs text-muted-foreground">1h</p>
              <p className={cn(
                "text-sm font-medium",
                getPriceChangeClass(crypto.priceChange1h)
              )}>
                {formatPercentage(crypto.priceChange1h)}
              </p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">24h</p>
              <p className={cn(
                "text-sm font-medium",
                getPriceChangeClass(crypto.priceChange24h)
              )}>
                {formatPercentage(crypto.priceChange24h)}
              </p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">7d</p>
              <p className={cn(
                "text-sm font-medium",
                getPriceChangeClass(crypto.priceChange7d)
              )}>
                {formatPercentage(crypto.priceChange7d)}
              </p>
            </div>
          </div>
          
          <div className="flex justify-between items-center mb-3">
            <div>
              <p className="text-xs text-muted-foreground">Volume (24h)</p>
              <p className="text-sm">{formatVolume(crypto.volume24h)}</p>
            </div>
            <div className="text-right">
              <p className="text-xs text-muted-foreground">Market Cap</p>
              <p className="text-sm">{formatVolume(crypto.marketCap)}</p>
            </div>
          </div>
          
          <Button 
            className="w-full bg-crypto-accent hover:bg-crypto-accent/80 text-black" 
            onClick={onBuy}
          >
            Buy
          </Button>
        </div>
      </Card>
    </div>
  );
};

export default CryptoCard;
