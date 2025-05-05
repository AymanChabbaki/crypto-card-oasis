
import { useState, useEffect } from 'react';

export const useWatchlistStorage = () => {
  const [watchlist, setWatchlist] = useState<string[]>([]);

  // Load watchlist on initial mount
  useEffect(() => {
    const savedWatchlist = localStorage.getItem('cryptoWatchlist');
    if (savedWatchlist) {
      setWatchlist(JSON.parse(savedWatchlist));
    }
  }, []);

  // Save watchlist to localStorage on any change
  useEffect(() => {
    localStorage.setItem('cryptoWatchlist', JSON.stringify(watchlist));
  }, [watchlist]);

  const addToWatchlist = (cryptoId: string) => {
    if (!watchlist.includes(cryptoId)) {
      setWatchlist((prev) => [...prev, cryptoId]);
    }
  };

  const removeFromWatchlist = (cryptoId: string) => {
    setWatchlist((prev) => prev.filter(id => id !== cryptoId));
  };

  return {
    watchlist,
    setWatchlist,
    addToWatchlist,
    removeFromWatchlist
  };
};
