
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { AuthProvider } from '@/contexts/AuthContext';
import { CryptoProvider } from '@/contexts/CryptoContext';
import Navbar from '@/components/Navbar';
import HomePage from "./pages/HomePage";
import LoginPage from "./pages/LoginPage";
import RegisterPage from "./pages/RegisterPage";
import DashboardPage from "./pages/DashboardPage";
import AdminPage from "./pages/AdminPage";
import MarketPage from "./pages/MarketPage";
import BuyCryptoPage from "./pages/BuyCryptoPage";
import DepositPage from "./pages/DepositPage";
import WithdrawPage from "./pages/WithdrawPage";
import PendingTransactionPage from "./pages/PendingTransactionPage";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <AuthProvider>
      <CryptoProvider>
        <TooltipProvider>
          <Toaster />
          <Sonner />
          <BrowserRouter>
            <div className="min-h-screen flex flex-col bg-crypto-gradient">
              <Navbar />
              <main className="flex-grow">
                <Routes>
                  <Route path="/" element={<HomePage />} />
                  <Route path="/login" element={<LoginPage />} />
                  <Route path="/register" element={<RegisterPage />} />
                  <Route path="/dashboard" element={<DashboardPage />} />
                  <Route path="/admin" element={<AdminPage />} />
                  <Route path="/market" element={<MarketPage />} />
                  <Route path="/buy/:cryptoId" element={<BuyCryptoPage />} />
                  <Route path="/dashboard/deposit" element={<DepositPage />} />
                  <Route path="/dashboard/withdraw" element={<WithdrawPage />} />
                  <Route path="/transaction/pending" element={<PendingTransactionPage />} />
                  <Route path="*" element={<NotFound />} />
                </Routes>
              </main>
              <footer className="bg-crypto-darker py-6 border-t border-gray-800">
                <div className="container mx-auto px-4">
                  <p className="text-center text-muted-foreground text-sm">
                    &copy; {new Date().getFullYear()} CryptoCard Oasis. All rights reserved.
                  </p>
                </div>
              </footer>
            </div>
          </BrowserRouter>
        </TooltipProvider>
      </CryptoProvider>
    </AuthProvider>
  </QueryClientProvider>
);

export default App;
