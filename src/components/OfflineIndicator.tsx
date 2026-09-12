import React from 'react';
import { useOnlineStatus } from '../hooks/useOnlineStatus.ts';
import { WifiOff } from 'lucide-react';

export const OfflineIndicator: React.FC = () => {
  const isOnline = useOnlineStatus();

  if (isOnline) return null;

  return (
    <div
      id="offline-banner"
      className="fixed bottom-4 left-4 z-50 flex items-center gap-2 rounded-lg bg-amber-600/90 border border-amber-500/40 px-3.5 py-2 text-xs font-medium text-white shadow-2xl backdrop-blur-md animate-fade-in"
    >
      <WifiOff className="w-4 h-4 text-amber-200" />
      <span>Offline Mode — Running entirely locally via WebCrypto and in-browser crypto engine.</span>
    </div>
  );
};
