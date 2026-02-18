'use client';

import { useState } from 'react';

const StarField = () => (
  <div className="absolute inset-0">
    {[...Array(5)].map((_, i) => (
      <div
        key={i}
        className="absolute w-1 h-1 bg-white rounded-full animate-pulse"
        style={{
          top: `${10 + i * 15}%`,
          left: `${20 + (i % 2) * 30}%`,
          animationDelay: `${i * 75}ms`
        }}
      />
    ))}
  </div>
);

const Moon = () => (
  <div className="absolute top-20 right-20 w-32 h-32 bg-white rounded-full shadow-2xl shadow-white/50">
    <div className="absolute top-4 left-6 w-4 h-4 bg-gray-200 rounded-full opacity-50" />
    <div className="absolute bottom-8 right-4 w-3 h-3 bg-gray-200 rounded-full opacity-30" />
  </div>
);

const DesertDunes = () => (
  <div className="absolute bottom-0 left-0 right-0 h-96">
    <div className="absolute bottom-0 left-0 right-0 h-64 bg-gradient-to-t from-gray-300 to-gray-200 rounded-t-full transform scale-150 origin-bottom" />
    <div className="absolute bottom-0 left-0 right-0 h-48 bg-gradient-to-t from-gray-400 to-gray-300 rounded-t-full transform scale-125 origin-bottom" />
    <div className="absolute bottom-0 left-0 right-0 h-32 bg-gradient-to-t from-gray-500 to-gray-400 rounded-t-full" />
  </div>
);

const HollowMasks = () => (
  <>
    <div className="absolute bottom-20 left-10 opacity-20">
      <div className="w-24 h-32 bg-white rounded-t-full" />
    </div>
    <div className="absolute bottom-32 right-16 opacity-15">
      <div className="w-16 h-20 bg-white rounded-t-full" />
    </div>
  </>
);

const Modal = ({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => {
  if (!isOpen) return null;
  
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-gray-900 p-8 rounded-lg max-w-2xl mx-4 border border-gray-700">
        <h2 className="text-3xl font-bold text-white mb-4">About Hueco Mundo</h2>
        <p className="text-gray-300 mb-6">
          Hueco Mundo is the vast desert realm where Hollows reside. This endless white desert exists between the Human World and Soul Society, 
          characterized by its perpetual night and white sand dunes stretching as far as the eye can see.
        </p>
        <button 
          onClick={onClose}
          className="px-6 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700 transition-colors"
        >
          Close
        </button>
      </div>
    </div>
  );
};

export default function Home() {
  const [showModal, setShowModal] = useState(false);
  return (
    <>
      <div className="min-h-screen bg-gradient-to-b from-slate-900 via-gray-900 to-black relative overflow-hidden">
        <StarField />
        <Moon />
        <DesertDunes />
        
        <main className="relative z-10 flex min-h-screen flex-col items-center justify-center px-8 text-center">
          <div className="max-w-4xl mx-auto">
            <h1 className="text-6xl md:text-8xl font-bold text-white mb-6 tracking-wider" style={{ textShadow: '0 0 20px rgba(255,255,255,0.5)' }}>
              HUECO MUNDO
            </h1>
            <p className="text-xl md:text-2xl text-gray-300 mb-8 font-light leading-relaxed">
              The Desert World of Hollows
            </p>
            <p className="text-lg text-gray-400 mb-12 max-w-2xl mx-auto">
              An endless white desert under an eternal moon. Where the hollows roam and the shadows dance.
            </p>
            
            <div className="flex flex-col sm:flex-row gap-6 justify-center items-center">
              <button 
                onClick={() => window.location.href = '/desert'}
                className="px-8 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white font-bold rounded-lg hover:from-orange-700 hover:to-red-700 transition-all duration-300 transform hover:scale-105 shadow-xl"
              >
                Enter the Desert
              </button>
              <button 
                onClick={() => setShowModal(true)}
                className="px-8 py-4 border-2 border-white text-white font-semibold rounded-lg hover:bg-white hover:text-black transition-all duration-300 transform hover:scale-105"
              >
                Learn More
              </button>
            </div>
            
            <HollowMasks />
          </div>
        </main>
        
        <Modal isOpen={showModal} onClose={() => setShowModal(false)} />
      </div>
    </>
  );
}