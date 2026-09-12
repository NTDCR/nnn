import React, { useState } from 'react';
import { runSelfVerificationTests, TestVectorResult } from '../crypto/testVectors.ts';
import { CheckCircle2, XCircle, Play, ShieldAlert, BookOpen, Terminal } from 'lucide-react';

export const VerificationPanel: React.FC = () => {
  const [isRunning, setIsRunning] = useState(false);
  const [results, setResults] = useState<TestVectorResult[] | null>(null);

  const handleRunTests = async () => {
    setIsRunning(true);
    try {
      const testResults = await runSelfVerificationTests();
      setResults(testResults);
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div id="crypto-verification-panel" className="rounded-2xl bg-slate-900/90 border border-slate-800 p-5 md:p-6 shadow-xl backdrop-blur-sm">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <Terminal className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              Cryptographic Integrity & Library Verification
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-950 border border-emerald-800 text-emerald-400 font-mono">
                Cure53 Audited / NIST / RFC
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              Live browser execution of @noble/ciphers, @noble/post-quantum, @noble/hashes, and WebCrypto AES-NI
            </p>
          </div>
        </div>

        <button
          id="run-test-vectors-btn"
          onClick={handleRunTests}
          disabled={isRunning}
          className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-semibold shadow-sm transition cursor-pointer"
        >
          <Play className="w-3.5 h-3.5 fill-current" />
          {isRunning ? 'Verifying Suites...' : 'Run All Test Vectors'}
        </button>
      </div>

      {/* Results List */}
      {results ? (
        <div className="mt-4 space-y-2.5">
          {results.map((res, idx) => (
            <div
              key={idx}
              className={`p-3.5 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-2 font-mono text-xs ${
                res.passed
                  ? 'bg-emerald-950/20 border-emerald-800/40 text-emerald-300'
                  : 'bg-rose-950/20 border-rose-800/40 text-rose-300'
              }`}
            >
              <div className="flex items-start sm:items-center gap-2.5">
                {res.passed ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5 sm:mt-0" />
                ) : (
                  <XCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5 sm:mt-0" />
                )}
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-slate-400 text-[10px] uppercase tracking-wider">{res.suite}</span>
                    <strong className="text-white font-medium">{res.name}</strong>
                  </div>
                  <div className="text-[11px] text-slate-400 mt-0.5 truncate max-w-md">
                    Tag: {res.actualHex}
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-3 text-right shrink-0">
                <span className="text-[11px] text-slate-500">{res.executionTimeMs} ms</span>
                <span
                  className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                    res.passed ? 'bg-emerald-900/60 text-emerald-200' : 'bg-rose-900/60 text-rose-200'
                  }`}
                >
                  {res.passed ? 'PASSED' : 'FAILED'}
                </span>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="mt-4 p-4 rounded-xl bg-slate-950/40 border border-slate-800 text-center text-xs text-slate-500">
          Click &ldquo;Run All Test Vectors&rdquo; to execute the test suite in real-time.
        </div>
      )}

      {/* Security note */}
      <div className="mt-4 pt-4 border-t border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px] text-slate-400">
        <div className="flex items-center gap-1.5">
          <ShieldAlert className="w-3.5 h-3.5 text-indigo-400" />
          <span>Constant-time comparison with generic error masking prevents side-channel leakage.</span>
        </div>
        <div className="flex items-center gap-1.5 font-mono text-slate-500">
          <BookOpen className="w-3.5 h-3.5" />
          <span>FIPS 197 / FIPS 203 / FIPS 204 / RFC 8439</span>
        </div>
      </div>
    </div>
  );
};
