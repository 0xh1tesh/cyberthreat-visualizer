import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  X,
  Loader,
  AlertTriangle,
  Zap,
  Shield,
  ChevronRight,
  Cpu,
  CheckCircle,
  AlertCircle,
} from 'lucide-react';

const ThreatReportModal = ({ threat, isOpen, onClose, aiProvider = 'auto' }) => {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const normalizeSourceStatus = (sourceStatus = {}) => {
    const readStatus = (key) => {
      const normalized = String(sourceStatus?.[key] || '').toLowerCase();
      return normalized === 'ok' ? 'ok' : 'failed';
    };

    return {
      abuseipdb: readStatus('abuseipdb'),
      otx: readStatus('otx'),
      shodan: readStatus('shodan'),
    };
  };

  const getSignalDisplayMeta = (value, sourceKey, sourceStatus = {}) => {
    const normalizedStatus = normalizeSourceStatus(sourceStatus);
    const sourceLabels = {
      abuseipdb: 'AbuseIPDB',
      otx: 'OTX',
      shodan: 'Shodan',
    };

    if (normalizedStatus[sourceKey] !== 'ok') {
      return {
        text: '0 (no data)',
        faded: true,
        tooltip: `${sourceLabels[sourceKey] || sourceKey} unavailable`,
      };
    }

    const numeric = Number(value);
    return {
      text: Number.isFinite(numeric) ? numeric.toFixed(0) : '0',
      faded: false,
      tooltip: '',
    };
  };

  const getAiSummaryUnavailableMessage = (aiSummary) => {
    const reasonCode = String(aiSummary?.reason_code || '').toLowerCase();
    if (reasonCode === 'no_provider') {
      if (aiProvider === 'off') {
        return 'AI generation is disabled. Switch AI mode from Off to Auto, OpenAI, or Gemini.';
      }
      return 'No usable AI provider is configured for the selected mode. Check provider keys and mode settings.';
    }
    if (reasonCode === 'timeout') {
      return 'AI generation timed out. Retry once or increase report timeout in backend configuration.';
    }
    if (reasonCode === 'upstream_http_error') {
      return 'The AI provider rejected this request. Verify API key status, quota, and model access.';
    }
    if (reasonCode === 'schema_mismatch') {
      return 'The AI provider replied, but response format validation failed. Retry to generate a fresh summary.';
    }
    if (reasonCode === 'network_error') {
      return 'Network error while reaching the AI provider. Check backend connectivity and retry.';
    }
    return 'AI summary is unavailable right now. Check provider configuration and try again.';
  };

  const mapThreatForReport = (rawThreat) => {
    if (!rawThreat || typeof rawThreat !== 'object') return null;

    const signalSources = Array.isArray(rawThreat?.signals?.usedSources)
      ? rawThreat.signals.usedSources
      : Array.isArray(rawThreat?.signals?.sourcesUsed)
        ? rawThreat.signals.sourcesUsed
        : [];

    const sourceStatus = normalizeSourceStatus(
      rawThreat?.sources || rawThreat?.signals?.sourceStatus || {}
    );

    return {
      sourceIp: String(rawThreat?.origin?.ip || rawThreat?.sourceIp || rawThreat?.ip || ''),
      sourceCountry: String(rawThreat?.origin?.country || rawThreat?.sourceCountry || ''),
      targetCountry: String(rawThreat?.target?.country || rawThreat?.targetCountry || ''),
      timestamp: rawThreat?.timestamp
        ? new Date(rawThreat.timestamp).getTime()
        : Date.now(),
      classification: String(rawThreat?.classification || 'LOW'),
      score: Number.isFinite(rawThreat?.score) ? rawThreat.score : 0,
      signals: {
        abuseScore: typeof rawThreat?.signals?.abuseScore === 'number' ? rawThreat.signals.abuseScore : 0,
        otxHits: typeof rawThreat?.signals?.otxHits === 'number' ? rawThreat.signals.otxHits : 0,
        portExposure: typeof rawThreat?.signals?.portExposure === 'number' ? rawThreat.signals.portExposure : 0,
        usedSources: signalSources,
        sourcesUsed: signalSources,
        sourceStatus,
      },
      sources: sourceStatus,
      ai: {
        used: Boolean(rawThreat?.ai?.used),
        confidence: typeof rawThreat?.ai?.confidence === 'number' ? rawThreat.ai.confidence : null,
        reason: rawThreat?.ai?.reason ? String(rawThreat.ai.reason) : null,
      },
    };
  };

  useEffect(() => {
    if (!isOpen || !threat) {
      setReport(null);
      setError(null);
      return;
    }

    const fetchReport = async () => {
      setLoading(true);
      setError(null);

      try {
        const headers = {
          'Content-Type': 'application/json',
          'X-AI-Provider': aiProvider,
        };

        const threatPayload = mapThreatForReport(threat);
        if (!threatPayload) {
          throw new Error('Invalid threat payload');
        }

        const response = await fetch('http://localhost:5000/api/report', {
          method: 'POST',
          headers,
          body: JSON.stringify({
            threat: threatPayload,
            provider: aiProvider,
            mode: aiProvider,
          }),
        });

        if (!response.ok) {
          throw new Error(`API error: ${response.status}`);
        }

        const data = await response.json();
        setReport(data);
      } catch (err) {
        setError(err.message || 'Failed to fetch report');
      } finally {
        setLoading(false);
      }
    };

    fetchReport();
  }, [isOpen, threat, aiProvider]);

  const getRiskLevelColor = (riskLevel) => {
    if (!riskLevel) return 'text-slate-400';
    const level = String(riskLevel).toUpperCase();
    if (level === 'CRITICAL') return 'text-red-400';
    if (level === 'HIGH') return 'text-orange-400';
    if (level === 'MEDIUM') return 'text-yellow-400';
    return 'text-green-400';
  };

  const getRiskLevelBgColor = (riskLevel) => {
    if (!riskLevel) return 'bg-slate-600/20';
    const level = String(riskLevel).toUpperCase();
    if (level === 'CRITICAL') return 'bg-red-600/20';
    if (level === 'HIGH') return 'bg-orange-600/20';
    if (level === 'MEDIUM') return 'bg-yellow-600/20';
    return 'bg-green-600/20';
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40"
          />

          {/* Modal */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 20 }}
            transition={{ duration: 0.3 }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
          >
            <div className="bg-slate-900 border border-slate-700/50 rounded-lg shadow-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
              {/* Header */}
              <div className="sticky top-0 bg-slate-900 border-b border-slate-700/30 p-6 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Cpu className="w-5 h-5 text-cyber-blue" />
                  <h2 className="text-lg font-semibold text-slate-100">
                    Threat Report
                  </h2>
                </div>
                <button
                  onClick={onClose}
                  className="p-1 hover:bg-slate-800 rounded transition-colors"
                >
                  <X className="w-5 h-5 text-slate-400" />
                </button>
              </div>

              {/* Content */}
              <div className="p-6 space-y-6">
                {loading && (
                  <div className="flex items-center justify-center py-12">
                    <Loader className="w-6 h-6 text-cyber-blue animate-spin" />
                  </div>
                )}

                {error && (
                  <div className="p-4 bg-red-600/20 border border-red-500/50 rounded-lg flex gap-3">
                    <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-sm text-red-200 font-medium">Error Loading Report</p>
                      <p className="text-xs text-red-300/70 mt-1">{error}</p>
                    </div>
                  </div>
                )}

                {report && !loading && (
                  <>
                    {/* Threat Basics */}
                    <div className="space-y-4">
                      <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
                        Threat Details
                      </h3>
                      <div className="grid grid-cols-2 gap-4">
                        <div className="bg-slate-800/40 border border-slate-700/30 rounded p-4">
                          <p className="text-xs text-slate-400 mb-1">IP Address</p>
                          <p className="text-sm font-mono text-cyber-blue">{report.ip || 'N/A'}</p>
                        </div>
                        <div className="bg-slate-800/40 border border-slate-700/30 rounded p-4">
                          <p className="text-xs text-slate-400 mb-1">Classification</p>
                          <p className="text-sm font-semibold text-slate-200">
                            {report.classification || 'LOW'}
                          </p>
                        </div>
                        <div className="bg-slate-800/40 border border-slate-700/30 rounded p-4">
                          <p className="text-xs text-slate-400 mb-1">Threat Score</p>
                          <p className="text-sm font-semibold text-slate-200">
                            {Number.isFinite(report.score) ? report.score.toFixed(1) : 'N/A'}
                          </p>
                        </div>
                        <div className="bg-slate-800/40 border border-slate-700/30 rounded p-4">
                          <p className="text-xs text-slate-400 mb-1">Timestamp</p>
                          <p className="text-xs text-slate-300">
                            {report.timestamp
                              ? new Date(report.timestamp).toLocaleString()
                              : 'N/A'}
                          </p>
                        </div>
                      </div>
                    </div>

                    {/* Signals */}
                    <div className="space-y-4">
                      <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
                        Signal Analysis
                      </h3>
                      {(() => {
                        const sourceStatus = normalizeSourceStatus(
                          report?.sources_status || report?.signals?.sourceStatus || {}
                        );
                        const degradedSources = Object.entries(sourceStatus)
                          .filter((entry) => entry[1] !== 'ok')
                          .map((entry) => entry[0]);
                        if (degradedSources.length === 0) return null;
                        return (
                          <div className="text-[10px] text-amber-300 font-mono uppercase tracking-[0.08em]" title="One or more threat intelligence providers are unavailable">
                            DEGRADED DATA
                          </div>
                        );
                      })()}
                      <div className="grid grid-cols-3 gap-3">
                        <div className="bg-slate-800/40 border border-slate-700/30 rounded p-3">
                          <p className="text-xs text-slate-400 mb-2">Abuse Score</p>
                          {(() => {
                            const meta = getSignalDisplayMeta(
                              report.signals?.abuseScore,
                              'abuseipdb',
                              report?.sources_status || report?.signals?.sourceStatus || {}
                            );
                            return (
                              <p title={meta.tooltip} className={`text-lg font-semibold ${meta.faded ? 'text-slate-500 italic' : 'text-amber-400'}`}>
                                {meta.text}
                              </p>
                            );
                          })()}
                        </div>
                        <div className="bg-slate-800/40 border border-slate-700/30 rounded p-3">
                          <p className="text-xs text-slate-400 mb-2">OTX Hits</p>
                          {(() => {
                            const meta = getSignalDisplayMeta(
                              report.signals?.otxHits,
                              'otx',
                              report?.sources_status || report?.signals?.sourceStatus || {}
                            );
                            return (
                              <p title={meta.tooltip} className={`text-lg font-semibold ${meta.faded ? 'text-slate-500 italic' : 'text-violet-400'}`}>
                                {meta.text}
                              </p>
                            );
                          })()}
                        </div>
                        <div className="bg-slate-800/40 border border-slate-700/30 rounded p-3">
                          <p className="text-xs text-slate-400 mb-2">Open Ports</p>
                          {(() => {
                            const meta = getSignalDisplayMeta(
                              report.signals?.portExposure,
                              'shodan',
                              report?.sources_status || report?.signals?.sourceStatus || {}
                            );
                            return (
                              <p title={meta.tooltip} className={`text-lg font-semibold ${meta.faded ? 'text-slate-500 italic' : 'text-cyan-400'}`}>
                                {meta.text}
                              </p>
                            );
                          })()}
                        </div>
                      </div>
                      {Array.isArray(report.sources) && report.sources.length > 0 && (
                        <div className="text-xs text-slate-400">
                          Sources: <span className="text-slate-300">{report.sources.join(', ')}</span>
                        </div>
                      )}
                    </div>

                    {/* AI Summary Section */}
                    {report.ai_summary && (
                      <div className="space-y-4 border-t border-slate-700/30 pt-6">
                        <div className="flex items-center gap-2">
                          <Zap className="w-4 h-4 text-cyber-blue" />
                          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
                            AI Incident Summary
                          </h3>
                          {report.ai_summary.used ? (
                            <span className="text-xs px-2 py-1 bg-cyber-blue/20 border border-cyber-blue/50 text-cyber-blue rounded">
                              AI Generated
                            </span>
                          ) : (
                            <span className="text-xs px-2 py-1 bg-slate-600/30 border border-slate-600/50 text-slate-400 rounded">
                              Unavailable
                            </span>
                          )}
                        </div>

                        {report.ai_summary.used ? (
                          <div className="space-y-4">
                            {report.ai_summary.provider && (
                              <div className="text-xs text-slate-400">
                                Provider: <span className="text-cyber-blue uppercase">{report.ai_summary.provider}</span>
                              </div>
                            )}

                            {/* Risk Level */}
                            {report.ai_summary.risk_level && (
                              <div className={`p-4 rounded-lg border ${getRiskLevelBgColor(
                                report.ai_summary.risk_level
                              )} border-current/30`}>
                                <p className="text-xs text-slate-400 mb-1">Risk Level</p>
                                <p className={`text-sm font-semibold ${getRiskLevelColor(
                                  report.ai_summary.risk_level
                                )}`}>
                                  {report.ai_summary.risk_level}
                                </p>
                              </div>
                            )}

                            {/* Executive Summary */}
                            {report.ai_summary.executive_summary && (
                              <div className="bg-slate-800/40 border border-slate-700/30 rounded-lg p-4">
                                <p className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                                  Executive Summary
                                </p>
                                <p className="text-sm text-slate-300 leading-relaxed">
                                  {report.ai_summary.executive_summary}
                                </p>
                              </div>
                            )}

                            {/* Technical Analysis */}
                            {report.ai_summary.technical_analysis && (
                              <div className="bg-slate-800/40 border border-slate-700/30 rounded-lg p-4">
                                <p className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                                  Technical Analysis
                                </p>
                                <p className="text-sm text-slate-300 leading-relaxed">
                                  {report.ai_summary.technical_analysis}
                                </p>
                              </div>
                            )}

                            {/* Recommended Action */}
                            {report.ai_summary.recommended_action && (
                              <div className="bg-slate-800/40 border border-slate-700/30 rounded-lg p-4">
                                <p className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2 flex items-center gap-2">
                                  <Shield className="w-4 h-4 text-green-400" />
                                  Recommended Action
                                </p>
                                <p className="text-sm text-slate-300 leading-relaxed">
                                  {report.ai_summary.recommended_action}
                                </p>
                              </div>
                            )}
                          </div>
                        ) : (
                          <div className="p-4 bg-slate-800/40 border border-slate-700/30 rounded-lg">
                            <p className="text-sm text-slate-400">
                              {getAiSummaryUnavailableMessage(report.ai_summary)}
                            </p>
                            {report.ai_summary.reason_detail && (
                              <p className="text-xs text-slate-500 mt-2 font-mono">
                                Detail: {report.ai_summary.reason_detail}
                              </p>
                            )}
                            {Array.isArray(report.ai_summary.attempted_providers) && report.ai_summary.attempted_providers.length > 0 && (
                              <p className="text-xs text-slate-500 mt-1 font-mono">
                                Attempted: {report.ai_summary.attempted_providers.join(', ')}
                              </p>
                            )}
                          </div>
                        )}
                      </div>
                    )}

                    {/* Rule-Based AI if available */}
                    {report.ai && (
                      <div className="border-t border-slate-700/30 pt-6 space-y-3">
                        <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                          Threat Classification
                        </h3>
                        <div className="bg-slate-800/40 border border-slate-700/30 rounded-lg p-4 space-y-2">
                          <div className="flex justify-between items-center">
                            <span className="text-xs text-slate-400">Method</span>
                            <span className="text-sm font-semibold text-slate-300">
                              {report.ai.used ? 'AI Assisted' : 'Rule-Based'}
                            </span>
                          </div>
                          {report.ai.confidence > 0 && (
                            <div className="flex justify-between items-center">
                              <span className="text-xs text-slate-400">Confidence</span>
                              <span className="text-sm font-semibold text-cyber-blue">
                                {report.ai.confidence.toFixed(0)}%
                              </span>
                            </div>
                          )}
                          {report.ai.reasoning && (
                            <div className="pt-2 border-t border-slate-700/30">
                              <p className="text-xs text-slate-400 mb-1">Reasoning</p>
                              <p className="text-xs text-slate-300">{report.ai.reasoning}</p>
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </>
                )}
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
};

export default ThreatReportModal;
