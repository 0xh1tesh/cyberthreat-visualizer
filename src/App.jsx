import React, { Suspense, lazy, useCallback, useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Globe2, LayoutGrid, ListChecks, RefreshCw, WifiOff } from 'lucide-react';
import Header from './components/Header';
import StatusBar from './components/StatusBar';
import Overview from './components/Overview';
import ThreatFeed from './components/ThreatFeed';
import ThreatReportModal from './components/ThreatReportModal';
import { ScenarioDetails, SimulationControls } from './components/SimulationPanels';
import { ClassMix, ObservationsTimeline, PhaseIntensity } from './components/Analytics';
import { Segmented } from './components/ui';
import { useThreatFeed } from './hooks/useThreatFeed';
import { useSimulation } from './hooks/useSimulation';
import { useThreatAnalysis } from './hooks/useThreatAnalysis';
import { useLayoutMode } from './hooks/useMediaQuery';
import { toNewThreat } from './lib/threat-normalize';
import { CLASS_META, CLASS_ORDER } from './lib/palette';
import { cn } from './lib/utils';

const GlobeView = lazy(() => import('./components/GlobeView'));

const PROVIDER_KEY = 'threat-globe:ai-provider';
const VALID_PROVIDERS = ['auto', 'gemini', 'openai', 'off'];

const readStoredProvider = () => {
  try {
    const stored = localStorage.getItem(PROVIDER_KEY);
    return VALID_PROVIDERS.includes(stored) ? stored : 'auto';
  } catch {
    return 'auto';
  }
};

const DEGRADED_REASONS = {
  'daily-threshold': 'the AbuseIPDB daily quota is used up',
  disabled: 'no AbuseIPDB key is configured',
  'rate-limited': 'AbuseIPDB is rate limiting requests',
};

const describeDegraded = (reason) =>
  DEGRADED_REASONS[reason] || 'the AbuseIPDB blacklist is unavailable';

const Banner = ({ tone = 'warn', icon: Icon, children, action }) => (
  <div
    role={tone === 'crit' ? 'alert' : 'status'}
    className={cn(
      'flex items-center gap-2.5 rounded-lg border px-3 py-2 text-xs backdrop-blur-0',
      tone === 'crit' && 'border-crit/30 bg-canvas text-crit',
      tone === 'warn' && 'border-warn/30 bg-canvas text-warn',
      tone === 'info' && 'border-info/30 bg-canvas text-info',
    )}
  >
    <Icon size={14} className="shrink-0" aria-hidden="true" />
    <span className="min-w-0 flex-1 text-ink">{children}</span>
    {action}
  </div>
);

const Legend = () => (
  <ul className="flex flex-wrap items-center gap-x-4 gap-y-1 rounded-lg border border-line bg-canvas px-3 py-2" aria-label="Severity legend">
    {CLASS_ORDER.map((key) => (
      <li key={key} className="flex items-center gap-1.5 text-2xs text-ink-muted">
        <span className="size-2 rounded-full" style={{ background: CLASS_META[key].color }} aria-hidden="true" />
        {CLASS_META[key].label}
      </li>
    ))}
  </ul>
);

const App = () => {
  const layout = useLayoutMode();
  const [mode, setMode] = useState('live');
  const [provider, setProvider] = useState(readStoredProvider);
  const [filter, setFilter] = useState('ALL');
  const [selectedId, setSelectedId] = useState(null);
  const [hoveredId, setHoveredId] = useState(null);
  const [reportThreat, setReportThreat] = useState(null);
  const [compactView, setCompactView] = useState('globe');
  const [sideTab, setSideTab] = useState('feed');

  const live = mode === 'live';
  const feed = useThreatFeed({ enabled: live, provider });
  const sim = useSimulation({ active: !live });
  const { reset: resetSim } = sim;
  const analysis = useThreatAnalysis(provider);

  useEffect(() => {
    try {
      localStorage.setItem(PROVIDER_KEY, provider);
    } catch {
      // storage unavailable (private mode); the choice simply is not remembered
    }
  }, [provider]);

  const attacks = useMemo(() => {
    if (!live) return sim.arcs;
    if (filter === 'ALL') return feed.attacks;
    return feed.attacks.filter((attack) => String(attack.classification).toUpperCase() === filter);
  }, [live, sim.arcs, feed.attacks, filter]);

  const threats = useMemo(() => attacks.map(toNewThreat), [attacks]);
  const allLiveThreats = useMemo(() => feed.attacks.map(toNewThreat), [feed.attacks]);

  const handleModeChange = useCallback((next) => {
    if (next === mode) return;
    setMode(next);
    setSelectedId(null);
    setHoveredId(null);
    setFilter('ALL');
    if (next === 'simulation') resetSim();
  }, [mode, resetSim]);

  const handleSelect = useCallback((id) => setSelectedId((current) => (current === id ? null : id)), []);
  const handleReport = useCallback((threat) => setReportThreat(threat), []);
  const closeReport = useCallback(() => setReportThreat(null), []);

  const handleGlobeClick = useCallback((arc) => {
    setSelectedId(arc.id);
    setReportThreat(toNewThreat(arc));
  }, []);

  const sortedForOverview = live ? allLiveThreats : threats;

  const feedNode = (
    <ThreatFeed
      className="flex h-full flex-col"
      threats={live ? allLiveThreats : []}
      status={feed.status}
      filter={filter}
      onFilterChange={setFilter}
      selectedId={selectedId}
      hoveredId={hoveredId}
      analysisStates={analysis.states}
      onSelect={handleSelect}
      onHover={setHoveredId}
      onReport={handleReport}
      onAnalyze={analysis.analyze}
      onRetry={feed.refresh}
    />
  );

  const overviewNode = live ? (
    <Overview
      threats={sortedForOverview}
      health={feed.health}
      aiHealth={feed.aiHealth}
      provider={provider}
      onProviderChange={setProvider}
      status={feed.status}
    />
  ) : (
    <ScenarioDetails sim={sim} />
  );

  const sideNode = live ? feedNode : <SimulationControls sim={sim} className="h-full" />;

  const analyticsNode = live ? (
    <div className="grid min-h-0 grid-cols-1 gap-3 sm:grid-cols-[minmax(0,1fr)_260px]">
      <ObservationsTimeline observations={feed.history} className="h-[200px]" />
      <ClassMix threats={allLiveThreats} className="hidden sm:block" />
    </div>
  ) : (
    <PhaseIntensity steps={sim.steps} stepIndex={sim.stepIndex} onSelect={sim.goToStep} className="h-[200px]" />
  );

  const banners = (
    <div className="pointer-events-none absolute inset-x-3 top-3 z-10 flex flex-col gap-2 [&>*]:pointer-events-auto">
      {!live && (
        <Banner tone="info" icon={Globe2}>
          <strong className="font-medium">Simulation</strong> · a historical scenario replay with illustrative routes, not live telemetry.
        </Banner>
      )}
      {live && feed.status === 'offline' && (
        <Banner
          tone="crit"
          icon={WifiOff}
          action={(
            <button type="button" onClick={feed.refresh} className="inline-flex items-center gap-1.5 rounded-md border border-crit/40 px-2 py-1 font-medium text-crit hover:bg-crit/10">
              <RefreshCw size={12} aria-hidden="true" /> Retry
            </button>
          )}
        >
          Cannot reach the API. {feed.attacks.length > 0 ? 'Showing the last known data.' : 'Retrying automatically.'}
        </Banner>
      )}
      {live && feed.status === 'degraded' && (
        <Banner tone="warn" icon={AlertTriangle}>
          Limited data: {describeDegraded(feed.meta.degradedReason)}, so sample IPs are shown.
        </Banner>
      )}
    </div>
  );

  const globe = (
    <div className="relative min-h-0 flex-1 overflow-hidden rounded-xl border border-line bg-canvas">
      <Suspense fallback={<div className="grid h-full place-items-center text-sm text-ink-muted" role="status">Preparing globe…</div>}>
        <GlobeView
          attacks={attacks}
          currentStep={sim.currentStep}
          highlightedCountries={sim.currentStep?.affectedRegions}
          highlightColor={sim.scenario === 'mirai' ? '#6cb6ff' : '#ff6b6b'}
          isPlaying={sim.isPlaying}
          onAttackClick={handleGlobeClick}
          onHoverAttack={setHoveredId}
          selectedId={selectedId}
          hoveredId={hoveredId}
        />
      </Suspense>

      {banners}

      <div className="pointer-events-none absolute bottom-3 left-3 flex flex-col items-start gap-2">
        <Legend />
      </div>

      {live && feed.status === 'live' && attacks.length === 0 && (
        <p className="absolute inset-x-0 bottom-16 text-center text-sm text-ink-muted">No threats match this filter.</p>
      )}

      {!live && sim.complete && (
        <div className="absolute inset-0 z-20 grid place-items-center bg-black/60 p-4">
          <div role="dialog" aria-label="Simulation complete" className="w-full max-w-sm rounded-xl border border-line bg-surface p-5 text-center">
            <p className="text-base font-semibold text-ink">Simulation complete</p>
            <p className="mt-1 text-[13px] text-ink-muted">
              {sim.scenarioMeta.label} · {sim.steps.length} phases replayed
            </p>
            <div className="mt-4 flex justify-center gap-2">
              <button type="button" onClick={sim.reset} className="rounded-lg bg-ink px-3.5 py-2 text-xs font-medium text-canvas hover:opacity-90">
                Restart
              </button>
              <button
                type="button"
                onClick={() => sim.selectScenario(sim.scenario === 'wannacry' ? 'mirai' : 'wannacry')}
                className="rounded-lg border border-line px-3.5 py-2 text-xs font-medium text-ink hover:border-line-strong"
              >
                Switch scenario
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );

  const compactTabs = [
    { value: 'globe', label: 'Globe', icon: Globe2 },
    { value: 'feed', label: live ? 'Feed' : 'Controls', icon: ListChecks },
    { value: 'overview', label: 'Insights', icon: LayoutGrid },
  ];

  return (
    <div className="flex h-dvh flex-col bg-canvas text-ink">
      <Header mode={mode} onModeChange={handleModeChange} provider={provider} onProviderChange={setProvider} status={live ? feed.status : 'simulation'} />

      <main className="flex min-h-0 flex-1 gap-3 p-3">
        {layout === 'wide' && (
          <aside className="scroll-thin w-[300px] shrink-0 overflow-y-auto" aria-label="Overview">{overviewNode}</aside>
        )}

        {(layout !== 'compact' || compactView === 'globe') && (
          <div className="flex min-w-0 flex-1 flex-col gap-3">
            {globe}
            <div className="shrink-0">{analyticsNode}</div>
          </div>
        )}

        {layout === 'wide' && (
          <aside className="flex w-[360px] shrink-0 flex-col" aria-label={live ? 'Threat feed' : 'Simulation controls'}>{sideNode}</aside>
        )}

        {layout === 'medium' && (
          <aside className="flex w-[340px] shrink-0 flex-col gap-3" aria-label="Details">
            <Segmented
              label="Side panel"
              options={[
                { value: 'feed', label: live ? 'Feed' : 'Controls' },
                { value: 'overview', label: live ? 'Overview' : 'Scenario' },
              ]}
              value={sideTab}
              onChange={setSideTab}
              size="sm"
            />
            <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
              {sideTab === 'feed' ? sideNode : overviewNode}
            </div>
          </aside>
        )}

        {layout === 'compact' && compactView === 'feed' && (
          <div className="flex min-w-0 flex-1 flex-col">{sideNode}</div>
        )}
        {layout === 'compact' && compactView === 'overview' && (
          <div className="scroll-thin flex min-w-0 flex-1 flex-col gap-3 overflow-y-auto">
            {overviewNode}
            {analyticsNode}
          </div>
        )}
      </main>

      {layout === 'compact' && (
        <nav aria-label="Sections" className="flex shrink-0 border-t border-line bg-canvas pb-[env(safe-area-inset-bottom)]">
          {compactTabs.map((tab) => (
            <button
              key={tab.value}
              type="button"
              aria-current={compactView === tab.value ? 'page' : undefined}
              onClick={() => setCompactView(tab.value)}
              className={cn(
                'flex flex-1 flex-col items-center gap-1 py-2.5 text-2xs font-medium transition-colors',
                compactView === tab.value ? 'text-ink' : 'text-ink-faint',
              )}
            >
              <tab.icon size={18} aria-hidden="true" />
              {tab.label}
            </button>
          ))}
        </nav>
      )}

      <StatusBar mode={mode} status={feed.status} lastUpdated={feed.lastUpdated} meta={feed.meta} count={attacks.length} />

      <ThreatReportModal threat={reportThreat} isOpen={Boolean(reportThreat)} onClose={closeReport} aiProvider={provider} />
    </div>
  );
};

export default App;
