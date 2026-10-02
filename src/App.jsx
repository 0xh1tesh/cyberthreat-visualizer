import React, { Suspense, lazy, useCallback, useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Globe2, LayoutGrid, ListChecks, RefreshCw, WifiOff } from 'lucide-react';
import Header from './components/Header';
import StatusBar from './components/StatusBar';
import Overview from './components/Overview';
import ThreatFeed from './components/ThreatFeed';
import ThreatReportModal from './components/ThreatReportModal';
import ScopeOverlay from './components/ScopeOverlay';
import { ScenarioDetails, SimulationControls } from './components/SimulationPanels';
import { ClassMix, ObservationsTimeline, PhaseIntensity } from './components/Analytics';
import { CommandButton, Segmented, StatusDot } from './components/ui';
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
      'flex items-center gap-2.5 border border-l-2 bg-canvas/95 px-3 py-2 text-[13px]',
      tone === 'crit' && 'border-crit/30 border-l-crit text-crit',
      tone === 'warn' && 'border-warn/30 border-l-warn text-warn',
      tone === 'info' && 'border-info/30 border-l-info text-info',
    )}
  >
    <Icon size={14} className="shrink-0" aria-hidden="true" />
    <span className="min-w-0 flex-1 text-ink">{children}</span>
    {action}
  </div>
);

const Legend = () => (
  <ul className="flex flex-wrap items-center gap-x-4 gap-y-1 border border-line bg-canvas/90 px-3 py-2" aria-label="Severity legend">
    {CLASS_ORDER.map((key) => (
      <li key={key} className="readout flex items-center gap-1.5 text-ink-muted!">
        <span className="size-2 rotate-45" style={{ background: CLASS_META[key].color }} aria-hidden="true" />
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
    <div className="pointer-events-none absolute inset-x-3 top-11 z-10 flex flex-col gap-2 [&>*]:pointer-events-auto">
      {!live && (
        <Banner tone="info" icon={Globe2}>
          <strong className="font-semibold uppercase tracking-wider">Simulation.</strong> A historical scenario replay with illustrative routes, not live telemetry.
        </Banner>
      )}
      {live && feed.status === 'offline' && (
        <Banner
          tone="crit"
          icon={WifiOff}
          action={(
            <CommandButton tone="crit" onClick={feed.refresh}>
              <RefreshCw size={12} aria-hidden="true" /> Retry
            </CommandButton>
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

  const sensor = live && feed.attacks[0] ? { lat: feed.attacks[0].targetLat, lng: feed.attacks[0].targetLng } : null;
  const formatCoord = (value, pos, neg) => `${Math.abs(value).toFixed(1)}°${value >= 0 ? pos : neg}`;

  const globe = (
    <div className="hud relative min-h-0 flex-1 overflow-hidden border border-line bg-canvas" style={{ containerType: 'size' }}>
      <ScopeOverlay />
      <Suspense fallback={<div className="readout grid h-full place-items-center" role="status">Acquiring globe…</div>}>
        <GlobeView
          attacks={attacks}
          currentStep={sim.currentStep}
          highlightedCountries={sim.currentStep?.affectedRegions}
          highlightColor={sim.scenario === 'mirai' ? CLASS_META.SCAN.color : CLASS_META.DDOS.color}
          isPlaying={sim.isPlaying}
          onAttackClick={handleGlobeClick}
          onHoverAttack={setHoveredId}
          selectedId={selectedId}
          hoveredId={hoveredId}
        />
      </Suspense>

      <div className="scanlines pointer-events-none absolute inset-0" aria-hidden="true" />

      <div className="pointer-events-none absolute inset-x-3 top-3 flex items-start justify-between gap-3">
        <p className="readout flex items-center gap-2 text-ink!">
          <StatusDot tone={live ? (feed.status === 'offline' ? 'crit' : feed.status === 'live' ? 'ok' : 'warn') : 'info'} pulse={live && feed.status === 'live'} />
          {live ? 'Live intercept' : `Replay: ${sim.scenarioMeta.label}`}
        </p>
        <p className="readout hidden text-right sm:block">
          {sensor
            ? <>Sensor <span className="text-info">{formatCoord(sensor.lat, 'N', 'S')} {formatCoord(sensor.lng, 'E', 'W')}</span></>
            : !live && <>Phase <span className="text-info">{String(sim.stepIndex + 1).padStart(2, '0')}/{String(sim.steps.length).padStart(2, '0')}</span></>}
        </p>
      </div>

      {banners}

      <div className="pointer-events-none absolute inset-x-3 bottom-3 flex items-end justify-between gap-3">
        <Legend />
        <p className="readout hidden max-w-[24ch] text-right lg:block">Drag to rotate. Select an arc for its report.</p>
      </div>

      {live && feed.status === 'live' && attacks.length === 0 && (
        <p className="readout absolute inset-x-0 bottom-16 text-center">No threats match this filter</p>
      )}

      {!live && sim.complete && (
        <div className="absolute inset-0 z-20 grid place-items-center bg-canvas/70 p-4">
          <div role="dialog" aria-label="Simulation complete" className="hud w-full max-w-sm border border-line-strong bg-surface p-5 text-center">
            <p className="text-lg font-bold uppercase tracking-[0.1em] text-info">Replay complete</p>
            <p className="mt-1 text-sm text-ink-muted">
              {sim.scenarioMeta.label}: {sim.steps.length} phases replayed
            </p>
            <div className="mt-4 flex justify-center gap-2">
              <button type="button" onClick={sim.reset} className="border border-info bg-info px-3.5 py-2 text-xs font-bold uppercase tracking-wider text-canvas hover:bg-info/85">
                Restart
              </button>
              <CommandButton onClick={() => sim.selectScenario(sim.scenario === 'wannacry' ? 'mirai' : 'wannacry')} className="px-3.5 py-2">
                Switch scenario
              </CommandButton>
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
    <div className="flex h-dvh flex-col text-ink">
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
          <div className="scroll-thin flex min-w-0 flex-1 flex-col gap-3 overflow-y-auto [&>*]:shrink-0">
            {overviewNode}
            {analyticsNode}
          </div>
        )}
      </main>

      {layout === 'compact' && (
        <nav aria-label="Sections" className="flex shrink-0 border-t border-line bg-canvas/95 pb-[env(safe-area-inset-bottom)]">
          {compactTabs.map((tab) => (
            <button
              key={tab.value}
              type="button"
              aria-current={compactView === tab.value ? 'page' : undefined}
              onClick={() => setCompactView(tab.value)}
              className={cn(
                '-mt-px flex flex-1 flex-col items-center gap-1 border-t-2 py-2.5 text-xs font-semibold uppercase tracking-wider transition-colors',
                compactView === tab.value ? 'border-info text-info' : 'border-transparent text-ink-faint',
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
