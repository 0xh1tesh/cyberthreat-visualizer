import React, { Suspense, lazy, useCallback, useEffect, useMemo, useState } from 'react';
import { MotionConfig } from 'motion/react';
import { ArrowClockwiseIcon, GlobeHemisphereWestIcon, ListBulletsIcon, SquaresFourIcon, WarningIcon, WifiSlashIcon } from '@phosphor-icons/react';
import Header from './components/Header';
import StatusBar from './components/StatusBar';
import Overview from './components/Overview';
import ThreatFeed from './components/ThreatFeed';
import ThreatReportModal from './components/ThreatReportModal';
import { ScenarioDetails, SimulationControls } from './components/SimulationPanels';
import { ClassMix, ObservationsTimeline, PhaseIntensity } from './components/Analytics';
import { Button, Tabs } from './components/ui';
import { useThreatFeed } from './hooks/useThreatFeed';
import { SIM_SCENARIOS, useSimulation } from './hooks/useSimulation';
import { useThreatAnalysis } from './hooks/useThreatAnalysis';
import { useLayoutMode, useTheme } from './hooks/useMediaQuery';
import { toNewThreat } from './lib/threat-normalize';
import { CLASS_META, CLASS_ORDER, SEVERITY_BG, THEMES } from './lib/palette';
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

const Banner = ({ tone = 'note', icon: Icon, lead, children, action }) => (
  <div
    role={tone === 'alert' ? 'alert' : 'status'}
    className="flex max-w-xl items-center gap-2.5 bg-sheet/95 px-3 py-2 text-[13px] text-ink shadow-[0_8px_24px_-14px_rgb(0_0_0/0.4)]"
  >
    {Icon && <Icon size={15} weight="bold" className={cn('shrink-0', tone === 'alert' ? 'text-crit' : tone === 'warn' ? 'text-high' : 'text-ink-mute')} aria-hidden="true" />}
    <p className="min-w-0 flex-1"><strong className="font-semibold">{lead}</strong> {children}</p>
    {action}
  </div>
);

/** Ordinal key: one contiguous ramp, read left to right from low to critical. */
const SeverityKey = () => (
  <ul className="grid grid-cols-4 gap-0.5" aria-label="Severity key, low to critical">
    {[...CLASS_ORDER].reverse().map((key) => (
      <li key={key} className="w-14">
        <span className={cn('block h-1.5', SEVERITY_BG[CLASS_META[key].tone])} aria-hidden="true" />
        <span className="mt-1 block text-[11px] text-ink-soft">{CLASS_META[key].severity}</span>
      </li>
    ))}
  </ul>
);

const App = () => {
  const layout = useLayoutMode();
  const [theme, toggleTheme] = useTheme();
  const colors = THEMES[theme];
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

  const feedNode = (
    <ThreatFeed
      className="flex h-full min-h-0 flex-col"
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
      threats={allLiveThreats}
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
    <div className="grid min-h-0 grid-cols-1 gap-6 sm:grid-cols-[minmax(0,1fr)_220px]">
      <ObservationsTimeline observations={feed.history} colors={colors} className="h-[190px]" />
      <ClassMix threats={allLiveThreats} className="hidden sm:block" />
    </div>
  ) : (
    <PhaseIntensity steps={sim.steps} stepIndex={sim.stepIndex} onSelect={sim.goToStep} colors={colors} className="h-[190px]" />
  );

  const otherScenario = Object.values(SIM_SCENARIOS).find((item) => item.key !== sim.scenario);

  const globe = (
    <figure className="relative min-h-[320px] flex-1" style={{ containerType: 'size' }}>
      <div className="absolute inset-x-0 top-[4.5rem] bottom-0">
        <Suspense fallback={<div className="grid h-full place-items-center text-[13px] text-ink-mute" role="status">Loading the globe</div>}>
          <GlobeView
            attacks={attacks}
            currentStep={sim.currentStep}
            highlightedCountries={sim.currentStep?.affectedRegions}
            colors={colors}
            isPlaying={sim.isPlaying}
            onAttackClick={handleGlobeClick}
            onHoverAttack={setHoveredId}
            selectedId={selectedId}
            hoveredId={hoveredId}
          />
        </Suspense>
      </div>

      <figcaption className="pointer-events-none absolute inset-x-0 top-0 max-w-[46ch]">
        <p className="condensed text-[24px] leading-7 font-bold text-ink">
          {live ? 'Where hostile traffic is coming from' : `${sim.scenarioMeta.title}, replayed`}
        </p>
        <p className="mt-1 text-[13px] leading-5 text-ink-mute">
          {live
            ? 'The highest-scoring sources from the latest refresh, each routed to the monitoring node.'
            : sim.currentStep ? `Phase ${sim.stepIndex + 1} of ${sim.steps.length}: ${sim.currentStep.title}` : 'Select a phase to begin.'}
        </p>
      </figcaption>

      <div className="pointer-events-none absolute inset-x-0 top-[4.75rem] z-10 flex flex-col gap-2 [&>*]:pointer-events-auto">
        {!live && (
          <Banner icon={GlobeHemisphereWestIcon} lead="Simulation.">
            A historical scenario replay with illustrative routes, not live telemetry.
          </Banner>
        )}
        {live && feed.status === 'offline' && (
          <Banner
            tone="alert"
            icon={WifiSlashIcon}
            lead="Cannot reach the API."
            action={(
              <Button variant="alert" onClick={feed.refresh}>
                <ArrowClockwiseIcon size={13} aria-hidden="true" /> Retry
              </Button>
            )}
          >
            {feed.attacks.length > 0 ? 'Showing the last known data.' : 'Retrying automatically.'}
          </Banner>
        )}
        {live && feed.status === 'degraded' && (
          <Banner tone="warn" icon={WarningIcon} lead="Limited data:">
            {describeDegraded(feed.meta.degradedReason)}, so sample IPs are shown.
          </Banner>
        )}
      </div>

      <div className="pointer-events-none absolute inset-x-0 bottom-0 flex items-end justify-between gap-6">
        <SeverityKey />
        <p className="hidden text-right text-[11.5px] leading-[1.45] text-ink-mute lg:block">
          {live ? 'Source: AbuseIPDB, AlienVault OTX, Shodan, IPinfo.' : 'Source: public incident reporting.'}
          <br />
          Drag to rotate. Select a route for its report.
        </p>
      </div>

      {live && feed.status === 'live' && attacks.length === 0 && (
        <p className="absolute inset-x-0 bottom-14 text-center text-[13px] text-ink-mute">No threats match this filter.</p>
      )}

      {!live && sim.complete && (
        <div className="absolute inset-0 z-20 grid place-items-center bg-paper/60 p-4">
          <div role="dialog" aria-label="Simulation complete" className="w-full max-w-sm border-t-[6px] border-ink bg-sheet p-6 shadow-[0_24px_60px_-20px_rgb(0_0_0/0.4)]">
            <p className="condensed text-[30px] leading-8 font-extrabold text-ink">Replay complete</p>
            <p className="mt-1.5 text-sm text-ink-soft">All {sim.steps.length} phases of {sim.scenarioMeta.label} have played.</p>
            <div className="mt-5 flex gap-2">
              <Button variant="solid" size="md" onClick={sim.reset}>Replay</Button>
              <Button size="md" onClick={() => sim.selectScenario(otherScenario.key)}>Switch to {otherScenario.label}</Button>
            </div>
          </div>
        </div>
      )}
    </figure>
  );

  const compactTabs = [
    { value: 'globe', label: 'Globe', icon: GlobeHemisphereWestIcon },
    { value: 'feed', label: live ? 'Feed' : 'Controls', icon: ListBulletsIcon },
    { value: 'overview', label: live ? 'Overview' : 'Scenario', icon: SquaresFourIcon },
  ];

  return (
    <MotionConfig reducedMotion="user">
      <div className="flex h-dvh flex-col text-ink">
        <Header
          mode={mode}
          onModeChange={handleModeChange}
          provider={provider}
          onProviderChange={setProvider}
          status={live ? feed.status : 'simulation'}
          theme={theme}
          onToggleTheme={toggleTheme}
        />

        <main
          className={cn(
            'min-h-0 flex-1',
            layout === 'wide' && 'grid grid-cols-[320px_minmax(0,1fr)_390px] divide-x divide-rule',
            layout === 'medium' && 'grid grid-cols-[minmax(0,1fr)_340px] divide-x divide-rule',
            layout === 'compact' && 'flex flex-col',
          )}
        >
          {layout === 'wide' && (
            <aside className="scroll-thin overflow-y-auto px-5 py-5" aria-label={live ? 'Overview' : 'Scenario'}>{overviewNode}</aside>
          )}

          {(layout !== 'compact' || compactView === 'globe') && (
            <div className="flex min-h-0 min-w-0 flex-1 flex-col gap-5 px-4 py-4 sm:px-6 sm:py-5">
              {globe}
              <div className="shrink-0">{analyticsNode}</div>
            </div>
          )}

          {layout === 'wide' && (
            <aside className="flex min-h-0 flex-col px-5 py-5" aria-label={live ? 'Threat feed' : 'Simulation controls'}>{sideNode}</aside>
          )}

          {layout === 'medium' && (
            <aside className="flex min-h-0 flex-col gap-4 px-5 py-4" aria-label="Details">
              <Tabs
                label="Side panel"
                options={[
                  { value: 'feed', label: live ? 'Feed' : 'Controls' },
                  { value: 'overview', label: live ? 'Overview' : 'Scenario' },
                ]}
                value={sideTab}
                onChange={setSideTab}
              />
              <div className="scroll-thin flex min-h-0 flex-1 flex-col overflow-y-auto">
                {sideTab === 'feed' ? sideNode : overviewNode}
              </div>
            </aside>
          )}

          {layout === 'compact' && compactView === 'feed' && (
            <div className="flex min-h-0 min-w-0 flex-1 flex-col px-4 py-4">{sideNode}</div>
          )}
          {layout === 'compact' && compactView === 'overview' && (
            <div className="scroll-thin flex min-w-0 flex-1 flex-col gap-8 overflow-y-auto px-4 py-5 [&>*]:shrink-0">
              {overviewNode}
              {analyticsNode}
            </div>
          )}
        </main>

        {layout === 'compact' && (
          <nav aria-label="Sections" className="flex shrink-0 border-t border-ink pb-[env(safe-area-inset-bottom)]">
            {compactTabs.map((tab) => (
              <button
                key={tab.value}
                type="button"
                aria-current={compactView === tab.value ? 'page' : undefined}
                onClick={() => setCompactView(tab.value)}
                className={cn(
                  'flex flex-1 flex-col items-center gap-0.5 py-2 text-xs font-medium transition-colors',
                  compactView === tab.value ? 'bg-ink text-paper' : 'text-ink-mute',
                )}
              >
                <tab.icon size={20} weight={compactView === tab.value ? 'fill' : 'regular'} aria-hidden="true" />
                {tab.label}
              </button>
            ))}
          </nav>
        )}

        <StatusBar mode={mode} status={feed.status} lastUpdated={feed.lastUpdated} meta={feed.meta} count={attacks.length} />

        <ThreatReportModal threat={reportThreat} isOpen={Boolean(reportThreat)} onClose={closeReport} aiProvider={provider} />
      </div>
    </MotionConfig>
  );
};

export default App;
