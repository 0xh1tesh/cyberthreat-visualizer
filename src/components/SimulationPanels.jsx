import React from 'react';
import { CheckCircle2, Circle, FlaskConical, Pause, Play, RotateCcw, SkipBack, SkipForward, Sparkles, Terminal } from 'lucide-react';
import { Badge, IconButton, Panel, Segmented } from './ui';
import { cn } from '../lib/utils';
import { SIM_SCENARIOS } from '../hooks/useSimulation';

const SCENARIO_OPTIONS = Object.values(SIM_SCENARIOS).map(({ key, label }) => ({ value: key, label }));

const InfoBlock = ({ label, tone = 'text-ink-muted', children }) => (
  <div className="rounded-lg border border-line bg-canvas p-3">
    <p className="text-2xs font-medium uppercase tracking-wide text-ink-faint">{label}</p>
    <div className={cn('mt-1 text-[13px] leading-5', tone)}>{children}</div>
  </div>
);

export const ScenarioDetails = ({ sim }) => {
  const { currentStep, scenarioMeta } = sim;
  return (
    <div className="flex min-h-0 flex-col gap-3">
      <Panel title="Scenario" icon={FlaskConical}>
        <Segmented label="Scenario" options={SCENARIO_OPTIONS} value={sim.scenario} onChange={sim.selectScenario} size="sm" />
        <h3 className="mt-3 text-lg font-semibold text-ink">{scenarioMeta.title}</h3>
        {currentStep && (
          <div className="mt-3 space-y-3">
            <InfoBlock label="Estimated impact" tone="text-ink">
              <span className="font-medium">{currentStep.impactStat}</span>
            </InfoBlock>
            {currentStep.focusRegion?.primary && (
              <InfoBlock label={`Focus · ${currentStep.focusRegion.primary}`}>{currentStep.focusRegion.why}</InfoBlock>
            )}
          </div>
        )}
      </Panel>

      <Panel title="Phase insight" icon={Terminal}>
        {currentStep ? (
          <div className="space-y-3">
            <div>
              <p className="text-xs text-ink-muted">Phase {sim.stepIndex + 1} of {sim.steps.length}</p>
              <p className="mt-0.5 text-sm font-semibold text-ink">{currentStep.title}</p>
              <p className="mt-1.5 text-[13px] leading-5 text-ink-muted">{currentStep.description}</p>
            </div>
            {currentStep.technicalInsight && (
              <InfoBlock label="Key technique"><span className="font-mono text-xs text-ok">{currentStep.technicalInsight}</span></InfoBlock>
            )}
            {(currentStep.visualPattern || currentStep.arcNarrativeSummary) && (
              <InfoBlock label="On the globe">
                {currentStep.visualPattern}
                {currentStep.arcNarrativeSummary && <p className="mt-1">{currentStep.arcNarrativeSummary}</p>}
              </InfoBlock>
            )}
            {Array.isArray(currentStep.exploitBreakdown) && currentStep.exploitBreakdown.length > 0 && (
              <InfoBlock label="How it works">
                <ul className="list-disc space-y-1 pl-4 marker:text-ink-faint">
                  {currentStep.exploitBreakdown.map((item, index) => <li key={index}>{item}</li>)}
                </ul>
              </InfoBlock>
            )}
            {currentStep.analystTakeaway && (
              <InfoBlock label="Analyst takeaway" tone="text-warn">{currentStep.analystTakeaway}</InfoBlock>
            )}
            {currentStep.affectedRegions?.length > 0 && (
              <div>
                <p className="mb-1.5 text-2xs font-medium uppercase tracking-wide text-ink-faint">Countries involved</p>
                <div className="flex flex-wrap gap-1.5">
                  {currentStep.affectedRegions.map((region) => <Badge key={region} tone="info">{region}</Badge>)}
                </div>
              </div>
            )}
          </div>
        ) : (
          <p className="text-[13px] text-ink-muted">Select a phase to begin.</p>
        )}
      </Panel>
    </div>
  );
};

export const SimulationControls = ({ sim, className }) => {
  const { steps, stepIndex, isPlaying, speed, complete } = sim;
  return (
    <div className={cn('flex min-h-0 flex-col gap-3', className)}>
      <Panel title="Playback" icon={Sparkles}>
        <div className="flex items-center justify-center gap-3">
          <IconButton label="Previous phase" onClick={() => sim.stepBy(-1)} disabled={stepIndex === 0}>
            <SkipBack size={15} aria-hidden="true" />
          </IconButton>
          <button
            type="button"
            onClick={sim.togglePlay}
            aria-label={isPlaying ? 'Pause' : complete ? 'Replay' : 'Play'}
            className="grid size-11 place-items-center rounded-full bg-ink text-canvas transition-opacity hover:opacity-90"
          >
            {isPlaying ? <Pause size={18} aria-hidden="true" /> : complete ? <RotateCcw size={18} aria-hidden="true" /> : <Play size={18} className="translate-x-px" aria-hidden="true" />}
          </button>
          <IconButton label="Next phase" onClick={() => sim.stepBy(1)} disabled={stepIndex >= steps.length - 1}>
            <SkipForward size={15} aria-hidden="true" />
          </IconButton>
        </div>

        <div className="mt-4 flex items-center justify-between text-xs text-ink-muted">
          <span>Speed</span>
          <div className="inline-flex rounded-lg border border-line bg-canvas p-0.5" role="group" aria-label="Playback speed">
            {[1, 2, 5].map((value) => (
              <button
                key={value}
                type="button"
                aria-pressed={speed === value}
                onClick={() => sim.setSpeed(value)}
                className={cn('rounded-md px-2.5 py-1 text-xs font-medium tabular transition-colors', speed === value ? 'bg-overlay text-ink' : 'text-ink-muted hover:text-ink')}
              >
                {value}×
              </button>
            ))}
          </div>
        </div>

        <div className="mt-4 border-t border-line pt-3">
          <div className="mb-1.5 flex justify-between text-xs text-ink-muted">
            <span>Progress</span>
            <span className="tabular">{stepIndex + 1} / {steps.length}</span>
          </div>
          <div
            className="h-1 overflow-hidden rounded-full bg-raised"
            role="progressbar"
            aria-valuemin={1}
            aria-valuemax={steps.length}
            aria-valuenow={stepIndex + 1}
            aria-label="Scenario progress"
          >
            <div className="h-full rounded-full bg-info transition-[width] duration-300" style={{ width: `${((stepIndex + 1) / steps.length) * 100}%` }} />
          </div>
        </div>
      </Panel>

      <Panel title="Phases" icon={Terminal} className="min-h-0 flex-1" bodyClassName="scroll-thin max-h-full overflow-y-auto">
        <ol className="space-y-1.5">
          {steps.map((step, index) => {
            const done = index < stepIndex;
            const current = index === stepIndex;
            return (
              <li key={step.id}>
                <button
                  type="button"
                  onClick={() => sim.goToStep(index)}
                  aria-current={current ? 'step' : undefined}
                  className={cn(
                    'flex w-full items-start gap-2.5 rounded-lg border px-2.5 py-2 text-left transition-colors',
                    current ? 'border-line-strong bg-raised' : 'border-transparent hover:bg-raised',
                  )}
                >
                  {done ? <CheckCircle2 size={15} className="mt-0.5 shrink-0 text-ok" aria-hidden="true" /> : <Circle size={15} className={cn('mt-0.5 shrink-0', current ? 'text-info' : 'text-ink-faint')} aria-hidden="true" />}
                  <span className="min-w-0">
                    <span className="block text-2xs tabular text-ink-faint">Phase {index + 1}</span>
                    <span className={cn('block text-[13px] leading-5', current ? 'text-ink' : 'text-ink-muted')}>{step.title}</span>
                  </span>
                </button>
              </li>
            );
          })}
        </ol>
      </Panel>
    </div>
  );
};
