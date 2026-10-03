import React from 'react';
import { ArrowCounterClockwiseIcon, PauseIcon, PlayIcon, SkipBackIcon, SkipForwardIcon } from '@phosphor-icons/react';
import { IconButton, Section, Tabs } from './ui';
import { cn } from '../lib/utils';
import { SIM_SCENARIOS } from '../hooks/useSimulation';

const SCENARIO_OPTIONS = Object.values(SIM_SCENARIOS).map(({ key, label }) => ({ value: key, label }));

const Note = ({ label, children, className }) => (
  <div className={className}>
    <h4 className="text-xs text-ink-mute">{label}</h4>
    <div className="mt-1 text-[13.5px] leading-[1.55] text-ink-soft">{children}</div>
  </div>
);

export const ScenarioDetails = ({ sim }) => {
  const { currentStep, scenarioMeta } = sim;
  return (
    <div className="flex min-h-0 flex-col gap-8">
      <section aria-labelledby="scenario-heading">
        <Tabs label="Scenario" options={SCENARIO_OPTIONS} value={sim.scenario} onChange={sim.selectScenario} />
        <h2 id="scenario-heading" className="condensed mt-4 text-[40px] leading-[0.98] font-extrabold tracking-[-0.015em] text-ink">
          {scenarioMeta.title}
        </h2>
        {currentStep && (
          <>
            <p className="condensed mt-4 border-l-[3px] border-crit pl-3 text-[21px] leading-6 font-semibold text-ink">
              {currentStep.impactStat}
            </p>
            {currentStep.focusRegion?.primary && (
              <Note label={`Focus: ${currentStep.focusRegion.primary}`} className="mt-4">{currentStep.focusRegion.why}</Note>
            )}
          </>
        )}
      </section>

      <Section title={currentStep ? currentStep.title : 'This phase'}>
        {currentStep ? (
          <div className="space-y-4">
            <p className="text-[14.5px] leading-[1.55] text-ink">{currentStep.description}</p>
            {currentStep.technicalInsight && (
              <Note label="Key technique"><span className="font-mono text-[12.5px] leading-5 text-ink">{currentStep.technicalInsight}</span></Note>
            )}
            {(currentStep.visualPattern || currentStep.arcNarrativeSummary) && (
              <Note label="On the globe">
                {currentStep.visualPattern}
                {currentStep.arcNarrativeSummary && <span className="mt-1 block">{currentStep.arcNarrativeSummary}</span>}
              </Note>
            )}
            {Array.isArray(currentStep.exploitBreakdown) && currentStep.exploitBreakdown.length > 0 && (
              <Note label="How it works">
                <ul className="list-disc space-y-1 pl-4 marker:text-ink-mute">
                  {currentStep.exploitBreakdown.map((item, index) => <li key={index}>{item}</li>)}
                </ul>
              </Note>
            )}
            {currentStep.analystTakeaway && (
              <div className="bg-wash px-3 py-2.5">
                <h4 className="text-xs font-semibold text-ink">Analyst takeaway</h4>
                <p className="mt-1 text-[13.5px] leading-[1.55] text-ink">{currentStep.analystTakeaway}</p>
              </div>
            )}
            {currentStep.affectedRegions?.length > 0 && (
              <Note label="Countries involved">{currentStep.affectedRegions.join(', ')}</Note>
            )}
          </div>
        ) : (
          <p className="text-[13px] text-ink-mute">Select a phase to begin.</p>
        )}
      </Section>
    </div>
  );
};

export const SimulationControls = ({ sim, className }) => {
  const { steps, stepIndex, isPlaying, speed, complete } = sim;
  return (
    <div className={cn('flex min-h-0 flex-col gap-6', className)}>
      <Section title="Playback">
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={sim.togglePlay}
            className="inline-flex h-10 items-center gap-2 bg-ink px-4 text-[14px] font-semibold text-paper transition-[background-color,transform] hover:bg-ink/85 active:translate-y-px"
          >
            {isPlaying ? <PauseIcon size={16} weight="fill" aria-hidden="true" /> : complete ? <ArrowCounterClockwiseIcon size={16} weight="bold" aria-hidden="true" /> : <PlayIcon size={16} weight="fill" aria-hidden="true" />}
            {isPlaying ? 'Pause' : complete ? 'Replay' : 'Play'}
          </button>
          <IconButton label="Previous phase" onClick={() => sim.stepBy(-1)} disabled={stepIndex === 0} className="size-10">
            <SkipBackIcon size={17} weight="fill" aria-hidden="true" />
          </IconButton>
          <IconButton label="Next phase" onClick={() => sim.stepBy(1)} disabled={stepIndex >= steps.length - 1} className="size-10">
            <SkipForwardIcon size={17} weight="fill" aria-hidden="true" />
          </IconButton>

          <div className="ml-auto flex items-center gap-1" role="group" aria-label="Playback speed">
            {[1, 2, 5].map((value) => (
              <button
                key={value}
                type="button"
                aria-pressed={speed === value}
                onClick={() => sim.setSpeed(value)}
                className={cn('h-7 min-w-8 px-1.5 text-[12.5px] font-medium tabular transition-colors', speed === value ? 'bg-ink text-paper' : 'text-ink-mute hover:text-ink')}
              >
                {value}×
              </button>
            ))}
          </div>
        </div>

        <div
          className="mt-4 flex gap-0.5"
          role="progressbar"
          aria-valuemin={1}
          aria-valuemax={steps.length}
          aria-valuenow={stepIndex + 1}
          aria-label={`Phase ${stepIndex + 1} of ${steps.length}`}
        >
          {steps.map((step, index) => (
            <span key={step.id} className={cn('h-1 flex-1 transition-colors duration-300', index <= stepIndex ? 'bg-ink' : 'bg-rule')} />
          ))}
        </div>
        <p className="mt-1.5 text-xs text-ink-mute tabular">Phase {stepIndex + 1} of {steps.length}</p>
      </Section>

      <Section title="Timeline" className="flex min-h-0 flex-1 flex-col" bodyClassName="scroll-thin min-h-0 flex-1 overflow-y-auto">
        <ol>
          {steps.map((step, index) => {
            const current = index === stepIndex;
            return (
              <li key={step.id}>
                <button
                  type="button"
                  onClick={() => sim.goToStep(index)}
                  aria-current={current ? 'step' : undefined}
                  className={cn(
                    'grid w-full grid-cols-[1.75rem_minmax(0,1fr)] items-baseline gap-2 px-2 py-2 text-left transition-colors',
                    current ? 'bg-ink text-paper' : index < stepIndex ? 'text-ink-soft hover:bg-wash' : 'text-ink-mute hover:bg-wash hover:text-ink',
                  )}
                >
                  <span className="condensed text-[15px] font-bold tabular">{index + 1}</span>
                  <span className="text-[13.5px] leading-5">{step.title}</span>
                </button>
              </li>
            );
          })}
        </ol>
      </Section>
    </div>
  );
};
