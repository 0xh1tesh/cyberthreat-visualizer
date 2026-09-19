import { useCallback, useEffect, useMemo, useState } from 'react';
import { miraiSteps, wannacrySteps } from '../data/constants';
import { normalizeAttackBatch } from '../lib/threat-normalize';

export const SIM_SCENARIOS = {
  wannacry: { key: 'wannacry', label: 'WannaCry', title: 'WannaCry ransomware', steps: wannacrySteps },
  mirai: { key: 'mirai', label: 'Mirai', title: 'Mirai botnet', steps: miraiSteps },
};

const STAGE_DURATION_MS = 2600;

export function useSimulation({ active }) {
  const [scenario, setScenario] = useState('wannacry');
  const [stepIndex, setStepIndex] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [complete, setComplete] = useState(false);

  const steps = SIM_SCENARIOS[scenario].steps;
  const currentStep = active ? steps[stepIndex] ?? null : null;

  const arcs = useMemo(() => normalizeAttackBatch(currentStep?.arcs), [currentStep]);

  useEffect(() => {
    if (!active || !isPlaying) return undefined;
    const timer = setInterval(() => {
      setStepIndex((previous) => {
        const next = previous + 1;
        if (next >= steps.length) {
          setIsPlaying(false);
          setComplete(true);
          return previous;
        }
        return next;
      });
    }, STAGE_DURATION_MS / speed);
    return () => clearInterval(timer);
  }, [active, isPlaying, speed, steps.length]);

  const reset = useCallback(() => {
    setStepIndex(0);
    setIsPlaying(false);
    setComplete(false);
  }, []);

  const selectScenario = useCallback((key) => {
    setScenario(key);
    setStepIndex(0);
    setIsPlaying(false);
    setComplete(false);
  }, []);

  const togglePlay = useCallback(() => {
    if (complete) {
      setStepIndex(0);
      setComplete(false);
      setIsPlaying(true);
      return;
    }
    setIsPlaying((value) => !value);
  }, [complete]);

  const stepBy = useCallback((delta) => {
    setComplete(false);
    setStepIndex((previous) => Math.max(0, Math.min(steps.length - 1, previous + delta)));
  }, [steps.length]);

  const goToStep = useCallback((index) => {
    setComplete(false);
    setStepIndex(Math.max(0, Math.min(steps.length - 1, index)));
  }, [steps.length]);

  return {
    scenario,
    scenarioMeta: SIM_SCENARIOS[scenario],
    steps,
    stepIndex,
    currentStep,
    arcs,
    isPlaying,
    speed,
    setSpeed,
    complete,
    reset,
    selectScenario,
    togglePlay,
    stepBy,
    goToStep,
    pause: () => setIsPlaying(false),
  };
}
