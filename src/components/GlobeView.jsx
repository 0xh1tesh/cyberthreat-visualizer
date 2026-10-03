import React, { useEffect, useMemo, useRef, useState } from 'react';
import Globe from 'globe.gl';
import { BackSide, Mesh, MeshBasicMaterial, SphereGeometry } from 'three';
import { feature } from 'topojson-client';
import { classColor, classMeta, withAlpha } from '../lib/palette';

const MAX_LIVE_ARCS = 12;
const SIM_REVEAL_STEP_MS = 140;
const COUNTRIES_URL = '/textures/countries-110m.json';

// A printed atlas: flat sea, paper land, ink coastlines and a 15° graticule (drawn as paths so it
// can follow the theme; globe.gl's built-in graticule colour is fixed).
const GRATICULE = [
  ...Array.from({ length: 24 }, (_, i) => Array.from({ length: 33 }, (__, j) => [-80 + j * 5, -180 + i * 15])),
  ...Array.from({ length: 11 }, (_, i) => Array.from({ length: 73 }, (__, j) => [-75 + i * 15, -180 + j * 5])),
];

const ID_TO_COUNTRY = {
  36: 'Australia', 76: 'Brazil', 124: 'Canada', 156: 'China', 170: 'Colombia',
  250: 'France', 276: 'Germany', 356: 'India', 380: 'Italy', 392: 'Japan',
  410: 'South Korea', 528: 'Netherlands', 616: 'Poland', 620: 'Portugal',
  643: 'Russia', 704: 'Vietnam', 724: 'Spain', 826: 'United Kingdom', 840: 'United States',
};

const escapeHtml = (value) => String(value ?? '')
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#39;');

const getCountryName = (featureObj) => {
  const props = featureObj?.properties || {};
  return String(props.name || props.NAME || ID_TO_COUNTRY[Number(featureObj?.id)] || 'Unknown');
};

const isFiniteNum = (value) => typeof value === 'number' && Number.isFinite(value);

const hasValidCoords = (attack) =>
  attack
  && isFiniteNum(attack.sourceLat) && isFiniteNum(attack.sourceLng)
  && isFiniteNum(attack.targetLat) && isFiniteNum(attack.targetLng);

const hashToUnit = (value) => {
  let hash = 0;
  const input = String(value || 'arc');
  for (let i = 0; i < input.length; i += 1) {
    hash = ((hash << 5) - hash) + input.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash % 1000) / 1000;
};

const prefersReducedMotion = () =>
  typeof window !== 'undefined'
  && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

const arcTooltip = (arc, colors) => {
  const meta = classMeta(arc.classification);
  return `
    <div class="globe-tip">
      <div class="globe-tip__title">
        <span class="globe-tip__key" style="background:${classColor(arc.classification, colors)}"></span>
        ${escapeHtml(arc.sourceCountry)}
      </div>
      <div class="globe-tip__row"><span>Class</span><span>${escapeHtml(meta.label)}</span></div>
      <div class="globe-tip__row"><span>Score</span><span>${escapeHtml(Math.round(arc.score))} of 100</span></div>
      <div class="globe-tip__row"><span>Destination</span><span>${escapeHtml(arc.targetCountry)}</span></div>
      ${arc.sourceIp ? `<div class="globe-tip__row"><span>IP</span><span>${escapeHtml(arc.sourceIp)}</span></div>` : ''}
      <div class="globe-tip__hint">Select the route for its full report</div>
    </div>`;
};

const GlobeView = ({
  attacks,
  currentStep,
  highlightedCountries,
  colors,
  isPlaying,
  onAttackClick,
  onHoverAttack,
  selectedId,
  hoveredId,
}) => {
  const containerRef = useRef(null);
  const globeRef = useRef(null);
  const outlineRef = useRef(null);
  const interaction = useRef({ hovering: false, dragging: false });
  const latest = useRef({ isPlaying, currentStep, onAttackClick, onHoverAttack, colors });
  const [phase, setPhase] = useState('loading');
  const [countries, setCountries] = useState([]);
  const [mapFailed, setMapFailed] = useState(false);
  const [reveal, setReveal] = useState({ stepId: null, count: null });

  useEffect(() => {
    latest.current = { isPlaying, currentStep, onAttackClick, onHoverAttack, colors };
  });

  const arcs = useMemo(() => {
    const valid = (Array.isArray(attacks) ? attacks : []).filter(hasValidCoords);
    if (currentStep) return valid;
    return [...valid].sort((a, b) => (b.score || 0) - (a.score || 0)).slice(0, MAX_LIVE_ARCS);
  }, [attacks, currentStep]);

  // The feeds cannot observe victims, so live arcs all converge on one monitoring node.
  const monitoringNode = useMemo(() => {
    if (currentStep || arcs.length === 0) return null;
    return { lat: arcs[0].targetLat, lng: arcs[0].targetLng };
  }, [arcs, currentStep]);

  const applyRotation = () => {
    const globe = globeRef.current;
    if (!globe) return;
    const { isPlaying: playing, currentStep: step } = latest.current;
    const { hovering, dragging } = interaction.current;
    globe.controls().autoRotate = !prefersReducedMotion() && !hovering && !dragging && (step ? Boolean(playing) : true);
  };

  // ── Globe lifecycle ──
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return undefined;

    let globe;
    try {
      globe = Globe()(container)
        .backgroundColor('rgba(0,0,0,0)')
        .showAtmosphere(false)
        .showGraticules(false)
        .globeMaterial(new MeshBasicMaterial({ color: latest.current.colors.sea }))
        .pathsData(GRATICULE)
        .pathTransitionDuration(0)
        .width(container.clientWidth || 600)
        .height(container.clientHeight || 600);
    } catch {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- WebGL init is an external system; report its failure
      setPhase('unsupported');
      return undefined;
    }

    const renderer = globe.renderer?.();
    renderer?.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));

    const controls = globe.controls();
    controls.autoRotateSpeed = 0.25;
    controls.enableDamping = true;
    controls.dampingFactor = 0.08;
    controls.minDistance = 180;
    controls.maxDistance = 520;

    const onStart = () => { interaction.current.dragging = true; applyRotation(); };
    const onEnd = () => { interaction.current.dragging = false; applyRotation(); };
    controls.addEventListener('start', onStart);
    controls.addEventListener('end', onEnd);

    globe.pointOfView({ lat: 22, lng: 10, altitude: 1.6 });
    // An ink rim: a slightly larger back-faced sphere shows only at the silhouette.
    const outline = new Mesh(
      new SphereGeometry(globe.getGlobeRadius() * 1.005, 96, 64),
      new MeshBasicMaterial({ color: latest.current.colors.ink, side: BackSide }),
    );
    globe.scene().add(outline);
    outlineRef.current = outline;

    globeRef.current = globe;
    applyRotation();
    setPhase('ready');

    const observer = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect;
      if (width > 0 && height > 0) globe.width(width).height(height);
    });
    observer.observe(container);

    return () => {
      observer.disconnect();
      controls.removeEventListener('start', onStart);
      controls.removeEventListener('end', onEnd);
      globeRef.current = null;
      globe.pauseAnimation?.();
      globe.globeMaterial()?.dispose?.();
      outline.geometry.dispose();
      outline.material.dispose();
      outlineRef.current = null;
      renderer?.dispose?.();
      globe._destructor?.();
    };
  }, []);

  useEffect(applyRotation, [isPlaying, currentStep]);

  // ── Theme: sea and graticule ──
  useEffect(() => {
    const globe = globeRef.current;
    if (!globe) return;
    globe.globeMaterial()?.color?.set(colors.sea);
    outlineRef.current?.material.color.set(colors.ink);
    globe.pathColor(() => colors.grid);
  }, [colors, phase]);

  // ── Country outlines (vendored locally) ──
  useEffect(() => {
    const controller = new AbortController();
    (async () => {
      try {
        const response = await fetch(COUNTRIES_URL, { signal: controller.signal });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const topo = await response.json();
        setCountries(feature(topo, topo.objects.countries).features || []);
        setMapFailed(false);
      } catch (err) {
        if (err?.name !== 'AbortError') setMapFailed(true);
      }
    })();
    return () => controller.abort();
  }, []);

  const highlightKey = (highlightedCountries || []).join('|');
  useEffect(() => {
    const globe = globeRef.current;
    if (!globe || countries.length === 0) return;

    const affected = new Set((highlightedCountries || []).map((name) => name.toLowerCase()));
    globe
      .polygonsData(countries)
      .polygonAltitude(0.004)
      .polygonCapColor((f) => (affected.has(getCountryName(f).toLowerCase()) ? withAlpha(colors.high, 0.32) : colors.land))
      .polygonSideColor(() => 'rgba(0,0,0,0)')
      .polygonStrokeColor(() => colors.coast)
      .polygonLabel((f) => {
        const name = getCountryName(f);
        return `<div class="globe-tip"><div class="globe-tip__title">${escapeHtml(name)}</div>${
          currentStep ? `<div class="globe-tip__row"><span>Status</span><span>${affected.has(name.toLowerCase()) ? 'Affected' : 'Not affected'}</span></div>` : ''
        }</div>`;
      })
      .onPolygonHover((f) => { interaction.current.hovering = Boolean(f); applyRotation(); });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [countries, highlightKey, colors, phase, Boolean(currentStep)]);

  // ── Simulation: reveal arcs one by one ──
  const stepId = currentStep?.id ?? null;
  // Until this step's timers have run, show nothing; null means "reveal everything".
  const revealCount = !stepId ? null : reveal.stepId === stepId ? reveal.count : (prefersReducedMotion() ? null : 0);
  useEffect(() => {
    if (!stepId || prefersReducedMotion()) return undefined;
    const timers = [];
    for (let i = 0; i < arcs.length; i += 1) {
      timers.push(setTimeout(() => setReveal({ stepId, count: i + 1 }), 250 + i * SIM_REVEAL_STEP_MS));
    }
    timers.push(setTimeout(() => setReveal({ stepId, count: null }), 250 + arcs.length * SIM_REVEAL_STEP_MS + 50));
    return () => timers.forEach(clearTimeout);
  }, [stepId, arcs.length]);

  // ── Arcs, markers, rings ──
  useEffect(() => {
    const globe = globeRef.current;
    if (!globe) return;

    const visibleArcs = currentStep && revealCount !== null ? arcs.slice(0, revealCount) : arcs;
    const activeId = hoveredId || selectedId || null;
    const reduced = prefersReducedMotion();

    globe
      .arcsData(visibleArcs)
      .arcStartLat('sourceLat')
      .arcStartLng('sourceLng')
      .arcEndLat('targetLat')
      .arcEndLng('targetLng')
      .arcColor((arc) => {
        const dimmed = activeId && arc.id !== activeId;
        return withAlpha(classColor(arc.classification, colors), dimmed ? 0.16 : 0.92);
      })
      .arcStroke((arc) => {
        const base = 0.28 + ((arc.score || 0) / 100) * 0.3;
        return arc.id === activeId ? base * 1.7 : base;
      })
      .arcAltitude((arc) => 0.16 + hashToUnit(arc.id) * 0.08 + ((arc.intensity || 5) / 10) * 0.06)
      .arcCurveResolution(48)
      .arcDashLength(reduced ? 1 : 0.5)
      .arcDashGap(reduced ? 0 : 0.12)
      .arcDashAnimateTime(reduced ? 0 : 3200)
      .arcsTransitionDuration(reduced ? 0 : 500)
      .arcLabel((arc) => arcTooltip(arc, colors))
      .onArcHover((arc) => {
        interaction.current.hovering = Boolean(arc);
        applyRotation();
        latest.current.onHoverAttack?.(arc ? arc.id : null);
      })
      .onArcClick((arc) => {
        if (arc) latest.current.onAttackClick?.(arc);
      });

    const sourcePoints = visibleArcs.map((arc) => ({
      lat: arc.sourceLat,
      lng: arc.sourceLng,
      color: withAlpha(classColor(arc.classification, colors), arc.id === activeId || !activeId ? 1 : 0.3),
      size: arc.id === activeId ? 0.36 : 0.22,
      label: `<div class="globe-tip"><div class="globe-tip__title">${escapeHtml(arc.sourceCountry)}</div>${
        arc.sourceCity && arc.sourceCity !== 'Unknown' ? `<div class="globe-tip__row"><span>City</span><span>${escapeHtml(arc.sourceCity)}</span></div>` : ''
      }</div>`,
    }));
    const nodePoints = monitoringNode
      ? [{ lat: monitoringNode.lat, lng: monitoringNode.lng, color: colors.ink, size: 0.3, label: '<div class="globe-tip"><div class="globe-tip__title">Monitoring node</div><div class="globe-tip__hint">The feeds cannot see victims, so every route ends here.</div></div>' }]
      : [];

    globe
      .pointsData([...sourcePoints, ...nodePoints])
      .pointColor('color')
      .pointRadius('size')
      .pointAltitude(0.012)
      .pointsMerge(false)
      .pointsTransitionDuration(reduced ? 0 : 300)
      .pointLabel('label')
      .onPointHover((point) => { interaction.current.hovering = Boolean(point); applyRotation(); });

    const ringTargets = currentStep
      ? visibleArcs.slice(-4).map((arc) => ({ lat: arc.targetLat, lng: arc.targetLng, color: classColor(arc.classification, colors) }))
      : monitoringNode ? [{ lat: monitoringNode.lat, lng: monitoringNode.lng, color: colors.ink }] : [];

    globe
      .ringsData(reduced ? [] : ringTargets)
      .ringColor((ring) => (t) => withAlpha(ring.color, Math.max(0, (1 - t) * 0.5)))
      .ringMaxRadius(currentStep ? 4 : 5)
      .ringPropagationSpeed(currentStep ? 2.2 : 1.4)
      .ringRepeatPeriod(currentStep ? 1400 : 2600);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [arcs, revealCount, hoveredId, selectedId, monitoringNode, phase, currentStep?.id, colors]);

  // ── Labels: affected countries in a replay, the monitoring node when live ──
  useEffect(() => {
    const globe = globeRef.current;
    if (!globe) return;

    // globe.gl owns the outer element's transform, so the offset lives on an inner node.
    const element = (label) => {
      const el = document.createElement('div');
      const tag = document.createElement('div');
      tag.className = 'globe-label';
      tag.textContent = label.name;
      el.appendChild(tag);
      return el;
    };

    if (!currentStep?.affectedRegions?.length) {
      globe
        .htmlElementsData(monitoringNode ? [{ name: 'Monitoring node', ...monitoringNode }] : [])
        .htmlLat('lat')
        .htmlLng('lng')
        .htmlAltitude(0.02)
        .htmlElement(element);
      return;
    }

    const coords = new Map();
    (currentStep.arcs || []).forEach((arc) => {
      [[arc.targetCountry, arc.targetLat, arc.targetLng], [arc.sourceCountry, arc.sourceLat, arc.sourceLng]].forEach(([name, lat, lng]) => {
        if (!coords.has(name) && isFiniteNum(lat) && isFiniteNum(lng)) coords.set(name, { lat, lng });
      });
    });

    const labels = currentStep.affectedRegions
      .map((name) => (coords.has(name) ? { name, ...coords.get(name) } : null))
      .filter(Boolean)
      .slice(0, 6);

    globe
      .htmlElementsData(labels)
      .htmlLat('lat')
      .htmlLng('lng')
      .htmlAltitude(0.05)
      .htmlElement(element);
  }, [currentStep, monitoringNode, phase]);

  // ── Camera ──
  useEffect(() => {
    const globe = globeRef.current;
    const target = currentStep?.cameraTarget;
    if (!globe || !target) return undefined;
    const timer = setTimeout(() => {
      globe.pointOfView({ lat: target.lat, lng: target.lng, altitude: 1.8 }, prefersReducedMotion() ? 0 : 1200);
    }, 200);
    return () => clearTimeout(timer);
  }, [currentStep]);

  useEffect(() => {
    const globe = globeRef.current;
    if (!globe || currentStep || !selectedId) return;
    const arc = arcs.find((item) => item.id === selectedId);
    if (arc) globe.pointOfView({ lat: arc.sourceLat, lng: arc.sourceLng, altitude: 1.6 }, prefersReducedMotion() ? 0 : 900);
  }, [selectedId, arcs, currentStep]);

  return (
    <div
      className="relative h-full w-full overflow-hidden"
      role="img"
      aria-label={`Globe showing ${arcs.length} threat route${arcs.length === 1 ? '' : 's'}`}
    >
      <div ref={containerRef} className="absolute inset-0" />

      {phase === 'loading' && (
        <div className="absolute inset-0 grid place-items-center text-[13px] text-ink-mute" role="status">
          Loading the globe
        </div>
      )}

      {phase === 'unsupported' && (
        <div className="absolute inset-0 grid place-items-center p-6 text-center" role="alert">
          <div className="max-w-sm border-t-2 border-ink pt-3 text-left">
            <p className="condensed text-lg font-bold text-ink">3D view unavailable</p>
            <p className="mt-1 text-sm text-ink-soft">
              This browser could not start WebGL. The threat feed and charts still work.
            </p>
          </div>
        </div>
      )}

      {mapFailed && phase === 'ready' && (
        <p className="absolute top-14 left-1/2 -translate-x-1/2 bg-wash px-3 py-1 text-xs text-ink-soft" role="status">
          Country outlines could not be loaded
        </p>
      )}
    </div>
  );
};

export default GlobeView;
