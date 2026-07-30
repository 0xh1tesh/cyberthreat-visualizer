import React, { useEffect, useRef, useState } from 'react';
import Globe from 'globe.gl';
import { COLOR_MAP } from '../data/constants';
import { feature } from 'topojson-client';

const ID_TO_COUNTRY = {
  36: 'Australia',
  76: 'Brazil',
  124: 'Canada',
  156: 'China',
  170: 'Colombia',
  250: 'France',
  276: 'Germany',
  356: 'India',
  380: 'Italy',
  392: 'Japan',
  410: 'South Korea',
  528: 'Netherlands',
  616: 'Poland',
  620: 'Portugal',
  643: 'Russia',
  704: 'Vietnam',
  724: 'Spain',
  826: 'United Kingdom',
  840: 'United States'
};

const getCountryName = (featureObj) => {
  const props = featureObj?.properties || {};
  const rawName =
    props.name ||
    props.NAME ||
    props.admin ||
    props.country ||
    ID_TO_COUNTRY[Number(featureObj?.id)] ||
    `Country ${featureObj?.id ?? 'Unknown'}`;

  return String(rawName);
};

const toMarkerColor = (color) => {
  if (!color || typeof color !== 'string') return 'rgba(255, 255, 255, 0.35)';
  if (!color.startsWith('#')) return color;

  const hex = color.replace('#', '');
  const fullHex = hex.length === 3
    ? hex.split('').map((char) => `${char}${char}`).join('')
    : hex;

  const r = parseInt(fullHex.substring(0, 2), 16);
  const g = parseInt(fullHex.substring(2, 4), 16);
  const b = parseInt(fullHex.substring(4, 6), 16);

  return `rgba(${r}, ${g}, ${b}, 0.55)`;
};

const toArcColor = (color, alpha = 0.9) => {
  if (!color || typeof color !== 'string') return `rgba(255, 255, 255, ${alpha})`;
  if (color.startsWith('rgba')) {
    return color.replace(/[\d.]+\)$/, `${alpha})`);
  }
  if (!color.startsWith('#')) return color;

  const hex = color.replace('#', '');
  const fullHex = hex.length === 3
    ? hex.split('').map((char) => `${char}${char}`).join('')
    : hex;

  const r = parseInt(fullHex.substring(0, 2), 16);
  const g = parseInt(fullHex.substring(2, 4), 16);
  const b = parseInt(fullHex.substring(4, 6), 16);

  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
};

const hashStringToUnit = (value) => {
  let hash = 0;
  const input = String(value || 'arc');
  for (let i = 0; i < input.length; i++) {
    hash = ((hash << 5) - hash) + input.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash % 1000) / 1000;
};

const isFiniteNum = (v) => typeof v === 'number' && Number.isFinite(v);

const hasValidCoords = (attack) => {
  if (!attack) return false;
  return (
    isFiniteNum(attack.sourceLat) && isFiniteNum(attack.sourceLng) &&
    isFiniteNum(attack.targetLat) && isFiniteNum(attack.targetLng)
  );
};

const hasValidArcCoords = (arc) => {
  if (!arc) return false;
  return (
    isFiniteNum(arc.startLat) && isFiniteNum(arc.startLng) &&
    isFiniteNum(arc.endLat) && isFiniteNum(arc.endLng)
  );
};

const safeCoord = (v, fallback = 0) => isFiniteNum(v) ? v : fallback;

const normalizeIntensity = (intensity) => {
  if (typeof intensity !== 'number' || Number.isNaN(intensity)) return 5;
  if (intensity <= 1) return Math.min(10, Math.max(2, Math.round(intensity * 10)));
  return Math.min(10, Math.max(2, Math.round(intensity)));
};

const formatIntensity = (intensity) => `${normalizeIntensity(intensity)}/10`;

const toAttackId = (attack) => {
  if (!attack) return null;
  return attack.id || `${attack.sourceLat}-${attack.targetLat}-${attack.type || ''}-${attack.timestamp || ''}`;
};

const clampLat = (lat) => Math.max(-82, Math.min(82, Number(lat) || 0));

const wrapLng = (lng) => {
  let value = Number(lng) || 0;
  while (value > 180) value -= 360;
  while (value < -180) value += 360;
  return value;
};

const toIntensityUnit = (intensity) => {
  const numeric = Number(intensity);
  if (!Number.isFinite(numeric)) return 0.6;
  const scaled = numeric <= 1 ? numeric : numeric / 10;
  return Math.max(0.2, Math.min(1, scaled));
};

const MAX_LIVE_ARCS = 8;
const MAX_VISIBLE_ARCS_TOTAL = 8;
const MAX_MARKERS = 8;
const ARC_FADE_IN_MS = 500;
const ARC_HOLD_MS = 4500;
const ARC_FADE_OUT_MS = 2600;
const ARC_TOTAL_VISIBLE_MS = ARC_FADE_IN_MS + ARC_HOLD_MS + ARC_FADE_OUT_MS;
const ARC_CACHE_TTL_MS = ARC_TOTAL_VISIBLE_MS + 1200;
const IMPACT_PULSE_DURATION_MS = 640;
const SIM_SUPPORT_ARCS_PER_BASE = 1;
const SIM_STAGGER_START_MS = 300;
const SIM_STAGGER_STEP_MS = 120;

const ARC_SEMANTIC_GRADIENTS = {
  ddos: {
    start: '#ff3b4d',
    end: '#ffd166',
    glowStart: '#ff6270',
    glowEnd: '#ffe39a',
  },
  malware: {
    start: '#ff9f1a',
    end: '#ffd166',
    glowStart: '#ffbf57',
    glowEnd: '#ffe39a',
  },
  scan: {
    start: '#2ee08a',
    end: '#57ddff',
    glowStart: '#6bf3af',
    glowEnd: '#8ee9ff',
  },
};

const getArcGradientPalette = (type, fallbackColor) => {
  const normalizedType = String(type || '').toLowerCase();
  if (normalizedType.includes('ddos')) return ARC_SEMANTIC_GRADIENTS.ddos;
  if (normalizedType.includes('malware')) return ARC_SEMANTIC_GRADIENTS.malware;
  if (normalizedType.includes('scan')) return ARC_SEMANTIC_GRADIENTS.scan;

  return {
    start: fallbackColor || '#57ddff',
    end: '#9de7ff',
    glowStart: fallbackColor || '#8ce7ff',
    glowEnd: '#baf0ff',
  };
};

const expandSimulationArcs = (baseArcs = []) => {
  if (!Array.isArray(baseArcs) || baseArcs.length === 0) return [];

  const expanded = [];
  baseArcs.forEach((attack, index) => {
    if (!hasValidCoords(attack)) return;

    const baseId = toAttackId(attack) || `sim-${index}`;
    expanded.push(attack);

    const sourceIntensity = toIntensityUnit(attack.intensity);

    for (let layer = 1; layer <= SIM_SUPPORT_ARCS_PER_BASE; layer += 1) {
      const seed = hashStringToUnit(`${baseId}-support-${layer}`);
      const spread = (0.7 + (seed * 1.2)) * layer;
      const direction = layer % 2 === 0 ? -1 : 1;

      expanded.push({
        ...attack,
        id: `${baseId}-support-${layer}`,
        sourceAttackId: baseId,
        sourceLat: clampLat(attack.sourceLat + (direction * spread * 0.34)),
        sourceLng: wrapLng(attack.sourceLng - (direction * spread * 0.68)),
        targetLat: clampLat(attack.targetLat - (direction * spread * 0.3)),
        targetLng: wrapLng(attack.targetLng + (direction * spread * 0.58)),
        intensity: Math.max(0.32, Math.min(1, sourceIntensity * (0.86 - ((layer - 1) * 0.16)))),
        isSimulationSupport: true,
      });
    }
  });

  return expanded;
};

const GlobeView = ({
  attacks,
  currentStep,
  highlightedCountries = [],
  currentSim,
  isPlaying,
  onCountryClick,
  onAttackClick,
  selectedCountry,
  selectedAttack
}) => {
  const globeRef = useRef();
  const containerRef = useRef();
  const [dimensions, setDimensions] = useState({ width: window.innerWidth, height: window.innerHeight });
  const [countries, setCountries] = useState([]);
  const [isHovering, setIsHovering] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [pulseProgress, setPulseProgress] = useState(0);
  const lastPulseStepId = useRef(null);
  const pulseAnimationFrame = useRef(null);
  const cachedArcsRef = useRef(new Map());
  const arcFirstSeenRef = useRef(new Map());
  const [visibleArcCount, setVisibleArcCount] = useState(null); // null = show all (live mode)
  const staggerTimersRef = useRef([]);
  const [hoveredArcId, setHoveredArcId] = useState(null);
  const [fadeTick, setFadeTick] = useState(0);
  const lastCameraFocusKeyRef = useRef(null);
  const lastStaggerStepKeyRef = useRef(null);
  const attackCount = Array.isArray(attacks) ? attacks.length : 0;

  // Reactive rotation control
  useEffect(() => {
    if (globeRef.current) {
      const shouldRotate = (currentStep ? isPlaying : true) && !isHovering && !isDragging;
      globeRef.current.controls().autoRotate = shouldRotate;
    }
  }, [isPlaying, isHovering, isDragging, currentStep]);

  // Easing function: ease-out-in for natural pulse effect
  const easeOutIn = (t) => {
    // Quick expansion (ease-out), then settled return (ease-in)
    const halfway = 0.5;
    if (t < halfway) {
      // First half: ease-out (decelerate)
      const normalized = t / halfway;
      return 1 - Math.pow(1 - normalized, 2);
    } else {
      // Second half: ease-in (accelerate back)
      const normalized = (t - halfway) / halfway;
      return 1 - Math.pow(normalized, 2);
    }
  };

  // Helper: Get destination point color with brightness boost during pulse
  const destinationPointColor = (baseColor, progress) => {
    if (!baseColor || typeof baseColor !== 'string') {
      return `rgba(255, 255, 255, ${0.7 + progress * 0.3})`;
    }
    if (!baseColor.startsWith('#')) return baseColor;

    const hex = baseColor.replace('#', '');
    const fullHex =
      hex.length === 3
        ? hex.split('').map((char) => `${char}${char}`).join('')
        : hex;

    const r = parseInt(fullHex.substring(0, 2), 16);
    const g = parseInt(fullHex.substring(2, 4), 16);
    const b = parseInt(fullHex.substring(4, 6), 16);

    // Boost opacity from 0.7 → 1.0 during pulse, with eased progress
    const easedProgress = easeOutIn(progress);
    const opacity = 0.7 + easedProgress * 0.3;
    return `rgba(${r}, ${g}, ${b}, ${opacity})`;
  };

  // Helper: Trigger pulse animation on step change
  const triggerPulse = () => {
    // Cancel any ongoing animation
    if (pulseAnimationFrame.current) {
      cancelAnimationFrame(pulseAnimationFrame.current);
    }

    const startTime = Date.now();
    const duration = IMPACT_PULSE_DURATION_MS;

    const animate = () => {
      const elapsed = Date.now() - startTime;
      const progress = Math.min(elapsed / duration, 1);
      setPulseProgress(progress);

      if (progress < 1) {
        pulseAnimationFrame.current = requestAnimationFrame(animate);
      } else {
        pulseAnimationFrame.current = null;
      }
    };

    pulseAnimationFrame.current = requestAnimationFrame(animate);
  };



  useEffect(() => {
    // Handle window resize
    const handleResize = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.clientWidth,
          height: containerRef.current.clientHeight
        });
      }
    };

    window.addEventListener('resize', handleResize);
    handleResize(); // Init size

    return () => window.removeEventListener('resize', handleResize);
  }, []);

  useEffect(() => {
    if (!containerRef.current) return;

    // Initialize globe
    const globe = Globe()(containerRef.current)
      .globeImageUrl('https://unpkg.com/three-globe/example/img/earth-night.jpg')
      .bumpImageUrl('https://unpkg.com/three-globe/example/img/earth-topology.png')
      .backgroundImageUrl('https://unpkg.com/three-globe/example/img/night-sky.png')
      .backgroundColor('rgba(0,0,0,0)')
      .width(dimensions.width)
      .height(dimensions.height)
      .showAtmosphere(true)
      .atmosphereColor('#2a8ac7')
      .atmosphereAltitude(0.24);

    const globeMaterial = globe.globeMaterial();
    if (globeMaterial) {
      globeMaterial.shininess = 28;
      globeMaterial.emissiveIntensity = 0.22;
      globeMaterial.bumpScale = 0.58;
    }

    const renderer = globe.renderer?.();
    if (renderer) {
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
      renderer.toneMappingExposure = 1.18;
    }


    // Apply auto-rotate
    globe.controls().autoRotate = true;
    globe.controls().autoRotateSpeed = 0.2;
    globe.controls().enableDamping = true;
    globe.controls().dampingFactor = 0.06;

    // Handle drag state for reactive rotation
    globe.controls().addEventListener('start', () => setIsDragging(true));
    globe.controls().addEventListener('end', () => setIsDragging(false));
    
    // Setup initial point of view
    globe.pointOfView({ lat: 20, lng: 0, altitude: 1.92 });

    globeRef.current = globe;

    // Cleanup on unmount
    return () => {
      globe._destructor();
    };
  }, []); 

  useEffect(() => {
    const intervalId = setInterval(() => {
      setFadeTick((prev) => (prev + 1) % 1000000);
    }, 110);
    return () => clearInterval(intervalId);
  }, []);

  useEffect(() => {
    let cancelled = false;

    const loadCountries = async () => {
      try {
        const response = await fetch('https://unpkg.com/world-atlas@2/countries-110m.json');
        const topoData = await response.json();
        const geoJson = feature(topoData, topoData.objects.countries);
        if (!cancelled) {
          setCountries(geoJson.features || []);
        }
      } catch (error) {
        console.error('Failed to load world countries:', error);
      }
    };

    loadCountries();
    return () => {
      cancelled = true;
    };
  }, []);
  
  // Re-run this effect when dimensions update to resize globe
  useEffect(() => {
    if (globeRef.current) {
      globeRef.current.width(dimensions.width).height(dimensions.height);
    }
  }, [dimensions]);

  useEffect(() => {
    const clearStaggerTimers = () => {
      staggerTimersRef.current.forEach((timer) => clearTimeout(timer));
      staggerTimersRef.current = [];
    };

    if (!currentStep?.id) {
      clearStaggerTimers();
      lastStaggerStepKeyRef.current = null;
      setVisibleArcCount(null);
      return undefined;
    }

    const stepKey = `${currentStep.id}:${attackCount}`;
    if (lastStaggerStepKeyRef.current === stepKey) {
      return undefined;
    }

    lastStaggerStepKeyRef.current = stepKey;
    clearStaggerTimers();

    const validAttacks = (Array.isArray(attacks) ? attacks : []).filter(hasValidCoords);
    const simulationExpandedAttacks = expandSimulationArcs(validAttacks);
    const totalArcs = Math.min(MAX_VISIBLE_ARCS_TOTAL, simulationExpandedAttacks.length * 2);

    if (totalArcs <= 0) {
      setVisibleArcCount(0);
      return undefined;
    }

    setVisibleArcCount(0);

    for (let i = 0; i < totalArcs; i += 1) {
      const timer = setTimeout(() => {
        setVisibleArcCount(i + 1);
      }, SIM_STAGGER_START_MS + (i * SIM_STAGGER_STEP_MS));
      staggerTimersRef.current.push(timer);
    }

    const finalTimer = setTimeout(
      () => setVisibleArcCount(null),
      SIM_STAGGER_START_MS + (totalArcs * SIM_STAGGER_STEP_MS) + 60
    );
    staggerTimersRef.current.push(finalTimer);

    return () => {
      clearStaggerTimers();
    };
  }, [currentStep?.id, attackCount]);

  useEffect(() => {
    if (!globeRef.current) return;

    // Cache cleanup keeps memory bounded while allowing a full cinematic fade lifecycle.
    const now = Date.now();
    const maxAge = currentStep ? 30000 : ARC_CACHE_TTL_MS;
    for (const [id, createdAt] of arcFirstSeenRef.current.entries()) {
      if (now - createdAt > maxAge) {
        arcFirstSeenRef.current.delete(id);
        cachedArcsRef.current.delete(id);
        cachedArcsRef.current.delete(id + '_glow');
      }
    }

    const selectedAttackId = toAttackId(selectedAttack);
    const selectedCountryLower = selectedCountry ? selectedCountry.toLowerCase() : null;

    // Filter attacks with invalid coordinates before any rendering
    const validAttacks = (Array.isArray(attacks) ? attacks : []).filter(hasValidCoords);

    // Limit live clutter while preserving full buffer in state.
    const simulationExpandedAttacks = currentStep ? expandSimulationArcs(validAttacks) : validAttacks;
    const attacksForRender = currentStep ? simulationExpandedAttacks : validAttacks.slice(-MAX_LIVE_ARCS);

    // Detect top 2 most intense live attacks for visual priority
    const liveAttacks = !currentStep ? attacksForRender : [];
    const top2Ids = new Set();
    if (liveAttacks.length > 0) {
      [...liveAttacks]
        .sort((a, b) => (b.intensity || 0) - (a.intensity || 0))
        .slice(0, 2)
        .forEach(attack => {
          const id = attack.id || `${attack.sourceLat}-${attack.targetLat}-${attack.type || ''}-${attack.timestamp || ''}`;
          top2Ids.add(id);
        });
    }

    // Map attacks to arcs data, using a cache to preserve object identity and prevent animation reset
    const getAllArcs = (sourceArcs) => sourceArcs.flatMap(attack => {
      // Skip attacks with invalid coordinates — never send bad data to globe.gl
      if (!hasValidCoords(attack)) return [];

      const id = attack.id || `${attack.sourceLat}-${attack.targetLat}-${attack.type || ''}-${attack.timestamp || ''}`;
      const baseAttackId = String(attack.sourceAttackId || id);
      
      let mapped = cachedArcsRef.current.get(id);
      if (!mapped) {
        const baseColor = attack.color || currentStep?.arcColor || COLOR_MAP[attack.type];
        const gradient = getArcGradientPalette(attack.type, baseColor);
        const rawCurveOffset = hashStringToUnit(id) * 0.08;
        const supportLift = attack.isSimulationSupport ? (0.045 + (hashStringToUnit(`${id}-lift`) * 0.05)) : 0;
        const curveOffset = rawCurveOffset + supportLift;
        mapped = {
          ...attack,
          id,
          baseId: baseAttackId,
          startLat: attack.sourceLat,
          startLng: attack.sourceLng,
          endLat: attack.targetLat,
          endLng: attack.targetLng,
          baseColor,
          coreStartColor: gradient.start,
          coreEndColor: gradient.end,
          glowStartColor: gradient.glowStart,
          glowEndColor: gradient.glowEnd,
          markerSourceColor: gradient.start,
          markerTargetColor: gradient.end,
          curveOffset,
          isSimulationSupport: Boolean(attack.isSimulationSupport),
          color: toArcColor(baseColor, 0.9),
          glowColor: toArcColor(baseColor, 0.3)
        };
        cachedArcsRef.current.set(id, mapped);
        arcFirstSeenRef.current.set(id, Date.now());
      }

      const glowId = id + '_glow';
      let mappedGlow = cachedArcsRef.current.get(glowId);
      if (!mappedGlow) {
        mappedGlow = { ...mapped, id: glowId, baseId: baseAttackId, isGlow: true };
        cachedArcsRef.current.set(glowId, mappedGlow);
      }

      return [mappedGlow, mapped];
    });

    const fullArcsData = getAllArcs(attacksForRender).slice(0, MAX_VISIBLE_ARCS_TOTAL);

    const arcsData = currentStep && visibleArcCount !== null
      ? fullArcsData.slice(0, visibleArcCount * 2)
      : fullArcsData;

    const markerArcs = arcsData
      .filter((arc) => !arc.isGlow)
      .slice(0, currentStep ? 18 : MAX_MARKERS);

    const seenOrigins = new Set();
    const sourceMarkers = markerArcs
      .filter((arc) => {
        if (!hasValidArcCoords(arc)) return false;
        const key = `${arc.startLat.toFixed(2)}:${arc.startLng.toFixed(2)}`;
        if (seenOrigins.has(key)) return false;
        seenOrigins.add(key);
        return true;
      })
      .map((arc) => ({
        lat: arc.startLat,
        lng: arc.startLng,
        size: 0.14 + ((normalizeIntensity(arc.intensity) / 10) * 0.08),
        color: toMarkerColor(arc.markerSourceColor || arc.coreStartColor)
      }));

    // Destination impact markers at arc targets with pulse animation
    const destinationMarkers = markerArcs
      .filter((arc) => hasValidArcCoords(arc))
      .map((arc, index) => ({
        id: `${arc.baseId || arc.id}-impact-${index}`,
        lat: arc.endLat,
        lng: arc.endLng,
        size: 0.24 + ((normalizeIntensity(arc.intensity) / 10) * 0.12),
        color: arc.markerTargetColor || arc.coreEndColor,
        ringColor: arc.glowEndColor || arc.coreEndColor,
        intensity: arc.intensity
      }));

    // Subtle source markers (clean indicator replacing pulsing rings)
    if (currentStep && lastPulseStepId.current !== currentStep.id) {
      lastPulseStepId.current = currentStep.id;
      triggerPulse();
    }

    // Configure Arcs
    const getArcAlpha = (arc) => {
      const baseId = arc.baseId || String(arc.id).replace('_glow', '');
      const seenAt = arcFirstSeenRef.current.get(baseId) || now;
      const ageMs = now - seenAt;

      let lifecycleAlpha = 1;
      if (!currentStep) {
        if (ageMs < ARC_FADE_IN_MS) {
          lifecycleAlpha = ageMs / ARC_FADE_IN_MS;
        } else if (ageMs > (ARC_FADE_IN_MS + ARC_HOLD_MS)) {
          const fadeElapsed = ageMs - (ARC_FADE_IN_MS + ARC_HOLD_MS);
          lifecycleAlpha = Math.max(0, 1 - (fadeElapsed / ARC_FADE_OUT_MS));
        }
      }

      const hasHover = Boolean(hoveredArcId);
      const hasSelection = !currentStep && Boolean(selectedAttackId || selectedCountryLower);
      const arcMatchesCountry = Boolean(
        selectedCountryLower && (
          String(arc.sourceCountry || '').toLowerCase() === selectedCountryLower ||
          String(arc.targetCountry || '').toLowerCase() === selectedCountryLower
        )
      );
      const arcMatchesSelection = selectedAttackId
        ? baseId === selectedAttackId
        : arcMatchesCountry;

      let focusAlpha = 1;
      if (hasHover) {
        focusAlpha = baseId === hoveredArcId ? 1 : 0.22;
      } else if (hasSelection) {
        focusAlpha = arcMatchesSelection ? 1 : 0.24;
      }

      const baseAlpha = arc.isGlow
        ? (currentStep ? 0.42 : 0.6)
        : (currentStep ? 0.78 : 0.95);

      return baseAlpha * lifecycleAlpha * focusAlpha;
    };

    globeRef.current
      .arcsData(arcsData)
      .arcColor((arc) => {
         let alpha = getArcAlpha(arc);
         if (arc.provider === 'fallback') alpha *= 0.78;

         const normalized = normalizeIntensity(arc.intensity) / 10;
         if (arc.isGlow) {
           alpha = Math.min(1, alpha * ((currentStep ? 0.9 : 1.22) + (normalized * (currentStep ? 0.05 : 0.12))));
         } else {
           alpha = Math.min(1, alpha * ((currentStep ? 0.86 : 0.98) + (normalized * (currentStep ? 0.02 : 0.06))));
         }

         if (currentStep && arc.isSimulationSupport) {
           alpha *= 0.58;
         }

         const startColor = arc.isGlow
           ? (arc.glowStartColor || arc.coreStartColor || arc.baseColor)
           : (arc.coreStartColor || arc.baseColor);
         const endColor = arc.isGlow
           ? (arc.glowEndColor || arc.coreEndColor || arc.baseColor)
           : (arc.coreEndColor || arc.baseColor);

         return [toArcColor(startColor, alpha), toArcColor(endColor, alpha)];
      })
      .arcStroke((arc) => {
        const normalized = normalizeIntensity(arc.intensity);
        const baseId = arc.baseId || String(arc.id).replace('_glow', '');
        const isTop2 = top2Ids.has(baseId);
        const hasSelection = !currentStep && Boolean(selectedAttackId || selectedCountryLower);
        const arcMatchesCountry = Boolean(
          selectedCountryLower && (
            String(arc.sourceCountry || '').toLowerCase() === selectedCountryLower ||
            String(arc.targetCountry || '').toLowerCase() === selectedCountryLower
          )
        );
        const arcMatchesSelection = selectedAttackId
          ? baseId === selectedAttackId
          : arcMatchesCountry;

        let focusBoost = 1;
        if (hoveredArcId) {
          focusBoost = baseId === hoveredArcId ? 1.22 : 0.86;
        } else if (hasSelection) {
          focusBoost = arcMatchesSelection ? 1.2 : 0.8;
        }

        const top2Boost = isTop2 ? 1.12 : 1;
        const width = arc.isGlow
          ? (currentStep ? 0.72 + normalized * 0.05 : 1.1 + normalized * 0.08)
          : (currentStep ? 0.28 + normalized * 0.035 : 0.4 + normalized * 0.05);
        const simulationSupportScale = currentStep && arc.isSimulationSupport ? 0.72 : 1;
        return width * focusBoost * top2Boost * simulationSupportScale;
      })
      .arcAltitude((arc) => {
        const baseAltitude = currentStep
          ? 0.18 + (arc.curveOffset * 0.85) + (normalizeIntensity(arc.intensity) * 0.0065)
          : 0.2 + (arc.curveOffset * 0.8) + (normalizeIntensity(arc.intensity) * 0.008);
        return arc.isGlow ? baseAltitude + 0.002 : baseAltitude;
      })
      .arcDashLength(currentStep ? 0.38 : 0.42)
      .arcDashGap(currentStep ? 0.22 : 0.18)
      .arcDashAnimateTime(currentStep ? 2400 : 1950)
      .arcsTransitionDuration(currentStep ? 780 : 560)
      
      // Custom tooltip for arcs
      .arcLabel(attack => `
        <div class="globe-tooltip">
          <div class="tooltip-header">
            <span class="${String(attack.type || 'unknown').toLowerCase()}-text">●</span> ${attack.type || 'Unknown'} Attack
          </div>
          <div class="tooltip-body">
            <div class="tooltip-row">
              <span class="tooltip-label">Source:</span>
              <span>${attack.provider ? String(attack.provider).toUpperCase() : 'UNKNOWN'}</span>
            </div>
            <div class="tooltip-row">
              <span class="tooltip-label">Route:</span>
              <span>${attack.sourceCountry || 'Unknown'} → ${attack.targetCountry || 'Unknown'}</span>
            </div>
            <div class="tooltip-row">
              <span class="tooltip-label">Type:</span>
              <span>${attack.type || 'Unknown'}</span>
            </div>
            <div class="tooltip-row">
              <span class="tooltip-label">Intensity:</span>
              <span>${formatIntensity(attack.intensity)}</span>
            </div>
            <div style="margin-top: 8px; font-size: 0.75rem; color: #999;">Click for details</div>
          </div>
        </div>
      `)
      // Hover interaction for arcs
      .onArcHover((arc) => {
        setIsHovering(!!arc);
        setHoveredArcId(arc ? (arc.baseId || String(arc.id).replace('_glow', '')) : null);
      })
      .onArcClick((arc) => {
        if (!arc || typeof onAttackClick !== 'function') return;
        const baseId = arc.baseId || String(arc.id || '').replace('_glow', '');
        if (!baseId) return;

        const clickedAttack = attacksForRender.find((attack) => toAttackId(attack) === baseId)
          || validAttacks.find((attack) => toAttackId(attack) === baseId);

        if (clickedAttack) {
          onAttackClick(clickedAttack);
        }
      });

    // Source marker configuration
    // Combine source and destination markers into single points array
    const allMarkers = [
      ...sourceMarkers,
      ...destinationMarkers.map((marker) => ({
        ...marker,
        altitude: 0.02, // Destination points slightly higher to avoid z-fighting
        isDestination: true // Tag for dynamic color calculation
      }))
    ];

    const globeInstance = globeRef.current;

    globeInstance
      .pointsData(allMarkers)
      .pointColor((point) => {
        // For destination points, apply pulse brightness boost
        if (point.isDestination) {
          return destinationPointColor(point.color, pulseProgress);
        }
        // Source points stay constant
        return toMarkerColor(point.color);
      })
      .pointRadius((point) => {
        // For destination points, apply expansion pulse (1x to 2x)
        if (point.isDestination) {
          const easedProgress = easeOutIn(pulseProgress);
          const pulseBoost = currentStep ? 1.55 : 1.35;
          return point.size * (1 + (easedProgress * pulseBoost));
        }
        // Source points stay constant
        return point.size;
      })
      .pointAltitude((point) => point.altitude || 0.018)
      .pointsMerge(false)
      .pointsTransitionDuration(700)
      .pointLabel(point => `
        <div class="globe-tooltip">
          <div class="tooltip-body">
            <span class="tooltip-label">${point.isDestination ? 'Target Impact Point' : 'Attack Source Point'}</span>
            ${point.intensity ? `<br/><span style="margin-top: 4px; display: inline-block;">Intensity: ${formatIntensity(point.intensity)}</span>` : ''}
          </div>
        </div>
      `)
      .onPointHover((point) => setIsHovering(!!point));

    // Impact ripple rings are optional depending on globe.gl feature availability.
    if (
      typeof globeInstance.ringsData === 'function' &&
      typeof globeInstance.ringColor === 'function' &&
      typeof globeInstance.ringMaxRadius === 'function' &&
      typeof globeInstance.ringPropagationSpeed === 'function' &&
      typeof globeInstance.ringRepeatPeriod === 'function'
    ) {
      globeInstance
        .ringsData(destinationMarkers)
        .ringColor((marker) => (t) => {
          const alpha = Math.max(0, (1 - t) * 0.72);
          return toArcColor(marker.ringColor || marker.color, alpha);
        })
        .ringMaxRadius((marker) => (
          currentStep
            ? 0.62 + ((normalizeIntensity(marker.intensity) / 10) * 0.52)
            : 0.52 + ((normalizeIntensity(marker.intensity) / 10) * 0.5)
        ))
        .ringPropagationSpeed((marker) => (
          currentStep
            ? 0.46 + ((normalizeIntensity(marker.intensity) / 10) * 0.34)
            : 0.58 + ((normalizeIntensity(marker.intensity) / 10) * 0.42)
        ))
        .ringRepeatPeriod((marker) => (
          currentStep
            ? 1320 + ((10 - normalizeIntensity(marker.intensity)) * 110)
            : 1080 + ((10 - normalizeIntensity(marker.intensity)) * 95)
        ));

      if (typeof globeInstance.ringsTransitionDuration === 'function') {
        globeInstance.ringsTransitionDuration(350);
      }
    }

  }, [attacks, currentStep, pulseProgress, visibleArcCount, hoveredArcId, fadeTick, selectedAttack, selectedCountry, onAttackClick]);

  useEffect(() => {
    if (!globeRef.current || !countries.length) return;
    if (typeof globeRef.current.polygonsData !== 'function') return;

    const normalized = new Set(highlightedCountries.map((country) => country.toLowerCase()));
    const highlightColor = currentSim === 'mirai' ? 'rgba(82, 196, 255, 0.24)' : 'rgba(255,60,60,0.24)';

    globeRef.current
      .polygonsData(countries)
      .polygonAltitude(0.012)
      .polygonCapColor((featureObj) => {
        const name = getCountryName(featureObj).toLowerCase();
        return normalized.has(name) ? highlightColor : 'rgba(98, 158, 208, 0.25)';
      })
      .polygonSideColor(() => 'rgba(130, 190, 235, 0.12)')
      .polygonStrokeColor(() => 'rgba(176, 232, 255, 0.72)')
      .polygonLabel((featureObj) => {
        const countryName = getCountryName(featureObj);
        const isAffected = normalized.has(countryName.toLowerCase());
        return `
          <div class="country-hover-tooltip">
            <strong>${countryName}</strong><br/>
            ${isAffected ? 'Affected' : 'Not affected'}
          </div>
        `;
      })
      .onPolygonClick((featureObj) => {
        if (!currentStep || !onCountryClick) return;

        const countryName = getCountryName(featureObj);
        const attackCount = currentStep.arcs.filter((arc) =>
          arc.sourceCountry === countryName || arc.targetCountry === countryName
        ).length;

        const role = currentStep.affectedRegions.includes(countryName) ? 'Affected' : 'Unaffected';

        onCountryClick({
          name: countryName,
          role,
          attackCount,
          attackType: currentStep.attackType
        });
      })
      // Hover interaction for polygons
      .onPolygonHover((feature) => setIsHovering(!!feature));

  }, [countries, highlightedCountries, currentSim, currentStep, onCountryClick]);

  useEffect(() => {
    if (!globeRef.current) return;

    if (!currentStep?.affectedRegions?.length) {
      globeRef.current.htmlElementsData([]);
      return;
    }

    const coordMap = new Map();
    (currentStep.arcs || []).forEach((arc) => {
      if (!coordMap.has(arc.targetCountry) && isFiniteNum(arc.targetLat) && isFiniteNum(arc.targetLng)) {
        coordMap.set(arc.targetCountry, { lat: arc.targetLat, lng: arc.targetLng });
      }
      if (!coordMap.has(arc.sourceCountry) && isFiniteNum(arc.sourceLat) && isFiniteNum(arc.sourceLng)) {
        coordMap.set(arc.sourceCountry, { lat: arc.sourceLat, lng: arc.sourceLng });
      }
    });

    const labelData = currentStep.affectedRegions
      .map((country) => {
        const coords = coordMap.get(country);
        return coords ? { name: country, lat: coords.lat, lng: coords.lng } : null;
      })
      .filter(Boolean)
      .slice(0, 6);

    globeRef.current
      .htmlElementsData(labelData)
      .htmlLat('lat')
      .htmlLng('lng')
      .htmlAltitude(0.06)
      .htmlElement((label) => {
        const el = document.createElement('div');
        el.className = `country-step-label ${currentSim === 'mirai' ? 'country-step-label-mirai' : 'country-step-label-wannacry'}`;
        el.textContent = label.name;
        return el;
      });
  }, [currentStep, currentSim]);

  // Cleanup animation on unmount
  useEffect(() => {
    return () => {
      if (pulseAnimationFrame.current) {
        cancelAnimationFrame(pulseAnimationFrame.current);
        pulseAnimationFrame.current = null;
      }
    };
  }, []);

  useEffect(() => {
    if (!globeRef.current || !currentStep?.cameraTarget) return;

    // Camera transition begins at 200ms delay after step change
    const t = setTimeout(() => {
      globeRef.current.pointOfView(
        {
          lat: currentStep.cameraTarget.lat,
          lng: currentStep.cameraTarget.lng,
          altitude: 1.8
        },
        1200
      );
    }, 200);
    return () => clearTimeout(t);
  }, [currentStep]);

  useEffect(() => {
    if (!globeRef.current || currentStep) return;

    const animationMs = 900;
    const selectedAttackId = toAttackId(selectedAttack);
    const focusKey = selectedAttackId
      ? `attack:${selectedAttackId}`
      : selectedCountry
        ? `country:${String(selectedCountry).toLowerCase()}`
        : null;

    // Apply camera focus only when the selected target changes.
    // This prevents repeated recentering that can feel like camera lock.
    if (!focusKey) {
      lastCameraFocusKeyRef.current = null;
      return;
    }

    if (lastCameraFocusKeyRef.current === focusKey) {
      return;
    }

    lastCameraFocusKeyRef.current = focusKey;

    if (selectedAttack) {
      const midLat = (safeCoord(selectedAttack.sourceLat) + safeCoord(selectedAttack.targetLat)) / 2;
      const midLng = (safeCoord(selectedAttack.sourceLng) + safeCoord(selectedAttack.targetLng)) / 2;
      globeRef.current.pointOfView({ lat: midLat, lng: midLng, altitude: 1.45 }, animationMs);
      return;
    }

    if (selectedCountry) {
      const selectedLower = selectedCountry.toLowerCase();
      const relatedArc = attacks.find((attack) =>
        String(attack.sourceCountry || '').toLowerCase() === selectedLower ||
        String(attack.targetCountry || '').toLowerCase() === selectedLower
      );

      if (!relatedArc) return;

      const isSource = String(relatedArc.sourceCountry || '').toLowerCase() === selectedLower;
      const arcLat = isSource ? relatedArc.sourceLat : relatedArc.targetLat;
      const arcLng = isSource ? relatedArc.sourceLng : relatedArc.targetLng;
      if (!isFiniteNum(arcLat) || !isFiniteNum(arcLng)) return;
      globeRef.current.pointOfView(
        {
          lat: arcLat,
          lng: arcLng,
          altitude: 1.6
        },
        animationMs
      );
    }
  }, [selectedAttack, selectedCountry, attacks, currentStep]);

  return (
    <div style={styles.wrapper}>
      <div style={styles.ambientGlow}></div>
      <div style={styles.overlay}></div>
      <div style={styles.cyberScan}></div>
      <div ref={containerRef} style={styles.container}></div>
    </div>
  );
};

const styles = {
  wrapper: {
    flex: 1,
    position: 'relative',
    height: '100%',
    width: '100%',
    backgroundColor: '#061223',
    overflow: 'hidden'
  },
  container: {
    width: '100%',
    height: '100%',
    position: 'absolute',
    top: 0,
    left: 0,
    zIndex: 5
  },
  ambientGlow: {
    pointerEvents: 'none',
    position: 'absolute',
    top: '50%',
    left: '50%',
    width: '88%',
    height: '88%',
    transform: 'translate(-50%, -50%)',
    borderRadius: '50%',
    background: 'radial-gradient(circle at center, rgba(58, 176, 255, 0.36) 0%, rgba(58, 176, 255, 0.14) 46%, rgba(0, 0, 0, 0) 74%)',
    filter: 'blur(28px)',
    zIndex: 1,
  },
  overlay: {
    pointerEvents: 'none',
    position: 'absolute',
    top: 0,
    left: 0,
    width: '100%',
    height: '100%',
    background: 'radial-gradient(circle at center, rgba(0, 0, 0, 0) 38%, rgba(8, 15, 26, 0.24) 68%, rgba(5, 9, 17, 0.5) 100%)',
    zIndex: 2
  },
  cyberScan: {
    pointerEvents: 'none',
    position: 'absolute',
    top: 0,
    left: 0,
    width: '100%',
    height: '100%',
    zIndex: 6,
    opacity: 0.08,
    backgroundImage:
      'repeating-linear-gradient(0deg, rgba(87, 221, 255, 0.08) 0px, rgba(87, 221, 255, 0.08) 1px, transparent 1px, transparent 5px)',
    mixBlendMode: 'normal'
  }
};

export default GlobeView;
