// Attack type classifications and color mappings
// These are used by normalizers and the globe visualization

export const ATTACK_TYPES = {
  DDOS: 'DDoS',
  MALWARE: 'Malware',
  SCAN: 'Scan'
};

export const COLOR_MAP = {
  [ATTACK_TYPES.DDOS]: '#ff6b6b',
  [ATTACK_TYPES.MALWARE]: '#ffb454',
  [ATTACK_TYPES.SCAN]: '#5fd4a0'
};

let simIdCounter = 0;
export const generateId = () => `sim-${++simIdCounter}`;


// Derive a score (0–100) and classification consistent with the arc type and intensity.
// This ensures normalizeAttackData() never falls back to scoring from absent signals,
// which would produce score=0 / classification=LOW even for Malware arcs.
const TYPE_BASE_SCORE = {
  [ATTACK_TYPES.DDOS]:    { min: 75, max: 100 }, // DDOS classification threshold ≥ 75
  [ATTACK_TYPES.MALWARE]: { min: 50, max:  74 }, // MALWARE classification threshold ≥ 50
  [ATTACK_TYPES.SCAN]:    { min: 30, max:  49 }, // SCAN classification threshold ≥ 30
};

const TYPE_TO_CLASSIFICATION = {
  [ATTACK_TYPES.DDOS]:    'DDOS',
  [ATTACK_TYPES.MALWARE]: 'MALWARE',
  [ATTACK_TYPES.SCAN]:    'SCAN',
};

const deriveSimScore = (type, intensity) => {
  const range = TYPE_BASE_SCORE[type] || { min: 30, max: 49 };
  // Scale intensity (0–1) within the type's score band
  const safeIntensity = Math.max(0, Math.min(1, Number(intensity) || 0.5));
  return Math.round(range.min + safeIntensity * (range.max - range.min));
};

const createArc = ({
  sourceLat,
  sourceLng,
  sourceCountry,
  targetLat,
  targetLng,
  targetCountry,
  type,
  intensity,
  color,
  timestamp = Date.now()
}) => {
  const score = deriveSimScore(type, intensity);
  const classification = TYPE_TO_CLASSIFICATION[type] || 'SCAN';
  // Represent intensity as an otxHits-equivalent signal so the scoring pipeline
  // has real data and produces a consistent normalizedScore.
  const otxHits = Math.round((Number(intensity) || 0.5) * 10);
  return {
    id: generateId(),
    sourceLat,
    sourceLng,
    sourceCountry,
    synthetic: true,
    targetLat,
    targetLng,
    targetCountry,
    type,
    intensity,
    color,
    timestamp,
    // Pre-computed scoring so normalizeAttackData honours type, not recalculates from nulls
    score,
    classification,
    signals: {
      abuseScore: null,
      otxHits,
      portExposure: null,
      usedSources: ['otx'],
      missingSources: ['abuseipdb', 'shodan'],
      activeWeight: 0.3,
    },
  };
};

// ── Simulation scenario steps (educational content, not mock data) ──

const baseWannacrySteps = [
  {
    id: 'wannacry-step-1',
    title: 'Initial Infection Vector',
    description:
      'WannaCry activated May 12 2017 via the M.E.Doc accounting software supply chain in Ukraine. Within 90 seconds every Windows host on the local network was encrypted. Most victims never paid ransom because the payment portal collapsed under load.',
    technicalInsight: 'EternalBlue MS17-010 SMBv1 remote code execution, DoublePulsar backdoor, port 445',
    attackType: ATTACK_TYPES.MALWARE,
    impactStat: '~10,000 systems encrypted in 90 min',
    affectedRegions: ['Ukraine', 'Russia'],
    cameraTarget: { lat: 49, lng: 32 },
    arcColor: '#ff3c3c',
    arcs: [
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'Ukraine', sourceLat: 50.4501, sourceLng: 30.5234, targetCountry: 'Russia', targetLat: 55.7558, targetLng: 37.6173, intensity: 0.95, color: '#ff3c3c' }),
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'Ukraine', sourceLat: 49.4871, sourceLng: 31.2718, targetCountry: 'Ukraine', targetLat: 46.9648, targetLng: 31.9961, intensity: 0.88, color: '#ff3c3c' }),
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'Russia', sourceLat: 55.7558, sourceLng: 37.6173, targetCountry: 'Ukraine', targetLat: 47.838, targetLng: 35.1396, intensity: 0.79, color: '#ff3c3c' })
    ]
  },
  {
    id: 'wannacry-step-2',
    title: 'NHS Collapse',
    description:
      'Within 6 hours, 80 of 236 UK NHS trusts went dark. MRI machines locked, patient records inaccessible, ambulances diverted to unaffected hospitals. NHS was running unpatched Windows XP on medical equipment.',
    technicalInsight: 'Lateral movement via unpatched SMB shares, no network segmentation between medical devices and admin systems',
    attackType: ATTACK_TYPES.MALWARE,
    impactStat: '80 NHS trusts offline, £92M lost',
    affectedRegions: ['United Kingdom', 'Ireland'],
    cameraTarget: { lat: 54, lng: -2 },
    arcColor: '#ff5555',
    arcs: [
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'Ukraine', sourceLat: 50.4501, sourceLng: 30.5234, targetCountry: 'United Kingdom', targetLat: 51.5074, targetLng: -0.1278, intensity: 0.97, color: '#ff5555' }),
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'United Kingdom', sourceLat: 51.5074, sourceLng: -0.1278, targetCountry: 'United Kingdom', targetLat: 53.8008, targetLng: -1.5491, intensity: 0.91, color: '#ff5555' }),
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'United Kingdom', sourceLat: 53.4808, sourceLng: -2.2426, targetCountry: 'Ireland', targetLat: 53.3498, targetLng: -6.2603, intensity: 0.72, color: '#ff5555' }),
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'United Kingdom', sourceLat: 51.5074, sourceLng: -0.1278, targetCountry: 'United Kingdom', targetLat: 55.8642, targetLng: -4.2518, intensity: 0.84, color: '#ff5555' })
    ]
  },
  {
    id: 'wannacry-step-3',
    title: 'European Cascade',
    description:
      'The worm spread with no human interaction, hitting Telefónica (Spain), Deutsche Bahn railway displays (Germany), and Renault factories (France) which halted production lines. It scanned random global IP ranges on port 445 autonomously.',
    technicalInsight: 'No C2 server dependency — pure SMB scanning worm. Killswitch domain not yet registered.',
    attackType: ATTACK_TYPES.MALWARE,
    impactStat: '~45,000 infections across Europe',
    affectedRegions: ['Spain', 'Germany', 'France', 'Portugal', 'Italy'],
    cameraTarget: { lat: 48, lng: 10 },
    arcColor: '#ff6b35',
    arcs: [
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'Ukraine', sourceLat: 50.4501, sourceLng: 30.5234, targetCountry: 'Spain', targetLat: 40.4168, targetLng: -3.7038, intensity: 0.89, color: '#ff6b35' }),
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'Spain', sourceLat: 40.4168, sourceLng: -3.7038, targetCountry: 'Portugal', targetLat: 38.7223, targetLng: -9.1393, intensity: 0.77, color: '#ff6b35' }),
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'Ukraine', sourceLat: 50.4501, sourceLng: 30.5234, targetCountry: 'Germany', targetLat: 52.52, targetLng: 13.405, intensity: 0.86, color: '#ff6b35' }),
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'Germany', sourceLat: 52.52, sourceLng: 13.405, targetCountry: 'France', targetLat: 48.8566, targetLng: 2.3522, intensity: 0.81, color: '#ff6b35' }),
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'France', sourceLat: 48.8566, sourceLng: 2.3522, targetCountry: 'Italy', targetLat: 41.9028, targetLng: 12.4964, intensity: 0.74, color: '#ff6b35' })
    ]
  },
  {
    id: 'wannacry-step-4',
    title: 'Asia Pacific Wave',
    description:
      'As European workday ended, the worm hit Asian business hours. Chinese universities, Russian interior ministry, Indian state telecom BSNL, and FedEx Asia operations all went down. 75,000 infections in first 24 hours globally.',
    technicalInsight: 'Time-zone based propagation wave — no throttling in worm code meant it burned through Asian networks during business hours.',
    attackType: ATTACK_TYPES.MALWARE,
    impactStat: '~75,000 infections in 24 hours',
    affectedRegions: ['China', 'India', 'Japan', 'South Korea'],
    cameraTarget: { lat: 35, lng: 100 },
    arcColor: '#ff8c00',
    arcs: [
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'Russia', sourceLat: 55.7558, sourceLng: 37.6173, targetCountry: 'China', targetLat: 39.9042, targetLng: 116.4074, intensity: 0.93, color: '#ff8c00' }),
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'China', sourceLat: 39.9042, sourceLng: 116.4074, targetCountry: 'India', targetLat: 28.6139, targetLng: 77.209, intensity: 0.85, color: '#ff8c00' }),
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'China', sourceLat: 39.9042, sourceLng: 116.4074, targetCountry: 'Japan', targetLat: 35.6895, targetLng: 139.6917, intensity: 0.78, color: '#ff8c00' }),
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'Japan', sourceLat: 35.6895, sourceLng: 139.6917, targetCountry: 'South Korea', targetLat: 37.5665, targetLng: 126.978, intensity: 0.72, color: '#ff8c00' }),
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'India', sourceLat: 28.6139, sourceLng: 77.209, targetCountry: 'Japan', targetLat: 34.6937, targetLng: 135.5023, intensity: 0.69, color: '#ff8c00' })
    ]
  },
  {
    id: 'wannacry-step-5',
    title: 'Accidental Kill Switch',
    description:
      '22-year-old British researcher Marcus Hutchins noticed the malware checked for an unregistered domain before executing. He registered it for $10 — not knowing it would work. He thought it was a sandbox detection mechanism. Global propagation stopped instantly.',
    technicalInsight: 'Killswitch domain iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com — malware sent GET request on startup, if domain resolved it exited. Registration cost $10.69.',
    attackType: ATTACK_TYPES.MALWARE,
    impactStat: 'Global spread halted in seconds',
    affectedRegions: ['United Kingdom'],
    cameraTarget: { lat: 52, lng: -1 },
    arcColor: '#ffd700',
    arcs: [
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'United Kingdom', sourceLat: 51.5074, sourceLng: -0.1278, targetCountry: 'United States', targetLat: 37.3382, targetLng: -121.8863, intensity: 0.95, color: '#ffd700' }),
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'United Kingdom', sourceLat: 51.5074, sourceLng: -0.1278, targetCountry: 'Germany', targetLat: 52.52, targetLng: 13.405, intensity: 0.88, color: '#ffd700' }),
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'United Kingdom', sourceLat: 51.5074, sourceLng: -0.1278, targetCountry: 'China', targetLat: 39.9042, targetLng: 116.4074, intensity: 0.84, color: '#ffd700' })
    ]
  },
  {
    id: 'wannacry-step-6',
    title: 'Attribution and Aftermath',
    description:
      'The US, UK, and Australia formally attributed WannaCry to North Korea\'s Lazarus Group in December 2017. Patches had been available for 2 months before the attack — MS17-010 was patched in March 2017. Total damages: $4–8 billion across 150 countries.',
    technicalInsight: 'Lazarus Group used stolen NSA exploit weaponized and leaked by Shadow Brokers. Attribution based on code similarity to 2014 Sony Pictures hack malware.',
    attackType: ATTACK_TYPES.MALWARE,
    impactStat: '$4–8B damages, 150 countries hit',
    affectedRegions: ['United States', 'United Kingdom', 'Australia', 'Germany', 'France', 'Japan'],
    cameraTarget: { lat: 20, lng: 0 },
    arcColor: '#ff3c3c',
    arcs: [
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'United States', sourceLat: 38.9072, sourceLng: -77.0369, targetCountry: 'United Kingdom', targetLat: 51.5074, targetLng: -0.1278, intensity: 0.7, color: '#ff3c3c' }),
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'United Kingdom', sourceLat: 51.5074, sourceLng: -0.1278, targetCountry: 'Australia', targetLat: -33.8688, targetLng: 151.2093, intensity: 0.65, color: '#ff3c3c' }),
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'United States', sourceLat: 38.9072, sourceLng: -77.0369, targetCountry: 'Germany', targetLat: 52.52, targetLng: 13.405, intensity: 0.62, color: '#ff3c3c' }),
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'United States', sourceLat: 38.9072, sourceLng: -77.0369, targetCountry: 'France', targetLat: 48.8566, targetLng: 2.3522, intensity: 0.6, color: '#ff3c3c' }),
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'United States', sourceLat: 38.9072, sourceLng: -77.0369, targetCountry: 'Japan', targetLat: 35.6895, targetLng: 139.6917, intensity: 0.58, color: '#ff3c3c' })
    ]
  }
];

const baseMiraiSteps = [
  {
    id: 'mirai-step-1',
    title: 'Silent IoT Infection',
    description:
      'Starting August 2016, Mirai began silently scanning the entire IPv4 address space for IoT devices with Telnet port 23 open. Home routers, CCTV cameras, and DVR systems with factory default passwords were taken over in seconds. Owners had no idea.',
    technicalInsight: 'Brute-forced 61 default credential pairs over Telnet. Written in C for raw speed — could scan the full internet in under 10 minutes. Self-deleted after infection to hide from memory inspection.',
    attackType: ATTACK_TYPES.SCAN,
    impactStat: '~600,000 IoT devices infected',
    affectedRegions: ['China', 'Brazil', 'Vietnam', 'Colombia'],
    cameraTarget: { lat: 20, lng: 60 },
    arcColor: '#7c3aed',
    arcs: [
      createArc({ type: ATTACK_TYPES.SCAN, sourceCountry: 'China', sourceLat: 39.9042, sourceLng: 116.4074, targetCountry: 'Vietnam', targetLat: 21.0278, targetLng: 105.8342, intensity: 0.74, color: '#7c3aed' }),
      createArc({ type: ATTACK_TYPES.SCAN, sourceCountry: 'China', sourceLat: 39.9042, sourceLng: 116.4074, targetCountry: 'Brazil', targetLat: -23.5505, targetLng: -46.6333, intensity: 0.68, color: '#7c3aed' }),
      createArc({ type: ATTACK_TYPES.SCAN, sourceCountry: 'Brazil', sourceLat: -23.5505, sourceLng: -46.6333, targetCountry: 'Colombia', targetLat: 4.711, targetLng: -74.0721, intensity: 0.61, color: '#7c3aed' }),
      createArc({ type: ATTACK_TYPES.SCAN, sourceCountry: 'Vietnam', sourceLat: 21.0278, sourceLng: 105.8342, targetCountry: 'China', targetLat: 31.2304, targetLng: 121.4737, intensity: 0.55, color: '#7c3aed' })
    ]
  },
  {
    id: 'mirai-step-2',
    title: 'Botnet Assembly',
    description:
      'Infected devices silently phoned home to a C2 server and awaited flood commands. The botnet was rented out on criminal forums as a DDoS-for-hire service. First major test target was security journalist Brian Krebs, whose site was hit with 620 Gbps.',
    technicalInsight: 'IRC-based C2 protocol. Devices remained fully functional so owners never noticed. Loader used busybox shell commands for cross-architecture compatibility across ARM, MIPS, x86.',
    attackType: ATTACK_TYPES.MALWARE,
    impactStat: '620 Gbps test attack on KrebsOnSecurity',
    affectedRegions: ['United States', 'Germany', 'South Korea', 'Russia', 'Brazil'],
    cameraTarget: { lat: 37, lng: -40 },
    arcColor: '#9333ea',
    arcs: [
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'China', sourceLat: 39.9042, sourceLng: 116.4074, targetCountry: 'United States', targetLat: 38.9072, targetLng: -77.0369, intensity: 0.88, color: '#9333ea' }),
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'Russia', sourceLat: 55.7558, sourceLng: 37.6173, targetCountry: 'Germany', targetLat: 52.52, targetLng: 13.405, intensity: 0.79, color: '#9333ea' }),
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'Brazil', sourceLat: -23.5505, sourceLng: -46.6333, targetCountry: 'United States', targetLat: 37.7749, targetLng: -122.4194, intensity: 0.75, color: '#9333ea' }),
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'South Korea', sourceLat: 37.5665, sourceLng: 126.978, targetCountry: 'United States', targetLat: 34.0522, targetLng: -118.2437, intensity: 0.72, color: '#9333ea' })
    ]
  },
  {
    id: 'mirai-step-3',
    title: 'OVH Infrastructure Attack',
    description:
      'French cloud hosting provider OVH was hit with 1 Tbps of traffic — the largest DDoS ever recorded at that time. OVH hosted servers for Minecraft game servers, which were the likely commercial motive.',
    technicalInsight: 'Mirai used UDP flood, GRE flood, and DNS reflection amplification simultaneously. Multi-vector attack saturated upstream transit providers, not just the target.',
    attackType: ATTACK_TYPES.DDOS,
    impactStat: '1 Tbps — largest DDoS ever at the time',
    affectedRegions: ['France', 'Germany', 'United Kingdom', 'Netherlands'],
    cameraTarget: { lat: 47, lng: 5 },
    arcColor: '#a855f7',
    arcs: [
      createArc({ type: ATTACK_TYPES.DDOS, sourceCountry: 'United States', sourceLat: 37.7749, sourceLng: -122.4194, targetCountry: 'France', targetLat: 48.8566, targetLng: 2.3522, intensity: 0.96, color: '#a855f7' }),
      createArc({ type: ATTACK_TYPES.DDOS, sourceCountry: 'Brazil', sourceLat: -23.5505, sourceLng: -46.6333, targetCountry: 'France', targetLat: 48.8566, targetLng: 2.3522, intensity: 0.91, color: '#a855f7' }),
      createArc({ type: ATTACK_TYPES.DDOS, sourceCountry: 'China', sourceLat: 39.9042, sourceLng: 116.4074, targetCountry: 'France', targetLat: 48.8566, targetLng: 2.3522, intensity: 0.88, color: '#a855f7' }),
      createArc({ type: ATTACK_TYPES.DDOS, sourceCountry: 'Russia', sourceLat: 55.7558, sourceLng: 37.6173, targetCountry: 'France', targetLat: 48.8566, targetLng: 2.3522, intensity: 0.84, color: '#a855f7' })
    ]
  },
  {
    id: 'mirai-step-4',
    title: 'Dyn DNS Collapse',
    description:
      'October 21, 2016 — Mirai hit Dyn, a major DNS infrastructure provider. Twitter, Reddit, Netflix, GitHub, Spotify, CNN, and PayPal all went offline across North America and Europe. The attack lasted 11 hours in three waves.',
    technicalInsight: '1.2 Tbps volumetric UDP and TCP flood targeting Dyn\'s anycast DNS resolvers. DNS amplification multiplied attack volume by 50x. Anycast routing could not absorb traffic at this scale.',
    attackType: ATTACK_TYPES.DDOS,
    impactStat: '1.2 Tbps, 80+ major sites offline 11hrs',
    affectedRegions: ['United States', 'United Kingdom', 'France', 'Germany', 'Canada'],
    cameraTarget: { lat: 40, lng: -74 },
    arcColor: '#c084fc',
    arcs: [
      createArc({ type: ATTACK_TYPES.DDOS, sourceCountry: 'United States', sourceLat: 34.0522, sourceLng: -118.2437, targetCountry: 'United States', targetLat: 42.3601, targetLng: -71.0589, intensity: 0.97, color: '#c084fc' }),
      createArc({ type: ATTACK_TYPES.DDOS, sourceCountry: 'United Kingdom', sourceLat: 51.5074, sourceLng: -0.1278, targetCountry: 'United States', targetLat: 42.3601, targetLng: -71.0589, intensity: 0.91, color: '#c084fc' }),
      createArc({ type: ATTACK_TYPES.DDOS, sourceCountry: 'France', sourceLat: 48.8566, sourceLng: 2.3522, targetCountry: 'United States', targetLat: 42.3601, targetLng: -71.0589, intensity: 0.87, color: '#c084fc' }),
      createArc({ type: ATTACK_TYPES.DDOS, sourceCountry: 'Germany', sourceLat: 52.52, sourceLng: 13.405, targetCountry: 'United States', targetLat: 42.3601, targetLng: -71.0589, intensity: 0.84, color: '#c084fc' }),
      createArc({ type: ATTACK_TYPES.DDOS, sourceCountry: 'Canada', sourceLat: 43.6532, sourceLng: -79.3832, targetCountry: 'United States', targetLat: 42.3601, targetLng: -71.0589, intensity: 0.79, color: '#c084fc' })
    ]
  },
  {
    id: 'mirai-step-5',
    title: 'Source Code Release and Legacy',
    description:
      'The original Mirai author "Anna-senpai" released the full source code publicly in October 2016 as law enforcement closed in. This spawned dozens of Mirai variants that still persist today. Three men were arrested in 2017 and sentenced to community service in exchange for cooperation with FBI cybercrime investigations.',
    technicalInsight: 'Open-sourced C code allowed anyone to compile their own botnet. Variants like Satori, Okiru, and Masuta added new exploits beyond default credentials. IoT attack surface grew from 200,000 in 2016 to millions by 2020.',
    attackType: ATTACK_TYPES.MALWARE,
    impactStat: 'Source released — spawned 50+ variants',
    affectedRegions: ['United States', 'Japan', 'Germany', 'Brazil', 'Australia'],
    cameraTarget: { lat: 20, lng: -10 },
    arcColor: '#7c3aed',
    arcs: [
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'United States', sourceLat: 38.9072, sourceLng: -77.0369, targetCountry: 'Japan', targetLat: 35.6895, targetLng: 139.6917, intensity: 0.71, color: '#7c3aed' }),
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'United States', sourceLat: 38.9072, sourceLng: -77.0369, targetCountry: 'Germany', targetLat: 52.52, targetLng: 13.405, intensity: 0.68, color: '#7c3aed' }),
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'United States', sourceLat: 38.9072, sourceLng: -77.0369, targetCountry: 'Brazil', targetLat: -23.5505, targetLng: -46.6333, intensity: 0.65, color: '#7c3aed' }),
      createArc({ type: ATTACK_TYPES.MALWARE, sourceCountry: 'United States', sourceLat: 38.9072, sourceLng: -77.0369, targetCountry: 'Australia', targetLat: -33.8688, targetLng: 151.2093, intensity: 0.62, color: '#7c3aed' })
    ]
  }
];

const WANNACRY_STEP_CONTEXT = {
  'wannacry-step-1': {
    technicalInsight: 'WannaCry exploited the SMBv1 port 445 flaw (MS17-010) to run code remotely.',
    visualPattern: 'Arcs begin tightly around Ukraine, then branch outward to nearby systems as local spread starts.',
    arcNarrativeSummary: 'You are seeing the first infection jump and immediate neighborhood propagation.',
    intensityMeaning: 'Brighter arcs indicate faster host-to-host encryption activity.',
    focusRegion: {
      primary: 'Ukraine',
      why: 'This is the launch point where the first large infection burst appears on the map.',
    },
    exploitBreakdown: [
      'Entry: Compromised software update delivered the payload.',
      'Exploit: EternalBlue opened remote execution on SMB port 445.',
      'Backdoor: DoublePulsar helped execute follow-up actions.',
      'Spread: Worm scanned and moved laterally without user clicks.',
    ],
    analystTakeaway: 'Early patching on internal SMB services would have dramatically reduced first-wave spread.',
  },
  'wannacry-step-2': {
    technicalInsight: 'Once inside UK networks, WannaCry moved laterally through unpatched SMB shares.',
    visualPattern: 'Arcs cluster inside the UK and then spill into nearby Ireland, showing operational collapse zones.',
    arcNarrativeSummary: 'The map highlights internal network spread, not just cross-border hops.',
    intensityMeaning: 'Higher intensity arcs represent multiple trusts being hit in parallel.',
    focusRegion: {
      primary: 'United Kingdom',
      why: 'NHS infrastructure is the main impact center during this phase.',
    },
    exploitBreakdown: [
      'Weak point: Legacy Windows hosts remained unpatched.',
      'Path: Flat internal networks allowed fast trust-to-trust movement.',
      'Impact: Clinical devices and records systems were encrypted together.',
      'Effect: Ambulance routes and patient care were disrupted in hours.',
    ],
    analystTakeaway: 'Segmentation between medical devices and admin networks would have limited blast radius.',
  },
  'wannacry-step-3': {
    technicalInsight: 'WannaCry behaved like an autonomous SMB scanner, so no central command server was required.',
    visualPattern: 'Multiple medium-to-long arcs connect Western European countries in a cascade pattern.',
    arcNarrativeSummary: 'The globe shows a chain reaction as one affected network seeds the next region.',
    intensityMeaning: 'Arc thickness reflects how quickly each regional cluster joined the cascade.',
    focusRegion: {
      primary: 'Western Europe',
      why: 'Spain, Germany, and France became linked disruption hubs in the same window.',
    },
    exploitBreakdown: [
      'Engine: Worm scanned random public IP ranges on port 445.',
      'No C2 dependency: Infection continued even without operator interaction.',
      'Industrial impact: Transport and manufacturing systems stopped rapidly.',
      'Acceleration: Business-hour overlap increased exposure.',
    ],
    analystTakeaway: 'Internet-facing SMB and weak egress controls let regional incidents become continental.',
  },
  'wannacry-step-4': {
    technicalInsight: 'The worm followed business-hour geography: as one region slept, the next opened.',
    visualPattern: 'Long arcs move eastward into Asia-Pacific with several parallel destination clusters.',
    arcNarrativeSummary: 'This phase visualizes timezone-driven propagation across active enterprise networks.',
    intensityMeaning: 'Brighter arcs mark regions where infection acceleration peaked during local working hours.',
    focusRegion: {
      primary: 'China and India',
      why: 'These regions show the most concentrated high-intensity traffic in this wave.',
    },
    exploitBreakdown: [
      'Timing: Global timezones created sequential attack opportunity windows.',
      'Target class: Universities, telecom, and logistics systems were widely exposed.',
      'Mechanism: Same SMB exploit, different regional timing.',
      'Result: Infection totals surged before coordinated response caught up.',
    ],
    analystTakeaway: '24/7 patch governance is critical because attackers leverage timezone handoffs.',
  },
  'wannacry-step-5': {
    technicalInsight: 'A domain check inside malware acted as a kill switch when the domain was registered.',
    visualPattern: 'Arcs contract and normalize after a brief high-visibility pulse from the UK.',
    arcNarrativeSummary: 'The map transitions from explosive spread to abrupt containment behavior.',
    intensityMeaning: 'Falling arc intensity reflects rapid suppression of new successful infections.',
    focusRegion: {
      primary: 'United Kingdom',
      why: 'The kill-switch registration event originated from this region and changed global behavior.',
    },
    exploitBreakdown: [
      'Check: Malware queried a previously unregistered domain at startup.',
      'Action: Registering that domain caused malware instances to exit early.',
      'Effect: New propagation dropped sharply in seconds.',
      'Lesson: Reverse engineering can create immediate defensive leverage.',
    ],
    analystTakeaway: 'Fast malware analysis and decisive sinkholing can interrupt even large active outbreaks.',
  },
  'wannacry-step-6': {
    technicalInsight: 'Attribution linked the campaign to Lazarus, but the primary failure remained patch hygiene.',
    visualPattern: 'Global, lower-intensity arcs show residual impact and long-tail international consequences.',
    arcNarrativeSummary: 'This final view summarizes worldwide disruption rather than active rapid spread.',
    intensityMeaning: 'Moderate arcs represent sustained downstream business and infrastructure impact.',
    focusRegion: {
      primary: 'Global cross-region view',
      why: 'Damage and response costs were distributed across many countries, not one hotspot.',
    },
    exploitBreakdown: [
      'Root cause: Known vulnerability left unpatched across critical systems.',
      'Attribution: Code overlap and intelligence linked actors to Lazarus Group.',
      'Economic impact: Multi-billion-dollar losses across healthcare and industry.',
      'Aftermath: Defensive playbooks shifted toward faster patch SLAs.',
    ],
    analystTakeaway: 'Nation-scale incidents often begin with routine security debt, not exotic zero-days.',
  },
};

const MIRAI_STEP_CONTEXT = {
  'mirai-step-1': {
    technicalInsight: 'Mirai scanned for Telnet-exposed IoT devices and logged in with factory default passwords.',
    visualPattern: 'Wide scan arcs fan across distant countries, showing reconnaissance before full attack waves.',
    arcNarrativeSummary: 'The globe is showing bot recruitment traffic, not the final DDoS yet.',
    intensityMeaning: 'Higher intensity arcs indicate faster device discovery and takeover rates.',
    focusRegion: {
      primary: 'China and Southeast Asia',
      why: 'These regions show dense early IoT compromise paths in this stage.',
    },
    exploitBreakdown: [
      'Discovery: Continuous IPv4 scanning for open Telnet services.',
      'Access: Default credential brute-force against weak IoT admin logins.',
      'Execution: Lightweight malware binary adapted to device CPU families.',
      'Stealth: Devices remained usable, so compromise often went unnoticed.',
    ],
    analystTakeaway: 'Basic IoT hygiene, especially password changes and Telnet shutdown, blocks this phase early.',
  },
  'mirai-step-2': {
    technicalInsight: 'Compromised devices joined C2 channels and became remotely controlled DDoS workers.',
    visualPattern: 'Long command-and-control arcs connect infected regions to attack destinations.',
    arcNarrativeSummary: 'This phase visualizes assembly of a coordinated botnet swarm.',
    intensityMeaning: 'Brighter arcs indicate larger cohorts of bots receiving synchronized commands.',
    focusRegion: {
      primary: 'United States target corridor',
      why: 'Traffic converges toward early high-profile test targets in US infrastructure.',
    },
    exploitBreakdown: [
      'Control plane: Infected nodes checked in to command infrastructure.',
      'Tasking: Operators pushed target and flood-type instructions at scale.',
      'Commercialization: Access was rented in DDoS-for-hire markets.',
      'Test strike: High-bandwidth attack validated botnet effectiveness.',
    ],
    analystTakeaway: 'Botnet growth is dangerous when command channels stay intact across many geographies.',
  },
  'mirai-step-3': {
    technicalInsight: 'Mirai launched multi-vector floods (UDP/GRE/amplification) against OVH at record scale.',
    visualPattern: 'Several powerful inbound arcs converge on a single French infrastructure hub.',
    arcNarrativeSummary: 'The globe shows concentrated volumetric pressure from many source regions into one target.',
    intensityMeaning: 'Thicker, brighter arcs indicate source clusters contributing the largest bandwidth share.',
    focusRegion: {
      primary: 'France (OVH)',
      why: 'This is the single choke point where converging traffic saturates capacity.',
    },
    exploitBreakdown: [
      'Vector mix: UDP and GRE floods increased protocol-level stress.',
      'Amplification: Reflection techniques multiplied outgoing bot traffic.',
      'Convergence: Distributed sources hit the same infrastructure node.',
      'Consequence: Upstream transit links were saturated before app defenses engaged.',
    ],
    analystTakeaway: 'Capacity planning must include upstream provider saturation, not only endpoint resilience.',
  },
  'mirai-step-4': {
    technicalInsight: 'Dyn DNS was flooded hard enough to disrupt name resolution for major internet services.',
    visualPattern: 'Persistent transatlantic arcs repeatedly strike shared DNS infrastructure.',
    arcNarrativeSummary: 'This phase emphasizes dependency risk: one provider outage cascades to many platforms.',
    intensityMeaning: 'Sustained high-intensity arcs represent repeated wave attacks over several hours.',
    focusRegion: {
      primary: 'US East Coast DNS nodes',
      why: 'These nodes anchor global traffic resolution and became a systemic weak point.',
    },
    exploitBreakdown: [
      'Target choice: DNS infrastructure with broad downstream dependence.',
      'Wave strategy: Multiple attack rounds to exhaust mitigation cycles.',
      'Scale: Traffic volume exceeded expected anycast absorption margins.',
      'Impact: Popular services failed even though their own servers were not directly attacked.',
    ],
    analystTakeaway: 'Critical shared dependencies need attack-path isolation and failover diversity.',
  },
  'mirai-step-5': {
    technicalInsight: 'Public source release enabled fast copycat variants and a long-lived IoT botnet ecosystem.',
    visualPattern: 'Global medium-intensity arcs show propagation of Mirai derivatives across new regions.',
    arcNarrativeSummary: 'The map shifts from one campaign to many follow-on variant operations.',
    intensityMeaning: 'Steady arcs represent ongoing variant activity rather than one-time peak floods.',
    focusRegion: {
      primary: 'Global variant spread',
      why: 'The threat evolved into distributed, recurring campaigns across many countries.',
    },
    exploitBreakdown: [
      'Open source effect: Entry barrier dropped for new botnet operators.',
      'Variant growth: New strains added exploits beyond default-password attacks.',
      'Persistence: Insecure IoT fleets provided recurring recruitable devices.',
      'Policy impact: Regulatory and vendor pressure increased on IoT baseline security.',
    ],
    analystTakeaway: 'When offensive code goes public, insecure device ecosystems become a chronic strategic risk.',
  },
};

const enrichSimulationSteps = (steps, contextMap) => {
  return steps.map((step) => {
    const context = contextMap[step.id] || {};
    return {
      ...step,
      technicalInsight: context.technicalInsight || step.technicalInsight,
      visualPattern: context.visualPattern || '',
      arcNarrativeSummary: context.arcNarrativeSummary || '',
      intensityMeaning: context.intensityMeaning || '',
      focusRegion: context.focusRegion || null,
      exploitBreakdown: Array.isArray(context.exploitBreakdown) ? context.exploitBreakdown : [],
      analystTakeaway: context.analystTakeaway || '',
    };
  });
};

export const wannacrySteps = enrichSimulationSteps(baseWannacrySteps, WANNACRY_STEP_CONTEXT);
export const miraiSteps = enrichSimulationSteps(baseMiraiSteps, MIRAI_STEP_CONTEXT);
