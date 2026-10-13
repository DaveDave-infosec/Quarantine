export default function Logo({ size = 24 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true">
      <rect width="64" height="64" rx="14" fill="#14191A" />
      <g stroke="#EDF1F0" strokeWidth="3" strokeLinecap="round">
        <line x1="32" y1="32" x2="16" y2="18" />
        <line x1="32" y1="32" x2="48" y2="18" />
        <line x1="32" y1="32" x2="44" y2="48" />
      </g>
      <circle cx="32" cy="32" r="6" fill="#EDF1F0" />
      <circle cx="16" cy="18" r="4" fill="#EDF1F0" />
      <circle cx="48" cy="18" r="4" fill="#EDF1F0" />
      <circle cx="44" cy="48" r="4" fill="#EDF1F0" />
      <circle cx="44" cy="48" r="9.5" fill="none" stroke="#C2412D" strokeWidth="3.5" />
    </svg>
  );
}
