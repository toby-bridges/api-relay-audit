import { interpolate, useCurrentFrame } from "remotion";

export const BrandMark: React.FC<{ compact?: boolean }> = ({ compact = false }) => {
  const frame = useCurrentFrame();
  const size = compact ? 86 : 154;

  return (
    <div
      style={{
        width: size,
        height: size,
        borderRadius: compact ? 24 : 40,
        border: `${compact ? 2 : 3}px solid rgba(96,165,250,0.55)`,
        background:
          "linear-gradient(145deg, rgba(59,130,246,0.22), rgba(167,139,250,0.10))",
        boxShadow:
          "inset 0 0 50px rgba(59,130,246,0.10), 0 22px 70px rgba(37,99,235,0.18)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        scale: interpolate(frame, [0, 24], [0.82, 1], {
          extrapolateLeft: "clamp",
          extrapolateRight: "clamp",
        }),
      }}
    >
      <svg width={size * 0.68} height={size * 0.68} viewBox="0 0 100 100">
        <path
          d="M18 50H39M61 50H82"
          stroke="#60a5fa"
          strokeWidth="5"
          strokeLinecap="round"
        />
        <circle cx="12" cy="50" r="8" fill="#0a0e17" stroke="#60a5fa" strokeWidth="4" />
        <circle cx="88" cy="50" r="8" fill="#0a0e17" stroke="#a78bfa" strokeWidth="4" />
        <rect
          x="38"
          y="25"
          width="24"
          height="50"
          rx="7"
          fill="#111827"
          stroke="#f59e0b"
          strokeWidth="4"
        />
        <path d="M44 38H56M44 50H56M44 62H52" stroke="#f59e0b" strokeWidth="4" strokeLinecap="round" />
        <circle cx="50" cy="16" r="3" fill="#f59e0b" />
        <circle cx="50" cy="84" r="3" fill="#f59e0b" />
      </svg>
    </div>
  );
};
