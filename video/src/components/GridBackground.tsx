import { AbsoluteFill, interpolate, useCurrentFrame } from "remotion";

export const GridBackground: React.FC = () => {
  const frame = useCurrentFrame();

  return (
    <AbsoluteFill
      style={{
        backgroundColor: "#0a0e17",
        overflow: "hidden",
      }}
    >
      <AbsoluteFill
        style={{
          backgroundImage:
            "radial-gradient(circle at 18% 12%, rgba(59,130,246,0.20), transparent 34%), radial-gradient(circle at 82% 74%, rgba(167,139,250,0.15), transparent 36%), linear-gradient(145deg, rgba(10,14,23,0.2), rgba(13,18,32,0.92))",
        }}
      />
      <AbsoluteFill
        style={{
          opacity: 0.22,
          backgroundImage:
            "linear-gradient(rgba(148,163,184,0.08) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,0.08) 1px, transparent 1px)",
          backgroundSize: "64px 64px",
          translate: interpolate(frame, [0, 900], ["0px 0px", "32px 16px"], {
            extrapolateLeft: "clamp",
            extrapolateRight: "clamp",
          }),
          maskImage:
            "linear-gradient(to bottom, transparent 2%, black 22%, black 78%, transparent 100%)",
        }}
      />
      <div
        style={{
          position: "absolute",
          top: 48,
          left: 72,
          display: "flex",
          alignItems: "center",
          gap: 12,
          color: "#64748b",
          fontFamily: '"SF Mono", "Cascadia Code", monospace',
          fontSize: 20,
          letterSpacing: 2,
        }}
      >
        <span
          style={{
            width: 10,
            height: 10,
            borderRadius: 999,
            backgroundColor: "#10b981",
            boxShadow: "0 0 22px rgba(16,185,129,0.85)",
          }}
        />
        PUBLIC-SAFE DEMO · v2.4.1
      </div>
      <div
        style={{
          position: "absolute",
          top: 48,
          right: 72,
          color: "#475569",
          fontFamily: '"SF Mono", "Cascadia Code", monospace',
          fontSize: 18,
          letterSpacing: 2,
        }}
      >
        30 SEC / 900 FRAMES
      </div>
    </AbsoluteFill>
  );
};
