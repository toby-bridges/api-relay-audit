import { Easing, Interactive, interpolate, useCurrentFrame } from "remotion";

const PipelineNode: React.FC<{
  label: string;
  sublabel: string;
  color: string;
  active?: boolean;
}> = ({ label, sublabel, color, active = false }) => {
  return (
    <div
      style={{
        width: 280,
        height: 158,
        borderRadius: 26,
        border: `2px solid ${color}`,
        backgroundColor: "rgba(17,24,39,0.90)",
        boxShadow: active ? `0 0 70px ${color}45` : "0 20px 55px rgba(0,0,0,0.28)",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap: 8,
      }}
    >
      <div style={{ color, fontSize: 38, fontWeight: 850, letterSpacing: 3 }}>{label}</div>
      <div style={{ color: "#64748b", fontSize: 19, letterSpacing: 1.5 }}>{sublabel}</div>
    </div>
  );
};

export const HookScene: React.FC = () => {
  const frame = useCurrentFrame();
  const packetX = interpolate(frame, [44, 104], [300, 1400], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.bezier(0.22, 1, 0.36, 1),
  });

  return (
    <div style={{ position: "absolute", inset: 0, padding: "138px 112px 130px" }}>
      <div
        style={{
          color: "#60a5fa",
          fontFamily: '"SF Mono", "Cascadia Code", monospace',
          fontSize: 22,
          fontWeight: 700,
          letterSpacing: 4,
          opacity: interpolate(frame, [0, 12], [0, 1], {
            extrapolateLeft: "clamp",
            extrapolateRight: "clamp",
          }),
        }}
      >
        AI API RELAY / TRUST BOUNDARY
      </div>
      <Interactive.Div
        name="Hook title"
        style={{
          marginTop: 24,
          maxWidth: 1500,
          color: "#f8fafc",
          fontSize: 100,
          lineHeight: 1.08,
          fontWeight: 860,
          letterSpacing: -4,
          opacity: interpolate(frame, [5, 20], [0, 1], {
            extrapolateLeft: "clamp",
            extrapolateRight: "clamp",
            easing: Easing.bezier(0.16, 1, 0.3, 1),
          }),
          translate: interpolate(frame, [5, 22], ["0px 34px", "0px 0px"], {
            extrapolateLeft: "clamp",
            extrapolateRight: "clamp",
            easing: Easing.bezier(0.16, 1, 0.3, 1),
          }),
        }}
      >
        你的 AI API 中转，
        <span style={{ color: "#60a5fa" }}>真的只是在转发吗？</span>
      </Interactive.Div>

      <div
        style={{
          position: "absolute",
          left: 130,
          right: 130,
          bottom: 220,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          opacity: interpolate(frame, [24, 42], [0, 1], {
            extrapolateLeft: "clamp",
            extrapolateRight: "clamp",
          }),
        }}
      >
        <PipelineNode label="YOU" sublabel="REQUEST" color="#60a5fa" />
        <div style={{ flex: 1, height: 2, margin: "0 22px", backgroundColor: "#283548" }} />
        <PipelineNode label="RELAY" sublabel="UNTRUSTED MIDDLE" color="#f59e0b" active />
        <div style={{ flex: 1, height: 2, margin: "0 22px", backgroundColor: "#283548" }} />
        <PipelineNode label="MODEL" sublabel="UPSTREAM" color="#a78bfa" />
      </div>

      <div
        style={{
          position: "absolute",
          left: 0,
          top: 754,
          width: 62,
          height: 32,
          borderRadius: 10,
          border: "2px solid #60a5fa",
          backgroundColor: "#0a0e17",
          boxShadow:
            packetX > 760 && packetX < 1120
              ? "0 0 35px rgba(239,68,68,0.95)"
              : "0 0 28px rgba(96,165,250,0.75)",
          translate: `${packetX}px 0px`,
          opacity: interpolate(frame, [42, 48, 110, 118], [0, 1, 1, 0], {
            extrapolateLeft: "clamp",
            extrapolateRight: "clamp",
          }),
        }}
      >
        <div
          style={{
            width: "100%",
            height: "100%",
            borderRadius: 8,
            backgroundColor:
              packetX > 760 && packetX < 1120 ? "rgba(239,68,68,0.45)" : "rgba(59,130,246,0.32)",
          }}
        />
      </div>
    </div>
  );
};
