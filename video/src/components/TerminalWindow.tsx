import { interpolate, useCurrentFrame } from "remotion";
import { TERMINAL_LINES } from "../data/content";

export const TerminalWindow: React.FC = () => {
  const frame = useCurrentFrame();
  const command = 'python3 audit.py --profile full --key "$API_RELAY_AUDIT_KEY" --url "$RELAY_URL"';
  const typedCommand = command.slice(0, Math.floor(interpolate(frame, [8, 74], [0, command.length], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  })));

  return (
    <div
      style={{
        width: 1010,
        height: 580,
        borderRadius: 24,
        overflow: "hidden",
        border: "1px solid #283548",
        backgroundColor: "rgba(8,12,20,0.94)",
        boxShadow: "0 30px 100px rgba(0,0,0,0.38)",
      }}
    >
      <div
        style={{
          height: 58,
          display: "flex",
          alignItems: "center",
          padding: "0 22px",
          gap: 10,
          backgroundColor: "#111827",
          borderBottom: "1px solid #1e293b",
        }}
      >
        {(["#ff5f57", "#febc2e", "#28c840"] as const).map((color) => (
          <span key={color} style={{ width: 13, height: 13, borderRadius: 99, backgroundColor: color }} />
        ))}
        <span
          style={{
            marginLeft: 12,
            color: "#64748b",
            fontFamily: '"SF Mono", "Cascadia Code", monospace',
            fontSize: 18,
          }}
        >
          local audit · synthetic target
        </span>
      </div>
      <div
        style={{
          padding: "27px 32px",
          fontFamily: '"SF Mono", "Cascadia Code", monospace',
          fontSize: 22,
          lineHeight: 1.62,
        }}
      >
        <div style={{ color: "#64748b" }}>$ API_RELAY_AUDIT_KEY=[configured securely]</div>
        <div style={{ color: "#94a3b8", minHeight: 38, fontSize: 20 }}>
          <span style={{ color: "#10b981" }}>$ </span>
          {typedCommand}
          {frame < 80 ? <span style={{ color: "#60a5fa" }}>▌</span> : null}
        </div>
        <div style={{ height: 16 }} />
        {TERMINAL_LINES.map((line, index) => {
          const start = 78 + index * 21;
          const visible = frame >= start;
          const isCurrent = frame >= start && frame < start + 21;
          return (
            <div
              key={line}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 12,
                minHeight: 34,
                color: isCurrent ? "#e2e8f0" : "#64748b",
                opacity: visible ? 1 : 0,
                translate: interpolate(frame, [start, start + 7], ["-12px 0px", "0px 0px"], {
                  extrapolateLeft: "clamp",
                  extrapolateRight: "clamp",
                }),
              }}
            >
              <span style={{ color: isCurrent ? "#60a5fa" : "#10b981" }}>
                {isCurrent ? "◆" : "✓"}
              </span>
              {line}
            </div>
          );
        })}
        <div
          style={{
            marginTop: 13,
            color: "#10b981",
            opacity: interpolate(frame, [225, 236], [0, 1], {
              extrapolateLeft: "clamp",
              extrapolateRight: "clamp",
            }),
          }}
        >
          ✓ report.md written · evidence retained locally
        </div>
      </div>
    </div>
  );
};
