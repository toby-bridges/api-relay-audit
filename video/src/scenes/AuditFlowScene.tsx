import { Easing, Interactive, interpolate, useCurrentFrame } from "remotion";
import { TerminalWindow } from "../components/TerminalWindow";
import { AUDIT_STEPS } from "../data/content";

export const AuditFlowScene: React.FC = () => {
  const frame = useCurrentFrame();
  const completeSteps = Math.floor(interpolate(frame, [78, 232], [0, 14], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  }));

  return (
    <div style={{ position: "absolute", inset: 0, padding: "118px 92px 145px" }}>
      <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between" }}>
        <Interactive.Div
          name="Audit flow title"
          style={{
            color: "#f8fafc",
            fontSize: 72,
            lineHeight: 1.1,
            fontWeight: 850,
            letterSpacing: -2.5,
            opacity: interpolate(frame, [0, 16], [0, 1], {
              extrapolateLeft: "clamp",
              extrapolateRight: "clamp",
            }),
            translate: interpolate(frame, [0, 18], ["0px 24px", "0px 0px"], {
              extrapolateLeft: "clamp",
              extrapolateRight: "clamp",
              easing: Easing.bezier(0.16, 1, 0.3, 1),
            }),
          }}
        >
          把不可见的中间层，变成可复查的证据
        </Interactive.Div>
        <div style={{ display: "flex", gap: 12 }}>
          {["LOCAL PROCESS", "PYTHON + CURL", "NO EXTRA CHECKER"].map((label, index) => (
            <div
              key={label}
              style={{
                padding: "10px 16px",
                borderRadius: 999,
                border: "1px solid rgba(16,185,129,0.28)",
                backgroundColor: "rgba(16,185,129,0.08)",
                color: "#6ee7b7",
                fontFamily: '"SF Mono", "Cascadia Code", monospace',
                fontSize: 16,
                letterSpacing: 1.2,
                opacity: interpolate(frame, [12 + index * 6, 28 + index * 6], [0, 1], {
                  extrapolateLeft: "clamp",
                  extrapolateRight: "clamp",
                }),
              }}
            >
              {label}
            </div>
          ))}
        </div>
      </div>

      <div style={{ marginTop: 46, display: "flex", gap: 32 }}>
        <TerminalWindow />
        <div
          style={{
            flex: 1,
            height: 580,
            borderRadius: 24,
            border: "1px solid #283548",
            backgroundColor: "rgba(17,24,39,0.70)",
            padding: "28px 30px",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div style={{ color: "#94a3b8", fontSize: 21, fontWeight: 700 }}>14-STEP AUDIT</div>
            <div
              style={{
                color: "#60a5fa",
                fontFamily: '"SF Mono", "Cascadia Code", monospace',
                fontSize: 22,
                fontWeight: 800,
              }}
            >
              {String(completeSteps).padStart(2, "0")} / 14
            </div>
          </div>
          <div
            style={{
              marginTop: 22,
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: 11,
            }}
          >
            {AUDIT_STEPS.map((step, index) => {
              const done = index < completeSteps;
              const active = index === completeSteps && completeSteps < 14;
              return (
                <div
                  key={step}
                  style={{
                    minHeight: 56,
                    borderRadius: 13,
                    border: done
                      ? "1px solid rgba(16,185,129,0.30)"
                      : active
                        ? "1px solid rgba(96,165,250,0.45)"
                        : "1px solid #1e293b",
                    backgroundColor: done
                      ? "rgba(16,185,129,0.08)"
                      : active
                        ? "rgba(59,130,246,0.12)"
                        : "rgba(255,255,255,0.015)",
                    color: done ? "#6ee7b7" : active ? "#93c5fd" : "#475569",
                    display: "flex",
                    alignItems: "center",
                    gap: 10,
                    padding: "0 14px",
                    fontFamily: '"SF Mono", "Cascadia Code", monospace',
                    fontSize: 16,
                  }}
                >
                  <span>{done ? "✓" : active ? "◆" : "·"}</span>
                  <span>{String(index + 1).padStart(2, "0")}</span>
                  <span style={{ overflow: "hidden", whiteSpace: "nowrap", textOverflow: "ellipsis" }}>{step}</span>
                </div>
              );
            })}
          </div>
          <div
            style={{
              marginTop: 20,
              color: "#94a3b8",
              fontSize: 17,
              lineHeight: 1.45,
              textAlign: "center",
            }}
          >
            Key is sent only to the relay you choose.
          </div>
        </div>
      </div>
    </div>
  );
};
