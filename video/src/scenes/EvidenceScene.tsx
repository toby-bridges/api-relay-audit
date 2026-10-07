import { Easing, Interactive, interpolate, useCurrentFrame } from "remotion";
import { REPORT_ROWS } from "../data/content";

export const EvidenceScene: React.FC = () => {
  const frame = useCurrentFrame();

  return (
    <div style={{ position: "absolute", inset: 0, padding: "120px 105px 145px" }}>
      <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between" }}>
        <Interactive.Div
          name="Evidence title"
          style={{
            color: "#f8fafc",
            fontSize: 78,
            lineHeight: 1.1,
            fontWeight: 850,
            letterSpacing: -2.5,
            opacity: interpolate(frame, [0, 14], [0, 1], {
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
          结果不是“安全认证”，而是证据状态
        </Interactive.Div>
        <div
          style={{
            padding: "10px 18px",
            borderRadius: 999,
            border: "1px solid rgba(245,158,11,0.35)",
            color: "#fcd34d",
            backgroundColor: "rgba(245,158,11,0.08)",
            fontFamily: '"SF Mono", "Cascadia Code", monospace',
            fontSize: 17,
            letterSpacing: 1.4,
          }}
        >
          DETERMINISTIC FIXTURE · NOT LIVE DATA
        </div>
      </div>

      <div style={{ marginTop: 48, display: "grid", gridTemplateColumns: "1.25fr 0.75fr", gap: 28 }}>
        <div
          style={{
            borderRadius: 26,
            border: "1px solid #283548",
            overflow: "hidden",
            backgroundColor: "rgba(17,24,39,0.82)",
            boxShadow: "0 28px 90px rgba(0,0,0,0.34)",
          }}
        >
          <div
            style={{
              padding: "24px 30px",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              borderBottom: "1px solid #1e293b",
            }}
          >
            <div>
              <div style={{ color: "#f8fafc", fontSize: 29, fontWeight: 800 }}>example.invalid</div>
              <div style={{ marginTop: 5, color: "#64748b", fontSize: 17 }}>Sanitized Markdown report preview</div>
            </div>
            <div
              style={{
                padding: "10px 18px",
                borderRadius: 999,
                backgroundColor: "rgba(245,158,11,0.12)",
                color: "#fcd34d",
                fontSize: 21,
                fontWeight: 850,
                letterSpacing: 1,
              }}
            >
              MEDIUM
            </div>
          </div>
          <div style={{ padding: "12px 28px 20px" }}>
            {REPORT_ROWS.map((row, index) => {
              const start = 20 + index * 15;
              return (
                <div
                  key={row.step}
                  style={{
                    minHeight: 77,
                    display: "grid",
                    gridTemplateColumns: "60px 1fr 180px 1.2fr",
                    alignItems: "center",
                    gap: 13,
                    borderBottom: index === REPORT_ROWS.length - 1 ? "none" : "1px solid rgba(30,41,59,0.75)",
                    opacity: interpolate(frame, [start, start + 10], [0, 1], {
                      extrapolateLeft: "clamp",
                      extrapolateRight: "clamp",
                    }),
                    translate: interpolate(frame, [start, start + 12], ["-16px 0px", "0px 0px"], {
                      extrapolateLeft: "clamp",
                      extrapolateRight: "clamp",
                    }),
                  }}
                >
                  <div style={{ color: "#475569", fontFamily: '"SF Mono", monospace', fontSize: 18 }}>#{row.step}</div>
                  <div style={{ color: "#cbd5e1", fontSize: 21, fontWeight: 650 }}>{row.label}</div>
                  <div style={{ color: row.color, fontFamily: '"SF Mono", monospace', fontSize: 16, fontWeight: 800 }}>
                    {row.verdict}
                  </div>
                  <div style={{ color: "#64748b", fontSize: 17 }}>{row.evidence}</div>
                </div>
              );
            })}
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
          {[
            ["CLEAN", "No anomaly found in this probe", "#10b981"],
            ["ANOMALY", "Reviewable suspicious evidence", "#ef4444"],
            ["INCONCLUSIVE", "Could not establish either state", "#f59e0b"],
          ].map(([label, detail, color], index) => {
            const start = 35 + index * 20;
            return (
              <div
                key={label}
                style={{
                  flex: 1,
                  borderRadius: 22,
                  border: `1px solid ${color}44`,
                  backgroundColor: `${color}12`,
                  padding: "26px 28px",
                  display: "flex",
                  flexDirection: "column",
                  justifyContent: "center",
                  opacity: interpolate(frame, [start, start + 12], [0, 1], {
                    extrapolateLeft: "clamp",
                    extrapolateRight: "clamp",
                  }),
                  scale: interpolate(frame, [start, start + 14], [0.94, 1], {
                    extrapolateLeft: "clamp",
                    extrapolateRight: "clamp",
                  }),
                }}
              >
                <div style={{ color, fontSize: 29, fontWeight: 850, letterSpacing: 1 }}>{label}</div>
                <div style={{ marginTop: 7, color: "#94a3b8", fontSize: 18 }}>{detail}</div>
              </div>
            );
          })}
          <div
            style={{
              color: "#f8fafc",
              fontSize: 29,
              fontWeight: 820,
              textAlign: "center",
              padding: "8px 0",
              opacity: interpolate(frame, [104, 122], [0, 1], {
                extrapolateLeft: "clamp",
                extrapolateRight: "clamp",
              }),
            }}
          >
            INCONCLUSIVE <span style={{ color: "#ef4444" }}>≠</span> CLEAN
          </div>
        </div>
      </div>
    </div>
  );
};
