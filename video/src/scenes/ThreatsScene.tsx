import { Easing, Interactive, interpolate, useCurrentFrame } from "remotion";
import { THREATS } from "../data/content";

export const ThreatsScene: React.FC = () => {
  const frame = useCurrentFrame();

  return (
    <div style={{ position: "absolute", inset: 0, padding: "130px 112px 150px" }}>
      <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between" }}>
        <div>
          <div
            style={{
              color: "#f59e0b",
              fontFamily: '"SF Mono", "Cascadia Code", monospace',
              fontSize: 22,
              fontWeight: 750,
              letterSpacing: 4,
            }}
          >
            WHAT CAN CHANGE IN TRANSIT?
          </div>
          <Interactive.Div
            name="Threats title"
            style={{
              marginTop: 20,
              color: "#f8fafc",
              fontSize: 90,
              lineHeight: 1.08,
              fontWeight: 850,
              letterSpacing: -3,
              opacity: interpolate(frame, [0, 14], [0, 1], {
                extrapolateLeft: "clamp",
                extrapolateRight: "clamp",
              }),
              translate: interpolate(frame, [0, 18], ["0px 26px", "0px 0px"], {
                extrapolateLeft: "clamp",
                extrapolateRight: "clamp",
                easing: Easing.bezier(0.16, 1, 0.3, 1),
              }),
            }}
          >
            Relay 能改变什么？
          </Interactive.Div>
        </div>
        <div
          style={{
            color: "#94a3b8",
            fontSize: 28,
            lineHeight: 1.45,
            textAlign: "right",
            opacity: interpolate(frame, [10, 28], [0, 1], {
              extrapolateLeft: "clamp",
              extrapolateRight: "clamp",
            }),
          }}
        >
          风险信号需要证据交叉验证
          <br />
          <span style={{ color: "#64748b", fontSize: 21 }}>Signals, not automatic conclusions</span>
        </div>
      </div>

      <div
        style={{
          marginTop: 70,
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: 24,
        }}
      >
        {THREATS.map((threat, index) => {
          const start = 24 + index * 19;
          return (
            <div
              key={threat.code}
              style={{
                minHeight: 205,
                borderRadius: 28,
                border: "1px solid #283548",
                backgroundColor: "rgba(17,24,39,0.82)",
                padding: "34px 38px",
                display: "flex",
                alignItems: "center",
                gap: 30,
                boxShadow: `inset 4px 0 0 ${threat.color}`,
                opacity: interpolate(frame, [start, start + 13], [0, 1], {
                  extrapolateLeft: "clamp",
                  extrapolateRight: "clamp",
                }),
                translate: interpolate(frame, [start, start + 17], ["0px 30px", "0px 0px"], {
                  extrapolateLeft: "clamp",
                  extrapolateRight: "clamp",
                  easing: Easing.bezier(0.16, 1, 0.3, 1),
                }),
              }}
            >
              <div
                style={{
                  width: 82,
                  height: 82,
                  flexShrink: 0,
                  borderRadius: 24,
                  border: `2px solid ${threat.color}`,
                  color: threat.color,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontFamily: '"SF Mono", "Cascadia Code", monospace',
                  fontWeight: 850,
                  fontSize: 19,
                  letterSpacing: -0.5,
                  boxShadow: `0 0 35px ${threat.color}24`,
                }}
              >
                {String(index + 1).padStart(2, "0")}
              </div>
              <div>
                <div style={{ color: "#f8fafc", fontSize: 40, fontWeight: 780 }}>{threat.title}</div>
                <div
                  style={{
                    marginTop: 8,
                    color: threat.color,
                    fontFamily: '"SF Mono", "Cascadia Code", monospace',
                    fontSize: 19,
                    fontWeight: 700,
                    letterSpacing: 1.5,
                  }}
                >
                  {threat.code}
                </div>
                <div style={{ marginTop: 7, color: "#64748b", fontSize: 20 }}>{threat.detail}</div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
