import { Easing, Interactive, interpolate, useCurrentFrame } from "remotion";
import { BrandMark } from "../components/BrandMark";

export const CtaScene: React.FC = () => {
  const frame = useCurrentFrame();

  return (
    <div
      style={{
        position: "absolute",
        inset: 0,
        padding: "126px 112px 150px",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        textAlign: "center",
      }}
    >
      <BrandMark />
      <div
        style={{
          marginTop: 28,
          color: "#60a5fa",
          fontFamily: '"SF Mono", "Cascadia Code", monospace',
          fontSize: 19,
          fontWeight: 750,
          letterSpacing: 4,
          opacity: interpolate(frame, [8, 24], [0, 1], {
            extrapolateLeft: "clamp",
            extrapolateRight: "clamp",
          }),
        }}
      >
        OPEN SOURCE · LOCAL EXECUTION · REVIEWABLE EVIDENCE
      </div>
      <Interactive.Div
        name="Product name"
        style={{
          marginTop: 18,
          color: "#f8fafc",
          fontSize: 108,
          lineHeight: 1,
          fontWeight: 880,
          letterSpacing: -5,
          opacity: interpolate(frame, [13, 31], [0, 1], {
            extrapolateLeft: "clamp",
            extrapolateRight: "clamp",
          }),
          translate: interpolate(frame, [13, 34], ["0px 28px", "0px 0px"], {
            extrapolateLeft: "clamp",
            extrapolateRight: "clamp",
            easing: Easing.bezier(0.16, 1, 0.3, 1),
          }),
        }}
      >
        API Relay Audit
      </Interactive.Div>
      <Interactive.Div
        name="CTA tagline"
        style={{
          marginTop: 24,
          color: "#cbd5e1",
          fontSize: 58,
          lineHeight: 1.25,
          fontWeight: 760,
          opacity: interpolate(frame, [26, 44], [0, 1], {
            extrapolateLeft: "clamp",
            extrapolateRight: "clamp",
          }),
        }}
      >
        Audit before you trust.
      </Interactive.Div>
      <div
        style={{
          marginTop: 38,
          padding: "17px 28px",
          borderRadius: 18,
          border: "1px solid rgba(96,165,250,0.35)",
          backgroundColor: "rgba(59,130,246,0.09)",
          color: "#93c5fd",
          fontFamily: '"SF Mono", "Cascadia Code", monospace',
          fontSize: 25,
          letterSpacing: 0.4,
          opacity: interpolate(frame, [38, 56], [0, 1], {
            extrapolateLeft: "clamp",
            extrapolateRight: "clamp",
          }),
        }}
      >
        github.com/toby-bridges/api-relay-audit
      </div>
      <div
        style={{
          position: "absolute",
          bottom: 168,
          left: 112,
          right: 112,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          color: "#64748b",
          fontFamily: '"SF Mono", "Cascadia Code", monospace',
          fontSize: 18,
          letterSpacing: 1.4,
          opacity: interpolate(frame, [52, 70], [0, 1], {
            extrapolateLeft: "clamp",
            extrapolateRight: "clamp",
          }),
        }}
      >
        <span>v2.4.1</span>
        <span style={{ flex: 1, height: 1, margin: "0 24px", backgroundColor: "#283548" }} />
        <span>PUBLIC RELEASE BASELINE</span>
      </div>
    </div>
  );
};
