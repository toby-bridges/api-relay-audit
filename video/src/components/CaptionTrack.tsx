import type { Caption } from "@remotion/captions";
import { useCallback, useEffect, useState } from "react";
import {
  AbsoluteFill,
  interpolate,
  staticFile,
  useCurrentFrame,
  useDelayRender,
  useVideoConfig,
} from "remotion";

export const CaptionTrack: React.FC = () => {
  const [captions, setCaptions] = useState<Caption[] | null>(null);
  const { delayRender, continueRender, cancelRender } = useDelayRender();
  const [handle] = useState(() => delayRender("Loading public-safe captions"));
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const loadCaptions = useCallback(async () => {
    try {
      const response = await fetch(staticFile("captions.json"));
      if (!response.ok) {
        throw new Error(`Could not load captions: ${response.status}`);
      }
      const data = (await response.json()) as Caption[];
      setCaptions(data);
      continueRender(handle);
    } catch (error) {
      cancelRender(error instanceof Error ? error : new Error(String(error)));
    }
  }, [cancelRender, continueRender, handle]);

  useEffect(() => {
    loadCaptions();
  }, [loadCaptions]);

  if (!captions) {
    return null;
  }

  const nowMs = (frame / fps) * 1000;
  const active = captions.find(
    (caption) => nowMs >= caption.startMs && nowMs < caption.endMs,
  );

  if (!active) {
    return null;
  }

  const localFrame = frame - (active.startMs / 1000) * fps;
  const duration = ((active.endMs - active.startMs) / 1000) * fps;

  return (
    <AbsoluteFill
      style={{
        pointerEvents: "none",
        justifyContent: "flex-end",
        alignItems: "center",
        paddingBottom: 68,
      }}
    >
      <div
        style={{
          maxWidth: 1510,
          padding: "16px 32px 18px",
          borderRadius: 22,
          border: "1px solid rgba(148,163,184,0.22)",
          backgroundColor: "rgba(6,10,18,0.78)",
          boxShadow: "0 16px 70px rgba(0,0,0,0.35)",
          backdropFilter: "blur(16px)",
          color: "#f8fafc",
          fontSize: 48,
          fontWeight: 720,
          lineHeight: 1.25,
          textAlign: "center",
          letterSpacing: 1,
          opacity: interpolate(localFrame, [0, 6, duration - 6, duration], [0, 1, 1, 0], {
            extrapolateLeft: "clamp",
            extrapolateRight: "clamp",
          }),
          translate: interpolate(localFrame, [0, 8], ["0px 18px", "0px 0px"], {
            extrapolateLeft: "clamp",
            extrapolateRight: "clamp",
          }),
        }}
      >
        {active.text}
      </div>
    </AbsoluteFill>
  );
};
