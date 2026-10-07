import { Audio } from "@remotion/media";
import { TransitionSeries, linearTiming } from "@remotion/transitions";
import { fade } from "@remotion/transitions/fade";
import { AbsoluteFill, Sequence, interpolate, staticFile } from "remotion";
import { CaptionTrack } from "./components/CaptionTrack";
import { GridBackground } from "./components/GridBackground";
import { AuditFlowScene } from "./scenes/AuditFlowScene";
import { CtaScene } from "./scenes/CtaScene";
import { EvidenceScene } from "./scenes/EvidenceScene";
import { HookScene } from "./scenes/HookScene";
import { ThreatsScene } from "./scenes/ThreatsScene";

export const ApiRelayAudit30: React.FC = () => {
  return (
    <AbsoluteFill style={{ backgroundColor: "#0a0e17" }}>
      <GridBackground />
      <TransitionSeries>
        <TransitionSeries.Sequence durationInFrames={120} name="Hook">
          <HookScene />
        </TransitionSeries.Sequence>
        <TransitionSeries.Transition
          presentation={fade()}
          timing={linearTiming({ durationInFrames: 10 })}
        />
        <TransitionSeries.Sequence durationInFrames={170} name="Threats">
          <ThreatsScene />
        </TransitionSeries.Sequence>
        <TransitionSeries.Transition
          presentation={fade()}
          timing={linearTiming({ durationInFrames: 10 })}
        />
        <TransitionSeries.Sequence durationInFrames={260} name="Audit flow">
          <AuditFlowScene />
        </TransitionSeries.Sequence>
        <TransitionSeries.Transition
          presentation={fade()}
          timing={linearTiming({ durationInFrames: 10 })}
        />
        <TransitionSeries.Sequence durationInFrames={220} name="Evidence">
          <EvidenceScene />
        </TransitionSeries.Sequence>
        <TransitionSeries.Transition
          presentation={fade()}
          timing={linearTiming({ durationInFrames: 10 })}
        />
        <TransitionSeries.Sequence durationInFrames={170} name="CTA">
          <CtaScene />
        </TransitionSeries.Sequence>
      </TransitionSeries>

      <Audio
        src={staticFile("audio/soundbed-electronic-30s.wav")}
        volume={(frame) =>
          interpolate(frame, [0, 40, 800, 899], [0, 0.78, 0.78, 0], {
            extrapolateLeft: "clamp",
            extrapolateRight: "clamp",
          })
        }
      />
      <Sequence from={12} durationInFrames={830} layout="none" name="Chinese voiceover">
        <Audio src={staticFile("audio/voiceover-zh-qwen3.wav")} volume={1} />
      </Sequence>
      <CaptionTrack />
    </AbsoluteFill>
  );
};
