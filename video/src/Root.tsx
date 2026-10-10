import "./index.css";
import { Composition, Folder } from "remotion";
import { ApiRelayAudit30 } from "./ApiRelayAudit30";
import { HookScene } from "./scenes/HookScene";
import { ThreatsScene } from "./scenes/ThreatsScene";
import { AuditFlowScene } from "./scenes/AuditFlowScene";
import { EvidenceScene } from "./scenes/EvidenceScene";
import { CtaScene } from "./scenes/CtaScene";

export const RemotionRoot: React.FC = () => {
  return (
    <>
      <Folder name="API-Relay-Audit-Scenes">
        <Composition
          id="HookScene"
          component={HookScene}
          durationInFrames={120}
          fps={30}
          width={1920}
          height={1080}
        />
        <Composition
          id="ThreatsScene"
          component={ThreatsScene}
          durationInFrames={170}
          fps={30}
          width={1920}
          height={1080}
        />
        <Composition
          id="AuditFlowScene"
          component={AuditFlowScene}
          durationInFrames={260}
          fps={30}
          width={1920}
          height={1080}
        />
        <Composition
          id="EvidenceScene"
          component={EvidenceScene}
          durationInFrames={220}
          fps={30}
          width={1920}
          height={1080}
        />
        <Composition
          id="CtaScene"
          component={CtaScene}
          durationInFrames={170}
          fps={30}
          width={1920}
          height={1080}
        />
      </Folder>
      <Composition
        id="ApiRelayAudit30"
        component={ApiRelayAudit30}
        durationInFrames={900}
        fps={30}
        width={1920}
        height={1080}
      />
    </>
  );
};
