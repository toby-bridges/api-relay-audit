# API Relay Audit — 30-second video

Remotion source for the public-safe API Relay Audit product video. It uses only
sanitized fixture data and does not contain API keys or private audit reports.

## Content baseline

The film is based on public release `v2.4.1`. Step 8 demonstrates pinned
package-command text comparison. The synthetic terminal uses `--profile full`
so the optional Web3 step is included. The report is a synthetic illustration,
not a real relay result or a safety certificate. Structured Tool Call
name/argument verification is not claimed by this film.

## Commands

Install dependencies:

```console
npm ci
```

Start the preview:

```console
npm run dev
```

Render the MP4 and cover:

```console
npm run render
npm run still
```

Run checks:

```console
npm run lint
npm run build
```

## Audio provenance

- Chinese narration: generated locally with
  [Qwen3-TTS 0.6B CustomVoice](https://github.com/QwenLM/Qwen3-TTS)
  (`Serena`, Apache-2.0) through
  [MLX Audio](https://github.com/Blaizzy/mlx-audio) (MIT).
- Soundbed: locally synthesized with FFmpeg; no third-party recording or sample.

Generated drafts in `out/` are ignored by Git. The reviewed MP4, cover,
and WebVTT captions used by the README are committed under `../web/assets/`.
The lightweight player is `../web/video.html`; it deploys through the existing
GitHub Pages workflow after merge.

After rendering, copy `out/api-relay-audit-30s.mp4` and
`out/api-relay-audit-cover.png` to `../web/assets/`, then verify their
metadata, decode, and visual layout before updating the public assets.
`../web/assets/api-relay-audit-zh.vtt` mirrors `public/captions.json`.

## License

Project source is AGPL-3.0-only. Remotion has its own
[license terms](https://github.com/remotion-dev/remotion/blob/main/LICENSE.md).
