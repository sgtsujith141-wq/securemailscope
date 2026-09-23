# Storyboard

Frame-by-frame intent. Read alongside `shot-list.md` and `narration.md`.

```
0:00  ┌──────────────────────────────┐   Dark. One line of text.
      │  Your email says it uses TLS.│   No logo yet. No music swell.
      └──────────────────────────────┘
0:04  ┌──────────────────────────────┐   Hard cut into the product,
      │  [TLS-KEX-001  HIGH  P1]     │   already showing a real finding.
      │  No forward secrecy          │   The viewer sees the answer
      └──────────────────────────────┘   before the question is finished.
0:08  ┌────────┬────────┬────────────┐   Three fast cuts.
      │TLS 1.0 │ 59/100 │ packets 4-5│   Each ~0.8s. No narration.
      └────────┴────────┴────────────┘
0:12  ┌──────────────────────────────┐   Title card. Restrained.
      │      SecureMailScope         │   Product name, one line,
      │  Evidence-backed cryptographic│  then straight out.
      │  investigation for email      │
      └──────────────────────────────┘
0:18  PCAP → TCP → SMTP/IMAP/POP3 → TLS → Evidence → Risk
      Built from the real architecture, revealed left to right
      as the narration names each stage.
0:45  First-run screen. The four steps. Holds while the
      narration makes the passive-only point. This screen
      exists because a new user needs it — showing it is honest.
1:00  Upload. Real drag, real file, real analysis, real duration.
1:20  Overview. Hold on "4 high-priority issues require attention".
      The score is visible but is not the subject of the frame.
1:40  ── THE MOMENT ──
      Finding detail, then evidence expands. Zoom slightly.
      Packets #4 and #5 on screen while the narration says them.
      This is the shot the whole video exists for.
2:05  ── THE SECOND MOMENT ──
      TLS 1.3. Certificate: NOT AVAILABLE, with the reason.
      Hold longer than feels comfortable. Saying what you cannot
      see is the most credible thing the product does.
2:30  Drift. Two captures side by side. TLS 1.2 → TLS 1.0.
      OBSERVED_CHANGE. Hold on the attribution explanation.
2:55  PDF export, then the PDF itself open, scrolled to the finding.
3:10  Montage, ~1s per frame, then end card.
3:30  ┌──────────────────────────────┐
      │       SecureMailScope        │
      │   SIH26159  ·  Zero-Day      │
      └──────────────────────────────┘
```

## Pacing

Fast at the top (0:00–0:18), steady in the middle, and deliberately slow at
1:40 and 2:05. Those two moments are the argument; everything else is context.

## Sound

No music under the two slow moments — silence carries them better. If music is
used elsewhere it must be a licence the team holds. No stock "cyber" tension
beds.
