# Narration

The words, as spoken in the finished video, one entry per generated line.
Written to be said out loud rather than read off a page, in the register a
team uses when it presents to judges: no hook, no slogan, no trailer voice.

## Voice

| Field | Value |
|---|---|
| Provider | ElevenLabs |
| Model | `eleven_multilingual_v2` |
| Voice | **Neel** (`SQ8WYwlpzxrTbbuJgi38`) — Indian English, conversational, professional |
| Settings | stability 0.42 · similarity 0.82 · style 0.18 · speaker boost on · speed 1.06 |
| Length | 14 lines, 326 words, 134.7s of speech |
| Pace | 145 words per minute across the whole script |

The voice is **synthesised**, not a person, and that is stated here, in
`demo-verification.md` and in `submission/README.md`. The operating system's
own speech synthesis was rejected for this project: it sounds robotic, and a
national-level submission should not open with a machine reading a script.

Regenerate with `bash scripts/make_narration.sh`, or one line at a time with
`bash scripts/make_narration.sh 10-tls13`. The audio itself is not committed
— it is large and regenerable — but the script, the voice and the exact
settings are, so a rebuild sounds the same.

Every line is quality-checked by `scripts/check_narration.py`, which measures
pace against the batch, looks for clipped samples, looks for the repeating
consonant artefact a stitched take produces, and flags a dead tail.

## Script

**01-intro** · 24 words · 11.52s

> Hello, we are Team Zero-Day, and our solution for SIH26159 is SecureMailScope — an AI-assisted cryptographic security posture assessment tool for secure email communications.

**02-what** · 29 words · 14.77s

> SecureMailScope analyzes authorised PCAP and PCAPNG captures and shows how email traffic was actually protected — including TLS versions, cipher suites, key exchange, certificate evidence, security findings and remediation.

**03-problem** · 18 words · 5.90s

> Even when email traffic is encrypted, the cryptography negotiated during the connection may still be outdated or weak.

**04-passive** · 21 words · 7.52s

> SecureMailScope works passively on traffic the organisation already has. It does not contact the mail server, and the capture remains local.

**05-analysis** · 12 words · 4.69s

> Here we analyze a controlled synthetic capture containing a deliberately weak configuration.

**06-engine** · 20 words · 9.80s

> The engine rebuilds the TCP session, identifies the email protocol, follows the TLS negotiation and evaluates the observed cryptographic parameters.

**07-finding** · 21 words · 8.59s

> This session negotiated static RSA key exchange, so it does not provide forward secrecy. SecureMailScope classifies this as a high-priority finding.

**08-evidence** · 33 words · 10.50s

> Every finding is linked back to the packet evidence used to establish it. Here the system points to packets four and five, together with their timestamps and the observation that triggered the rule.

**09-verify** · 16 words · 4.88s

> This allows an analyst to independently verify the same evidence in a tool such as Wireshark.

**10-tls13** · 42 words · 16.53s

> SecureMailScope also distinguishes evidence it could not observe from evidence that something is safe. In TLS 1.3, certificate messages may be encrypted in a passive capture. When that evidence cannot be observed, the tool reports it as NOT AVAILABLE instead of guessing.

**11-drift** · 30 words · 13.98s

> For repeated observations of the same service, SecureMailScope compares cryptographic posture across captures. Here, the observed negotiation changes from TLS 1.2 to TLS 1.0, which is recorded as cryptographic drift.

**12-report** · 21 words · 9.47s

> The investigation can then be exported as JSON, standalone HTML or PDF, carrying the findings, supporting packet references and remediation guidance.

**13-summary** · 13 words · 6.22s

> In summary, SecureMailScope provides passive, local-first and evidence-linked analysis of secure email traffic.

**14-close** · 26 words · 10.31s

> It helps an analyst understand what cryptography was actually negotiated, identify weaknesses, verify the evidence, track changes across captures and generate a forensic report. Thank you.
