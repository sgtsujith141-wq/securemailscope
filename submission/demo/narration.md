# Narration

The words, as spoken in the finished video. Written to be said out loud, not
read off a page: short sentences, contractions, no buzzwords.

## Voice

| Field | Value |
|---|---|
| Provider | ElevenLabs |
| Model | `eleven_multilingual_v2` |
| Voice | **Neel** (`SQ8WYwlpzxrTbbuJgi38`) — Indian English, conversational, professional |
| Settings | stability 0.42 · similarity 0.82 · style 0.18 · speaker boost on · speed 1.06 |
| Pace | ~141 words per minute across the whole script |

The voice is **synthesised**, not a person, and that is stated here, in
`demo-verification.md` and in `submission/README.md`. The operating system's
own speech synthesis was rejected for this project: it sounds robotic, and a
national-level submission should not open with a machine reading a script.

Regenerate with `bash scripts/make_narration.sh`. The audio itself is not
committed — it is large and regenerable — but the script, the voice and the
exact settings are, so a rebuild sounds the same.

## Script

**Hook**

> TLS is enabled. That sounds secure. But it doesn't tell you whether the server negotiated old protocols, weak key exchange, or a bad certificate setup. That's what SecureMailScope checks.

**Input**

> You give it an authorised PCAP or PCAPNG capture. It stays local. There's no live scan and no connection back to the mail server.

**Pipeline**

> SecureMailScope rebuilds the TCP sessions, figures out whether the traffic is SMTP, IMAP or POP three, follows STARTTLS, and then inspects the TLS handshake.

**Analysis**

> Here's a deliberately weak example. The server negotiated TLS 1.0 with static RSA. The investigation comes back weak, with high-priority findings that need attention.

**Evidence**

> And this is the part that matters. Open the finding. It isn't just saying weak crypto. The rule tells us what failed, why it matters, and exactly which packets established it. Packets four and five.

**Verify**

> So an analyst can take the same capture, open those packets in Wireshark, and check the conclusion independently.

**Tls13**

> It's also careful about what it can't see. In TLS 1.3, the certificate message is normally encrypted. So if the capture doesn't contain decryptable certificate evidence, SecureMailScope says NOT AVAILABLE. It doesn't guess.

**Drift**

> Now compare two captures from the same observed service. Earlier, it negotiated TLS 1.2. Later, TLS 1.0. SecureMailScope records that as observed cryptographic drift, with the evidence from both captures.

**Report**

> When the investigation is done, the same evidence can be exported as JSON, standalone HTML, or a forensic PDF. The report carries the findings, packet references and remediation with it.

**Close**

> So the idea is simple. Don't just ask whether email traffic is encrypted. Check what cryptography was actually negotiated. Show the evidence. And tell the analyst what needs fixing. That's SecureMailScope.

## Why it reads this way

Judges hear a lot of narration that sounds like a product brochure. Every
line here is something a person would actually say while showing somebody
their tool: "And this is the part that matters." "It doesn't guess."
"Packets four and five." The claims are the same ones the deck makes, in the
same order, about the same finding.
