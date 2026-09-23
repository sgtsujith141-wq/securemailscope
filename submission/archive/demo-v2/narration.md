# Narration script

Target: **3:00–3:30**. Roughly 155 words per minute, which is a normal
speaking pace — not a voiceover sprint.

Read it flat and confident. No sell, no adjectives that aren't doing work. The
material is interesting on its own; the delivery should get out of its way.

Timing notes are in brackets and are not spoken.

---

### 0:00 — Open on the result

> Your email says it uses TLS.

*[beat — two seconds of silence over the finding on screen]*

> But is the cryptography actually secure?

---

### 0:12 — Title

*[no narration over the title card]*

---

### 0:18 — The problem

> An organisation can tell you which mail servers it runs. It usually can't
> tell you which TLS versions those servers negotiated last week, which cipher
> suites they accepted, or which sessions had no forward secrecy.
>
> An active scanner won't answer that either. It reports what a server does for
> a scanner today — not what it did for real clients during the period you're
> investigating. And often you have no authority to touch the host at all.

---

### 0:45 — Passive by design

*[slow down here]*

> SecureMailScope reads the packet captures you already have.
>
> No live probing. No cloud upload. Nothing is sent anywhere, and no host in a
> capture is ever contacted.

---

### 1:00 — Live investigation

> This is a synthetic capture of an IMAP session over TLS.
>
> The capture is reconstructed into sessions, the email protocol is identified
> from the dialogue rather than the port, the TLS handshake is parsed, and each
> conclusion is tied back to the evidence behind it.

*[analysis runs — real, not sped up beyond a small editorial trim]*

> Fifty-nine out of a hundred. Weak. Four findings, two of them high priority.
>
> Notice what the interface leads with: not the score — the things that need
> attention.

---

### 1:40 — Evidence

*[slow down — this is the point of the product]*

> Static RSA key exchange. No forward secrecy.
>
> Instead of just saying "weak cryptography", SecureMailScope shows why it was
> flagged — the RFC it applies, the packets the evidence came from, and what to
> change.
>
> Packets four and five. You can open the same capture in Wireshark and check.

---

### 2:05 — What it won't claim

*[slow down again]*

> Here's a TLS 1.3 session. The certificate reads: not available.
>
> TLS 1.3 encrypts the certificate message. A passive capture without
> decryption material cannot expose what isn't on the wire — so the tool says
> so, rather than leaving a blank or guessing.

---

### 2:30 — Drift

> Two captures of the same server, an hour apart. Same client offer both times.
>
> The server selected TLS 1.2, then TLS 1.0. Because the offer didn't change,
> the difference is attributable to the server — and it's reported as an
> observed change, not an inference.

---

### 2:55 — Report

> Every investigation exports as JSON, offline HTML, or a forensic PDF. The
> HTML opens with no network access at all.

---

### 3:10 — Close

*[slow, deliberate]*

> SecureMailScope turns captured email traffic into explainable cryptographic
> evidence — so a security team can see what changed, understand what matters,
> and know what to fix.

*[end card: SecureMailScope · SIH26159 · Zero-Day]*

---

## Words to avoid

Banned outright, because they are hype and this project does not need it:

*revolutionary · cutting-edge · next-generation · game-changer · seamless ·
leverage · empower · unlock · imagine a world · welcome guys · in today's
video · AI-powered* (the anomaly detector in use is not a model, so this one
would also be false)

## Claims that must not be made

- That an **attack** was detected. The tool observes configurations.
- That the ML classifier is validated. It is `NOT_VALIDATED`.
- That the anomaly detector is machine learning. The one in use is a
  deterministic frequency table.
- That blast radius describes an enterprise. It is "observed within analyzed
  captures only".
- Any deployment, user count, saving or real-world detection rate.
