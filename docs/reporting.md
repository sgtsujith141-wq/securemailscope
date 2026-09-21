# Reporting

Three formats, one source. JSON, HTML and PDF are renderings of a single
`ReportModel`, so a fact that appears in two of them comes from one place.

## The canonical model

`reporting/report_model.py` performs **selection and structuring only**. The
posture score, coverage, findings, drift statuses and blast-radius counts are
copied from what the M4 and M5 engines decided. Nothing is recomputed.

This matters more than it might seem. A Jinja template that recalculated a
score, or a React component that summed severities in JavaScript, would be a
second analysis engine with no tests — and the first time it disagreed with the
real one, the report would be wrong in a way nobody could see. So: if a number
is not already in the analysis result, it does not appear in a report.

## Parity

`tests/test_backend.py::test_all_three_formats_agree_on_the_facts` compares,
across all three formats:

capture ids · session ids and counts · finding rule ids and severities · policy
version · posture score · remediation ids · blast-radius subjects · ML
validation status and anomaly algorithm

Long identifiers wrap across lines in the PDF, which is correct — wrapping is
what stops them being clipped — so the comparison is made on whitespace-
normalised text.

## JSON

The canonical model serialised with sorted keys and a stable indent. Preserves
forensic observations, findings, policy version, scores and coverage,
cryptographic intelligence, evidence references, ML validation status and
limitations.

## HTML

Rendered with Jinja2. Three properties are enforced in code rather than left to
the template author:

**Autoescaping, everywhere.** Every value in a report derives from a capture,
and a capture is untrusted input: a certificate subject, an SNI value or a
protocol banner can contain anything, including markup. No value is ever marked
safe. `test_the_html_report_escapes_untrusted_text` feeds a `<script>` tag
through the title and asserts it comes out escaped.

**Self-contained.** No external font, script, stylesheet or image, and no
network request of any kind. A forensic report that phoned home when opened
would leak the fact of an investigation — and possibly its contents — to
whoever served the asset. `find_external_references()` re-checks the rendered
output and **raises** if anything slipped in, so a template change cannot
quietly reintroduce one.

**No payload bytes.** Packet numbers, timestamps and stream offsets only.

## PDF

Built with ReportLab's Platypus **directly from the model**, not by converting
the HTML.

That is a security decision. An HTML-to-PDF renderer resolves what the document
references — stylesheets, fonts, images, and with some engines `file://` URLs.
Report content derives from untrusted captures, so a fetching renderer would be
a way to turn a malicious certificate subject into a local file read or an
outbound request. Platypus has no URL resolver at all: the guarantee is
structural, not a filter that has to be kept correct.

Typography uses the fonts ReportLab bundles, so nothing is read from the system
or the network.

### Layout

A4, 18 mm margins, page numbers and generation metadata in the footer of every
page. **Every table cell is a `Paragraph`**, so long values wrap instead of
clipping — a bare string in a ReportLab table is silently truncated at the cell
boundary, which is exactly the failure §19 asks to be tested for. Findings and
remediations are wrapped in `KeepTogether` so a block does not split across a
page boundary.

### Verification

It is not enough that a file was produced. `test_the_pdf_renders_correctly`:

- asserts the page size is A4 (595 × 842 pt);
- extracts the text and checks for the expected sections, page numbers and the
  scope statement;
- **rasterises every page** with pypdfium2 and asserts each has ink (no blank
  pages) and that nothing bleeds into the margins (which is what clipping looks
  like).

`test_long_values_wrap_rather_than_clipping` asserts every 71-character capture
identifier appears in full in the extracted text.

## Sections

Executive summary · investigation scope and capture inventory · methodology ·
protocol observations · TLS and certificate intelligence · security findings ·
prioritised remediations · cryptographic fingerprints · drift · correlations ·
observed blast radius · ML analysis · evidence appendix · limitations ·
warnings.

Sections appear only when there is evidence for them. Missing content is never
replaced by an invented finding: a report with no findings says so, and says
explicitly that it is not a statement that the analysed systems are secure.

## What reports never contain

Reconstructed payload bytes · credentials, usernames, passwords or SASL
payloads · email addresses or message bodies · private keys · anything fetched
from a network.

`test_reports_contain_no_payload_or_credentials` runs a capture carrying dummy
credentials through all three formats — extracting the PDF's text to check it
too — and asserts none of the marked strings appears.
