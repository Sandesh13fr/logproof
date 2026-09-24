# Artifact contract

## Reference

- Reference DOCX: `C:\Users\sande\.codex\plugins\cache\openai-curated-remote\openai-templates\0.1.1\skills\artifact-template-system-design\assets\reference.docx`
- SHA-256: `13504f6c221a42c1726460a9e865e563355539ff97d702d6c9b2267b4b261d76`
- Reference: 7 pages, 1 portrait section, 9 tables, 24 package parts.
- Evidence: bundled `section_audit.py`, `style_lint.py`, python-docx inventory, and the reference PDF exported read-only with Word to `%TEMP%\logproof-system-design-template.pdf`.
- The supplied preview was visually inspected. It shows the one-page cover pattern. The full reference PDF page text was inspected for all seven page patterns.

## Page system

- US Letter portrait, 8.5 x 11 inches; one section; left/right/top margins 0.70 inches, bottom 0.62 inches.
- Different first page is enabled. The first page contains a title block and a five-cell status/owner/date row, followed by a four-row metadata table.
- Later pages repeat a running footer. Replace the organization placeholder with `LogProof` while retaining footer alignment and page fields.
- Seven reference page patterns: cover; abstract/goals/problem; architecture/figure/components; lifecycle/contracts; consistency/security/operational readiness; operational readiness/alternatives/open questions; decision/milestones.

## Typography and color

- Template Title: 22 pt bold, dark navy, 7.5 pt after. Heading 1: 13.5 pt bold, dark navy, 6.5 pt after. Heading 2: 9.5 pt bold, Calibri. Heading 3: Helvetica Neue bold. Normal and tables use Helvetica Neue with direct formatting.
- User explicitly requests black and white. Recolor the copied document's blue headings and pale-blue table accents to black, white, and neutral gray. Preserve font sizes, typography, spacing, margins, paragraph roles, and table grid.
- Do not edit the retained source template.

## Components and slot map

- Cover paragraphs 8 and 9: product name and document title.
- Cover table 0: status, owner, date. Cover table 1: authors, reviewers, related documents, scope.
- Section 1 Abstract: paragraphs 22-23.
- Section 2 Goals and Non-Goals: table 2.
- Section 3 Background and Problem Statement: paragraphs 28-29.
- Section 4 Proposed Architecture: figure area at paragraphs 31-34; caption paragraph 33; table 3 is the component map.
- Section 5 Request Lifecycle: paragraphs 40-46. Add the concise screen and button guide as a cloned table pattern after this lifecycle.
- Section 6 API and Data Contracts: table 4 is the normalized event contract; paragraphs 54-59 are guarantees and schema reference.
- Section 7 Consistency, Idempotency, and Replay: paragraph 63 and table 5.
- Section 8 Security and Privacy: paragraphs 67-71.
- Section 9 Operational Readiness: table 6 and rollout constraint row.
- Section 10 Alternatives Considered: table 7.
- Section 11 Open Questions: paragraphs 81-84.
- Section 12 Decision and Next Steps: paragraph 87 and table 8.
- Metadata uses repository facts only. Unknown authors and owners remain stated as unassigned rather than invented.

## Package preservation and fidelity gates

- Retain section geometry, page fields, headers/footers, existing numbering, table styles/layouts, relationships, and font parts unless an explicit content or monochrome change requires an edit.
- Record the retained reference SHA-256 before and after authoring. Edit a copy only.
- Compare page count, section geometry, heading order, table count/patterns, and unchanged package parts. Inspect every final rendered page at 100% zoom.
- Expected deviations: replace template placeholders with LogProof behavior; add one interface action table and one monochrome architecture diagram; recolor blue accents to grayscale at the user's request.
