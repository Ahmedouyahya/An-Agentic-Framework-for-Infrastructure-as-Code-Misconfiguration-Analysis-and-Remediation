# Rapports

Thesis drafts, progress reports, and the final document.

## Layout

```
Rapports/
├── drafts/              Progress reports (rapport1 ... rapport5) and side pieces
├── final/               Final thesis document (added when writing is complete)
├── soutenance/          Defense material (slides, notes)
├── rapport5_preparation.md    Internal planning notes for rapport 5
└── rapport5_status_audit.md   Internal status audit written before rapport 5
```

## Progress reports

Each progress report summarises the work delivered at a given checkpoint
of the thesis. They are cumulative: reading the latest one alone is not
enough to reconstruct the whole trajectory.

| # | Folder                          | Focus                                                               |
|---|---------------------------------|---------------------------------------------------------------------|
| 1 | `drafts/rapport1/`              | Problem framing, subject proposal, initial state of the art         |
| 2 | `drafts/rapport2/`              | First framework skeleton, retrieval module, Configuration A/B/C     |
| 3 | `drafts/rapport3/`              | Expanded architecture, knowledge-base design, taxonomy adoption     |
| 4 | `drafts/rapport4/`              | Scraping pipeline design, dataset collection plan                   |
| 5 | `drafts/rapport5/`              | First preliminary QLoRA fine-tuning experiment on Gemma-2-2B-IT     |

## Side documents

- `drafts/rapport-critique/` — critical review of the approach and of
  the related literature (standalone piece, not part of the numbered
  sequence).
- `drafts/rp2/` — bibliographic report on IaC security and smart
  contracts, produced early in the project as a literature survey.

## Build

Each rapport folder is a self-contained LaTeX project. To rebuild a
report PDF:

```bash
cd drafts/rapport5   # or any other
pdflatex rapportN.tex
makeglossaries rapportN   # only for reports that use the glossary
pdflatex rapportN.tex
```

Most reports use the `glossaries` package for acronym management;
re-running `pdflatex` twice (with `makeglossaries` in between) is
sufficient to resolve all cross-references.
