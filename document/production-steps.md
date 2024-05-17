# Manual Steps (TODO: Automate this)

These are the steps I used to move from our internal draft excel Excel file to .md files and then eventually to produce the PDF.

- Take the Excel file and for each test tab, copy cells B8:F*, where * is the last row for that tab.
- paste those copied cells into: https://tabletomarkdown.com/convert-spreadsheet-to-markdown/ and click "Submit", then "copy".
- Paste that data into the "Testing Checklist" section for the relevant markdown file for that set of tests.
- Remove all of the blank lines between the titles and the first entry, including the seperator.
- Insert this new seperator, it represents % widths for `pandoc` to understand when we produce the PDF:
    ```
    | ---- | ------------- | - | - | - |
    ```
- install `pandoc`
- Now `cd` to the root of the project and run `pandoc document/0.1/*.md -o TASVS-v0.1.pdf -V geometry:margin=2cm`
    - `0.1` will need updating depending on release version


## Example output of expected table layout

| TASVS-ID       | Description                                                                                                                                 | L1 | L2 | L3 |
| ---- | ------------- | - | - | - |
| TASVS-ARCH-1   | Threat Modeling                                                                                                                             |    |    |    |
| TASVS-ARCH-1.1 | Completed a low fidelity threat model for thick client.                                                                                     | X  | X  | X  |
| TASVS-ARCH-1.2 | Completed a high fidelity threat model for thick client which is in currently in production.                                                |    | X  | X  |
| TASVS-ARCH-1.3 | Threat model includes server-side components and dependencies (cloud APIs, OIDC provider, file storage, etc.).                              |    | X  | X  |
| TASVS-ARCH-1.4 | Threat modeling process included all phases (system modeling, auto-threat identification, manual threat identification, threat mitigation). |    | X  | X  |
| TASVS-ARCH-1.5 | Threat model checked-in to source code repository.                                                                                          | X  | X  | X  |
| TASVS-ARCH-1.6 | Threat model updated regularly as part of a documented process within development team's SSDLC.                                             |    | X  | X  |