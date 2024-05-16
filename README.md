 # OWASP Thick Client Application Security Verification Standard
[![CC BY-SA 4.0][cc-by-sa-shield]][cc-by-sa]

This work is licensed under a
[Creative Commons Attribution-ShareAlike 4.0 International License][cc-by-sa].

[![CC BY-SA 4.0][cc-by-sa-image]][cc-by-sa]

[cc-by-sa]: http://creativecommons.org/licenses/by-sa/4.0/
[cc-by-sa-image]: https://licensebuttons.net/l/by-sa/4.0/88x31.png
[cc-by-sa-shield]: https://img.shields.io/badge/License-CC%20BY--SA%204.0-blue.svg
 
## Introduction

The primary aim of the OWASP Application Security Verification Standard (ASVS) Project is to provide an open application security standard for web apps and web services of all types.

The standard provides a basis for designing, building, and testing technical application security controls, including architectural concerns, secure development lifecycle, threat modelling, agile security including continuous integration / deployment, serverless, and configuration concerns.

This project aims to fill the gap between the web ASVS and the mobile ASVS (MASVS), whilst the MASVS can be used for thick client testing it's not a perfect fit and so we hope to produce something more appropriate.


## Roadmap to TASVS 1.0

The general idea would be to take the best and most applicable bits of the existing standards and then enhance it with specific items related to thick testing. I would call this our version 0.1 and produce it in spreadsheet form initially as (to my mind anyway) it's easier to relate the checklist approach to practical testing. My team would use it to review our existing products in our company (we have plenty to go at) in real AppSec engagements and refine it over time with the aim of producing version 1.0. At this point a formal PDF document would be produced and hopefully a new standard created.

Timelines would probably be in the 6-12 month range (end of 2024) for the v0.1 and timescales for refinement over time for the v1.0 production might be in the 6-24 months range (end of 2025) depending on how well the v0.1 is done initially. 


## Standard Objectives

The requirements were developed with the following objectives in mind and are taken from the web ASVS project: https://github.com/OWASP/ASVS/blob/master/README.md#standard-objectives

* Help organizations adopt or adapt a high quality secure coding standard
* Help architects and developers build secure software by designing and building security in, and verifying that they are in place and effective by the use of unit and integration tests that implement ASVS tests
* Help deploy secure software via the use of repeatable, secured builds
* Help security reviewers use a comprehensive, consistent, high quality standard for hybrid code reviews, secure code reviews, peer code reviews, retrospectives, and work with developers to build security unit and integration tests. It is even possible to use this standard for penetration testing at Level 1
* Assist tool vendors by ensuring there is an easily generatable machine readable version, with CWE mappings
* Assist organizations to benchmark application security tools by the percentage of coverage of the ASVS for dynamic, interactive, and static analysis tools
* Minimize overlapping and competing requirements from other standards, by either aligning strongly with them (NIST 800-63), or being strict supersets (OWASP Top 10 2017, PCI DSS 3.2.1), which will help reduce compliance costs, effort, and time wasted in accepting unnecessary differences as risks.


## License

The entire project content is under the [Creative Commons Attribution-ShareAlike 4.0 International License][cc-by-sa].
