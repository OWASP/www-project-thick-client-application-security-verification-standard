# Populates Excel template used as a checklist during AppSec Audits

- Author: Dave Hanson
- Version: 0.1
- Usage: ./Convert-TASVS-Excel/convert-tasvs-excel.py



## Background

A standard is useless unless it can easily be applied practically. This script is designed to make it easier to do that. It will pull the md files straight from Github, extract the checklist section and then insert it into the correct tab in an excel template. Run it in the same directory as the template.

The template is an altered version of the MASVS one, I really liked the style and so i tried to reuse it. One day I would like to align our process with the ASVS and MASVS projects so we have a consistent approach.

I'd also like to integrate this script with the release process so that it gets automatically produced.

