 # OWASP Thick Client Application Security Verification Standard (TASVS)
[![Downloads](https://img.shields.io/github/downloads/owasp/www-project-thick-client-application-security-verification-standard/total?logo=github&logoColor=white&style=flat-square)](https://github.com/owasp/www-project-thick-client-application-security-verification-standard/releases)
[![GitHub contributors](https://img.shields.io/github/contributors/owasp/www-project-thick-client-application-security-verification-standard)](https://github.com/owasp/www-project-thick-client-application-security-verification-standard/graphs/contributors)
[![GitHub issues](https://img.shields.io/github/issues/owasp/www-project-thick-client-application-security-verification-standard)](https://github.com/owasp/www-project-thick-client-application-security-verification-standard/issues)
[![GitHub pull requests](https://img.shields.io/github/issues-pr/owasp/www-project-thick-client-application-security-verification-standard)](https://github.com/owasp/www-project-thick-client-application-security-verification-standard/pulls)
[![GitHub license](https://img.shields.io/github/license/owasp/www-project-thick-client-application-security-verification-standard)](https://github.com/owasp/www-project-thick-client-application-security-verification-standard/blob/main/LICENSE)


 
## Introduction
The OWASP Thick Client Application Security Verification Standard (TASVS) Project aims to establish an open standard for securing thick client applications. This project provides a comprehensive framework for designing, building, and testing technical application security controls.

The TASVS Project fills the gap between the [OWASP Application Security Verification Standard (ASVS)](https://github.com/OWASP/ASVS) for web applications and the [Mobile Application Security Verification Standard (MASVS)](https://github.com/OWASP/owasp-masvs). While the MASVS can be applied to thick client testing, it is not an ideal fit. The TASVS Project seeks to create a more suitable standard for these scenarios.

## Project Leaders and Working Group

The project is mainly maintained by a single project leader [Dave Hanson](https://github.com/JeffreyShran). However he is heavily supported by his active AppSec team at Bentley Systems who include [Samuel Aubert](https://github.com/matreurai), [Einaras Bartkus](https://github.com/eb-bsi), [Thomas Chauchefoin](https://www.linkedin.com/in/thomaschauchefoin), and [John Cotter](https://www.linkedin.com/in/john-cotter-40338612/).

The project is also supported by the OWASP community and the OWASP Foundation. Special, thanks to [Starr Brown](https://github.com/mamicidal) for her support in her capacity as Director of Projects.

## Roadmap

The first public version that was suitable for use was released in September 2024. The project is in the process of refining the standard and adding more content.

As we mature, we will be looking to create a more structured approach to the roadmap. As with most activities we will allow ourselves to be steered by the work completed by the [ASVS project](https://github.com/OWASP/ASVS/wiki/Roadmap-to-version-5.0) to find that strucutre.

In the `utils\Convert-TASVS-Excel` directory, there is a script that can be used to populate an Excel template with the TASVS checklist. This is a useful tool for applying the standard in a practical way. It is not fully release ready yet, but can be used in a pinch. I will endevour to update it over time, for now grab the Excel file that will be named something like `TASVS_v1.6.xlsx`.

## Contributing

The project is looking for contributors to help with the following tasks:

- Getting the word out about the project. If you do ntohing else, please share this project with your network.
- Review and provide feedback on the current standard.
- Create new control objectives.
- Update existing control group definitions, particularly those ones that:
  - might benefit from code examples and 
  - those that could be elaborated on further in simpler terms to make it more accessible to juniors in our field and developers with less security experience.

> If you are interested in contributing, please review the [Contributing Guidelines](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md) documents.

## Standard Objectives

The requirements were developed with the following objectives in mind and are taken from the web ASVS project: https://github.com/OWASP/ASVS/blob/master/README.md#standard-objectives

* Help organizations adopt or adapt a high quality secure coding standard.
* Help architects and developers build secure software by designing and building security in, and verifying that they are in place and effective by the use of unit and integration tests that implement tests.
* Help security reviewers use a comprehensive, consistent, high quality standard for hybrid code reviews, secure code reviews, peer code reviews, retrospectives, and work with developers to build security unit and integration tests. It is even possible to use this standard for penetration testing at Level 1

## Special thanks to our contributers

The OWASP Thick Client Application Security Verification Standard (TASVS) Project would like to thank the following contributors for their support and dedication to the project:

<a href="https://github.com/OWASP/www-project-thick-client-application-security-verification-standard/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=OWASP/www-project-thick-client-application-security-verification-standard" />
</a>

## Sponsors

<a href="https://www.bentley.com/company/about-us/">
  <div>
    <img src="assets\images\BentleyLOGO_BLK_type.jpg" width="230" alt="Bentley Systems" />
  </div>
  <b>
    Bentley is the leading provider of infrastructure engineering software, advancing infrastructure for better quality of life and sustainability.
  </b>
  <div>
    <sup>Visit <u>bentley.com</u> to learn more.</sup>
  </div>
</a>

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=OWASP/www-project-thick-client-application-security-verification-standard&type=Date)](https://star-history.com/#OWASP/www-project-thick-client-application-security-verification-standard&Date)

## License

The entire project content is under the [Creative Commons Attribution-ShareAlike 4.0 International License][cc-by-sa].

## Related

Here are some related projects:
> please open an issue if you would like to have your project listed here.

- [OWASP Application Security Verification Standard (ASVS)](https://github.com/OWASP/ASVS)
- [OWASP Mobile Application Security Verification Standard (MASVS)](https://github.com/OWASP/owasp-masvs)