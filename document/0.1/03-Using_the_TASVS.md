# TODO: Make this as well written as: https://github.com/OWASP/owasp-TASVS/blob/master/Document/03-Using_the_TASVS.md

This page is basically a copy of the MASVS one right now. It needs personalising for our project. Their approach is great so why re-invent the wheel?

# The Thick Client Application Security Verification Standard

## Thick Client Application Security Model

The standard is divided into various groups that represent the most critical areas of the mobile attack surface. These control groups, labeled **TASVS-XXXXX**, provide guidance and standards for the following areas:

- **TASVS-STORAGE:** Secure storage of sensitive data on a device (data-at-rest).
- **TASVS-CRYPTO:** Cryptographic functionality used to protect sensitive data.
- **TASVS-AUTH:** Authentication and authorization mechanisms used by the mobile app.
- **TASVS-NETWORK:** Secure network communication between the mobile app and remote endpoints (data-in-transit).
- **TASVS-PLATFORM:** Secure interaction with the underlying mobile platform and other installed apps.
- **TASVS-CODE:** Security best practices for data processing and keeping the app up-to-date.
- **TASVS-RESILIENCE:** Resilience to reverse engineering and tampering attempts.
- **TASVS-PRIVACY:** Privacy controls to protect user privacy.

Each of these control groups contains individual controls labeled **TASVS-XXXXX-Y**, which provide specific guidance on the particular security measures that need to be implemented to meet the standard.


## MAS Testing Profiles

The MAS project has traditionally provided three verification levels (L1, L2 and R), which were revisited during the MASVS refactoring in 2023, and have been reworked as ["MAS Testing Profiles"](https://docs.google.com/document/d/1paz7dxKXHzAC9MN7Mnln1JiZwBNyg7Gs364AJ6KudEs/edit?usp=sharing) and moved over to the OWASP MASTG. These profiles are now aligned with the [NIST OSCAL (Open Security Controls Assessment Language)](https://pages.nist.gov/OSCAL/) standard, which is a comprehensive catalog of security controls that can be used to secure information systems.

By aligning with OSCAL, the MASVS provides a more flexible and comprehensive approach to security testing. OSCAL provides a standard format for security control information, which allows for easier sharing and reuse of security controls across different systems and organizations. This allows for a more efficient use of resources and a more targeted approach to mobile app security testing.

However, it is important to note that implementing these profiles fully or partially should be a risk-based decision made in consultation with business owners. The profiles should be tailored to the specific security risks and requirements of the mobile application being developed, and any deviations from the recommended controls should be carefully justified and documented.

## Assumptions

When using the MASVS, it's important to keep in mind the following assumptions:

- The MASVS is not a substitute for following secure development best practices, such as secure coding or secure SDLC. These practices should be followed holistically in your development process and the MASVS complements them specifically for mobile apps.
- The MASVS assumes that you've followed the relevant standards of your industry and country for all elements of your app's ecosystem, such as backend servers, IoT, and other companion devices.
- The MASVS is designed to evaluate the security of mobile apps that can be analyzed statically by obtaining the app package, dynamically by running it on a potentially compromised device, and also considers any network-based attacks such as MITM.

While the OWASP MASVS is an invaluable tool for enhancing the security of mobile applications, it cannot guarantee absolute security. It should be used as a baseline for security requirements, but additional security measures should also be implemented as appropriate to address specific risks and threats to the mobile app.

### Security Architecture, Design and Threat Modeling for Mobile Apps

> The OWASP MASVS assumes that best practices for secure architecture, design, and threat modeling have been followed as a foundation.

Security must be a top priority throughout all stages of mobile app development, from the initial planning and design phase to deployment and ongoing maintenance. Developers need to follow secure development best practices and ensure that security measures are prioritized to protect sensitive data, comply with policies and regulations, and identify and address security issues that can be targeted by attackers.

While the MASVS and MASTG focuses on controls and technical test cases for app security assessments, non-technical aspects such as following best practices laid out by [OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org/model/) or [NIST.SP.800-218 Secure Software Development Framework (SSDF)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf) for secure architecture, design, and threat modeling are still important. The MASVS can also be used as reference and input for a threat model to raise awareness of potential attacks.

To ensure that these practices are followed, developers can provide documentation or evidence of adherence to these standards, such as design documents, threat models, and security architecture diagrams. Additionally, interviews can be conducted to collect information on adherence to these practices and provide an understanding of the level of compliance with these standards.

### Secure App Ecosystem

> The OWASP MASVS assumes other relevant security standards are also leveraged to ensure that all systems involved in the app's operation meet their applicable requirements.

Mobile apps often interact with multiple systems, including backend servers, third-party APIs, Bluetooth devices, cars, IoT devices, and more. Each of these systems may introduce their own security risks that must be considered as part of the mobile app's security design and threat modeling. For example, when interacting with a backend server, the [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/) should be used to ensure that the server is secure and meets the required security standards. In the case of Bluetooth devices, the app should be designed to prevent unauthorized access, while for cars, the app should be designed to protect the user's data and ensure that there are no safety issues with the car's operation.

### Security Knowledge and Expertise

> The OWASP MASVS assumes a certain level of security knowledge and expertise among developers and security professionals using the standard. It's important to have a good understanding of mobile app security concepts, as well as the relevant tools and techniques used for mobile app security testing and assessment. To support this, the OWASP MAS project also provides the [OWASP Mobile Application Security Testing Guide (MASTG)](https://mas.owasp.org/MASTG/), which provides in-depth guidance on mobile app security testing and assessment.

Mobile app development is a rapidly evolving field, with new technologies, programming languages, and frameworks constantly emerging. It's essential for developers and security professionals to stay current with these developments, as well as to have a solid foundation in fundamental security principles.

OWASP SAMM provides a dedicated ["Education & Guidance"](https://owaspsamm.org/model/governance/education-and-guidance/) domain which aims to ensure that all stakeholders involved in the software development lifecycle are aware of the software security risks and are equipped with the knowledge and skills to mitigate these risks. This includes developers, testers, architects, project managers, executives, and other personnel involved in software development and deployment.

## Applicability of the MASVS

By adhering to the MASVS, businesses and developers can ensure that their mobile app are secure and meet industry-standard security requirements, regardless of the development approach used. This is the case for downloadable apps, as the project was traditionally focused on, but the MAS resources and guidelines are also applicable to other areas of the business such as preloaded applications and SDKs.
