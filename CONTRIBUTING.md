Contributing
============
We gratefully accept bug reports and contributions from the community. All PRs are reviewed by the project team / community, and may need some modifications to
be accepted.

Quick Checklist for PR contributors
-----------------------------------
More details on all of these points may be found in the sections below.

- [Sign-off](#license-and-copyright): all commits must be signed off.
- [Tests](#tests): please ensure the PR includes adequate tests.
- [Changelog](#documentation): if needed, please provide a changelog entry.

Coding Standards
----------------
- Contributions should include tests, as mentioned in the [Tests](#tests) and [Continuous Integration](#continuous-integration-tests) sections. Please check that your contribution passes basic tests before submission, and check the CI results after making a pull request.
- The code should be written in a clean and readable style, and must follow [our coding standards](https://mbed-tls.readthedocs.io/en/latest/kb/development/mbedtls-coding-standards/).
- The code should be written in a portable generic way, that will benefit the whole community, and not only your own needs.
- The code should be secure, and will be reviewed from a security point of view as well.

Making a Contribution
---------------------
1. [Check for open issues](https://github.com/Mbed-TLS/TF-PSA-Crypto/issues) or [start a discussion](https://lists.trustedfirmware.org/mailman3/lists/mbed-tls.lists.trustedfirmware.org) around a feature idea or a bug.
1. Fork the [TF-PSA-Crypto repository on GitHub](https://github.com/Mbed-TLS/TF-PSA-Crypto) to start making your changes. As a general rule, you should use the ["development" branch](https://github.com/Mbed-TLS/TF-PSA-Crypto/tree/development) as a basis.
1. Write a test which shows that the bug was fixed or that the feature works as expected.
1. Send a pull request (PR) and work with us until it gets merged and published. Contributions may need some modifications, so a few rounds of review and fixing may be necessary. See our [review process guidelines](https://mbed-tls.readthedocs.io/en/latest/reviews/review-for-contributors/).
1. For quick merging, the contribution should be short, and concentrated on a single feature or topic. The larger the contribution is, the longer it would take to review it and merge it.

Tests
-----
As mentioned, tests that show the correctness of the feature or bug fix should be added to the pull request, if no such tests exist.

TF-PSA-Crypto includes a comprehensive set of test suites in the `tests/` directory that are dynamically generated to produce the actual test source files (e.g. `test_suite_psa_crypto.c`). These files are generated from a `function file` (e.g. `suites/test_suite_psa_crypto.function`) and a `data file` (e.g. `suites/test_suite_psa_crypto.data`). The function file contains the test functions. The data file contains the test cases, specified as parameters that will be passed to the test function.

[A Knowledge Base article describing how to add additional tests is available on the Mbed TLS website](https://mbed-tls.readthedocs.io/en/latest/kb/development/test_suites/).

A test script `tests/scripts/basic-build-test.sh` is available to show test coverage of the library. New code contributions should provide a similar level of code coverage to that which already exists for the library.

Sample applications, if needed, should be modified as well.

Continuous Integration Tests
----------------------------
Once a PR has been made, the Continuous Integration (CI) tests are triggered and run. You should follow the result of the CI tests, and fix failures.

It is advised to enable the [githooks scripts](https://github.com/Mbed-TLS/mbedtls/tree/development/tests/git-scripts) prior to pushing your changes, for catching some of the issues as early as possible.

Documentation
-------------
TF-PSA-Crypto is well documented, but if you think documentation is needed, speak out!

1. All interfaces should be documented through Doxygen. New APIs should introduce Doxygen documentation.
1. Complex parts in the code should include comments.
1. If needed, a Readme file is advised.
1. If a [Knowledge Base (KB)](https://mbed-tls.readthedocs.io/en/latest/kb/) article should be added, write this as a comment in the PR description.
1. A [ChangeLog](https://github.com/Mbed-TLS/TF-PSA-Crypto/blob/development/ChangeLog.d/00README.md) entry should be added for this contribution.

License and Copyright
---------------------

Unless specifically indicated otherwise in a file, TF-PSA-Crypto files are provided under a dual [Apache-2.0](https://spdx.org/licenses/Apache-2.0.html) OR [GPL-2.0-or-later](https://spdx.org/licenses/GPL-2.0-or-later.html) license. See the [LICENSE](LICENSE) file for the full text of these licenses. This means that users may choose which of these licenses they take the code under.

Contributors must accept that their contributions are made under both the Apache-2.0 AND [GPL-2.0-or-later](https://spdx.org/licenses/GPL-2.0-or-later.html) licenses.

All new files should include the standard SPDX license identifier where possible, i.e. "SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later".

The copyright on contributions is retained by the original authors of the code. Where possible for new files, this should be noted in a comment at the top of the file in the form: "Copyright The Mbed TLS Contributors".

When contributing code to us, the committer and all authors are required to make the submission under the terms of the [Developer Certificate of Origin](dco.txt), confirming that the code submitted can (legally) become part of the project, and is submitted under both the Apache-2.0 AND GPL-2.0-or-later licenses.

This is done by including the standard Git `Signed-off-by:` line in every commit message. If more than one person contributed to the commit, they should also add their own `Signed-off-by:` line.
