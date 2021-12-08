# Contributing to python-pysecp256k1

A big welcome and thank you for considering contributing to python-pysecp256k1 open source project!

## Getting Started

Contributions are made to this repo via Issues and Pull Requests (PRs). A few general guidelines that cover both:

- To report security vulnerabilities in `secp256k1` go [here](https://github.com/bitcoin-core/secp256k1/blob/master/SECURITY.md).
- To report security vulnerabilities in `pysecp256k1` send email to virgovica@gmail.com. Following key 15497EE1ED031133DCC36FB3FE33B7BA26184899 may be used to communicate sensitive information. 
- Search for existing Issues and PRs before creating your own.

### Issues

Issues should be used to report problems with the library, request a new feature, or to discuss potential changes before a PR is created.
If you find an Issue that addresses the problem you're having, please add your own reproduction information to the existing issue rather than creating a new one. 
Adding a reaction can also help be indicating that a particular problem is affecting more than just the reporter.

### Pull Requests

PRs to this library is always welcome and can be a quick way to get your fix or improvement slated for the next release. In general, PRs should:

- Only fix/add the functionality in question **OR** address wide-spread whitespace/style issues, not both.
- Add unit tests for fixed or changed functionality (if a test suite already exists).
- Include documentation in the repo.

For changes that address core functionality or would require breaking changes (e.g. a major release), it's best to open an Issue to discuss your proposal first. This is not required but can save time creating and reviewing changes.

1. Fork the repository to your own Github account
2. Clone the project to your machine
3. Create a branch locally with a succinct but descriptive name
4. Commit changes to the branch
5. Following any formatting and testing guidelines specific to this repo
6. Push changes to your fork
7. Open a PR in this repository and follow the PR template so that we can efficiently review the changes.

### Formatting and testing guidelines
Testing is described in README.md. All tests have to pass. For formatting purposes use [black](https://github.com/psf/black):
```shell
pip install black
cd python-secp256k1
black .
```

## Getting Help
email: virgovica@gmail.com

twitter: @AVirgovic
