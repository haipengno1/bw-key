# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!--
Note: In this file, do not use the hard wrap in the middle of a sentence for compatibility with GitHub comment style markdown rendering.
-->

## [Unreleased]

## [1.0.0] - 2025-01-05

### Changed
- Migrated from structopt to clap v4.4 for command-line argument parsing
- Added password argument support to allow non-interactive password input
- Simplified error types and improved error messages
- Improved error handling to provide more descriptive messages
- Enhanced API error reporting with detailed error sources
- Refactored main function to better handle and display errors
- Changed host option from `-h` to `-H` to avoid conflict with help option
- Removed redundant error variants and unified error handling

### Fixed
- Suppressed dead code warnings in unused functions and constants

## [0.1.2] - 2024-04-20

fixed:
New version compatibility

## [0.1.1] - 2022-12-07

check the SSH_AUTH_SOCK can be connected first

## [0.1.0] - 2022-11-29

add Mac ARM support
add Linux ARM support

## [0.0.2] - 2022-02-17

add two factor auth support

## [0.0.1] - 2022-01-23

Initial release