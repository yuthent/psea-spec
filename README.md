# Post-Session Execution Assurance (PSEA)

PSEA is an architectural security model that requires cryptographic proof of authority at the moment a sensitive action is executed.

## Problem

Sessions inherit trust from authentication.
Authority is temporal and context-dependent.

## Core Principles

- Execution-time verification
- Human presence assurance
- Device-bound trust
- Cryptographic proof
- Connectivity independence

## Non-Goals

- Replacing authentication
- Hardening sessions
- Acting as MFA or Zero Trust

## Reference

[https://yuthent.com/psea](https://yuthent.com/psea)
