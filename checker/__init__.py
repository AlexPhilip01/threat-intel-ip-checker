"""Threat Intel IP Checker — core package.

Exposes the shared engine used by both the CLI (checker.cli) and the
live dashboard app (dashboard.routes), so there is exactly one
implementation of "how we check an IP" in the whole project.
"""
