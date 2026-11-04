"""One entry point for the whole analysis, so the app, evaluation and tests run identical steps."""
from dataclasses import dataclass

import pandas as pd

from . import clock
from .correlate import build_links, reconstruct
from .detections import run_all
from .validation import ISSUE_COLUMNS, validate


@dataclass
class Analysis:
    events: pd.DataFrame        # as parsed: the 15-field schema, untouched
    view: pd.DataFrame          # analysis copy: corrected times + timestamp_raw / correction / uncertainty
    issues: pd.DataFrame
    detections: list
    links: list
    incidents: list
    clock: list                 # ClockFinding per host
    clock_aware: bool


def analyse(events, clock_aware=True):
    """`clock_aware=False` reproduces the original behaviour (raw times only) for comparison."""
    findings = clock.assess(events)
    view = clock.apply(events, findings if clock_aware else [])
    issues = validate(events)
    extra = clock.issues(findings)
    if extra:
        issues = pd.concat([issues, pd.DataFrame(extra, columns=ISSUE_COLUMNS)], ignore_index=True)
    detections = run_all(view)
    links = build_links(view)
    incidents = reconstruct(view, detections, links)
    return Analysis(events, view, issues, detections, links, incidents, findings, clock_aware)
