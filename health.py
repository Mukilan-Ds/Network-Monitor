"""
NetWatch - Network Health Score
-----------------------------------
Boils down the whole network's current state into a single 0-100
score, so instead of reading a table of numbers you get one figure
that answers "is my network okay right now?" at a glance.

This isn't a standard industry metric -- it's a simple weighted
penalty system, deliberately kept transparent and easy to explain
(useful for a portfolio project: you should be able to justify
every number in it).

Scoring logic (starts at 100, subtracts penalties):
    - Device totally unreachable (0% of pings answered): -15 each
    - Latency above the "critical" threshold, or heavy packet loss: -10 each
    - Latency above the "warning" threshold, or minor packet loss: -4 each
    Score is clamped to the 0-100 range.
"""

from latency import measure_all  # noqa: F401  (kept for type-reference / potential reuse)

LATENCY_WARN_MS = 100
LATENCY_CRIT_MS = 300
LOSS_WARN_PCT = 1
LOSS_CRIT_PCT = 50

UNREACHABLE_PENALTY = 15
CRITICAL_PENALTY = 10
WARNING_PENALTY = 4


def compute_health_score(stats: list[dict]) -> int:
    """
    stats: the list of per-device dicts produced by latency.measure_all()
           (each with avg_ms, loss_pct, etc.)

    Returns an integer 0-100. An empty device list (nothing found on
    the network at all) returns 0, since that's the worst possible
    state for a "network health" check, not a neutral one.
    """
    if not stats:
        return 0

    score = 100

    for s in stats:
        avg_ms = s.get("avg_ms")
        loss_pct = s.get("loss_pct", 0)

        if avg_ms is None:
            score -= UNREACHABLE_PENALTY
            continue  # don't double-penalize an already-unreachable device

        if avg_ms > LATENCY_CRIT_MS or loss_pct >= LOSS_CRIT_PCT:
            score -= CRITICAL_PENALTY
        elif avg_ms > LATENCY_WARN_MS or loss_pct >= LOSS_WARN_PCT:
            score -= WARNING_PENALTY

    return max(0, min(100, score))


def health_label(score: int) -> str:
    """A short human-readable band for the score, for display purposes."""
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 50:
        return "Degraded"
    return "Poor"
