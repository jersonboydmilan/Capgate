"""Hypothesis profiles.

    pytest tests/fuzz                          # ci profile: fast, deterministic-enough for every run
    HYPOTHESIS_PROFILE=deep pytest tests/fuzz  # thousands of examples per property
"""

import os

from hypothesis import HealthCheck, settings

settings.register_profile("ci", max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
settings.register_profile("deep", max_examples=5000, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci"))
