"""Configuration regressions at the public loading boundary."""

import pytest

from sandbox_escape_finder import ConfigError, load_config


@pytest.mark.parametrize("timeout", [float("nan"), float("inf"), -float("inf")])
def test_nonfinite_timeout_is_rejected_when_loading_config(timeout):
    with pytest.raises(ConfigError, match="subprocess_timeout_s"):
        load_config({"subprocess_timeout_s": timeout})


def test_timeout_too_large_to_represent_is_a_configuration_error():
    with pytest.raises(ConfigError, match="subprocess_timeout_s"):
        load_config({"subprocess_timeout_s": 10 ** 1000})
