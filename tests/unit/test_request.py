import pytest

from capgate import ActionRequest
from capgate.request import MalformedRequest


def test_arguments_are_frozen_at_construction():
    args = {"query": "safe", "nested": {"k": ["a"]}}
    request = ActionRequest("researcher", "web.search", args)
    before = request.arguments_hash
    args["query"] = "malicious"
    args["nested"]["k"].append("b")
    assert request.arguments["query"] == "safe"
    assert request.arguments_hash == before

    view = request.arguments["nested"]
    view["k"].append("c")  # mutating a returned copy changes nothing
    assert request.arguments_copy()["nested"] == {"k": ["a"]}


def test_non_serializable_arguments_rejected():
    with pytest.raises(MalformedRequest):
        ActionRequest("researcher", "web.search", {"obj": object()})
    with pytest.raises(MalformedRequest):
        ActionRequest("researcher", "web.search", {"n": float("nan")})
