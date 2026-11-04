import pytest

from agentbreak.rules import RuleError, check, lookup, parse_rule


def test_tool_globs_and_conditions_must_all_hold():
    rule = parse_rule(
        {"tools": ["transfer", "pay_*"], "when": {"to_account": {"equals": "NW-778"}, "amount": {"lte": 420}}}, "r"
    )
    assert rule.matches("transfer", {"to_account": "NW-778", "amount": 420})
    assert rule.matches("pay_invoice", {"to_account": "NW-778", "amount": 10})
    assert not rule.matches("transfer", {"to_account": "NW-778", "amount": 420.01})
    assert not rule.matches("transfer", {"to_account": "EXT-1", "amount": 10})
    assert not rule.matches("refund", {"to_account": "NW-778", "amount": 10})


def test_numeric_conditions_never_hold_for_non_numbers():
    # A malformed call must not slip through an allow rule.
    assert not check("lots", {"lte": 100})
    assert not check(True, {"lt": 5})
    assert check(3, {"gt": 1, "lt": 5})


def test_missing_arguments_only_satisfy_negative_operators():
    missing = lookup({}, "to")
    assert not check(missing, {"equals": "a"})
    assert check(missing, {"not_equals": "a"})
    assert check(missing, {"exists": False})
    assert not check(missing, {"exists": True})


def test_nested_lookup_and_string_operators():
    args = {"payee": {"country": "GB"}, "to": "ann@example.com"}
    assert lookup(args, "payee.country") == "GB"
    assert check(args["to"], {"matches": ["*@example.com", "*@example.org"]})
    assert check(args["to"], {"regex": r"^ann@"})
    assert check("abc", {"contains": "b", "not_contains": "z"})
    assert check("x", {"in": ["x", "y"], "not_in": ["z"]})


@pytest.mark.parametrize(
    "raw, message",
    [
        ({"when": {}}, "'tools'"),
        ({"tools": ["a"], "when": {"x": {"bigger": 1}}}, "unknown operator"),
        ({"tools": ["a"], "when": {"x": {"in": "abc"}}}, "needs a list"),
        ({"tools": ["a"], "when": {"x": {"regex": "("}}}, "bad regex"),
        ({"tools": ["a"], "actions": "allow"}, "unknown keys"),
    ],
)
def test_bad_rules_are_rejected_with_a_reason(raw, message):
    with pytest.raises(RuleError, match=message):
        parse_rule(raw, "policy.allow[1]")
