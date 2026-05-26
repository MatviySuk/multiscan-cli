import pytest

from deduplicator import location_match


@pytest.mark.parametrize(
    "first_finding, second_finding, expected",
    [
        ({"path": "app.py", "line": 10}, {"path": "app.py", "line": 14}, True),
        ({"path": "app.py", "line": 10}, {"path": "app.py", "line": 15}, True),
        ({"path": "app.py", "line": 10}, {"path": "app.py", "line": 20}, False),
        ({"path": "utils.py", "line": 10}, {"path": "db.py", "line": 12}, False),
    ],
)
def test_location_match(first_finding, second_finding, expected):

    result = location_match(first_finding, second_finding)

    assert result == expected
