from datetime import datetime, timedelta, timezone

import pytest

import sqlalchemy as sa

from portal.extensions import db
from portal.models import AuditLog, Member


@pytest.fixture()
def member_model(init_db):
    member = Member(
        id=1,
        display_name="Test Member",
        email="example@example.com",
        username="test_username",
    )
    db.session.add(member)
    db.session.commit()
    return member


def create_and_check_log(audit, category, event, member, data):
    logged_at = datetime.now(timezone.utc).replace(microsecond=0)
    audit.log(category, event, member, data, logged_at)

    query = sa.select(AuditLog)
    log = db.session.execute(query).scalar_one()
    assert log.category == category
    assert log.event == event
    assert log.member == member
    assert log.data == data
    assert log.logged_at == logged_at


def test_create_audit_log_no_member(audit):
    create_and_check_log(audit, "my_category", "my_event", None, {"test": 67})


def test_create_audit_log_with_member(audit, member_model):
    create_and_check_log(
        audit, "my_category", "my_event", member_model, {"my_data": 67}
    )


def test_audit_get_all_logs(audit):
    category = "my_category"
    event = "my_event"
    member = None

    for i in range(10):
        data = {"iteration": i}
        audit.log(category, event, member, data)

    logs = audit.get_logs()
    for i, log in enumerate(logs):
        assert log.category == category
        assert log.event == event
        assert log.member == member
        assert log.data == {"iteration": i}


def test_audit_get_logs_by_category(audit):
    for i in range(5):
        audit.log("cat1", "event", None, None)
    for i in range(7):
        audit.log("cat2", "event", None, None)

    logs = audit.get_logs(category="cat1")
    assert len(logs.items) == 5


def test_audit_get_logs_by_event(audit):
    for i in range(5):
        audit.log("category", "event1", None, None)
    for i in range(7):
        audit.log("category", "event2", None, None)

    logs = audit.get_logs(event="event1")
    assert len(logs.items) == 5


def test_audit_get_logs_after_time(audit):
    logged_at = datetime.now(timezone.utc).replace(microsecond=0)

    for i in range(5):
        audit.log("category", "event", None, None, logged_at)
    for i in range(7):
        audit.log("category", "event", None, None, logged_at + timedelta(seconds=10))

    logs = audit.get_logs(start_time=logged_at + timedelta(seconds=5))
    assert len(logs.items) == 7
    for log in logs:
        assert log.logged_at == logged_at + timedelta(seconds=10)


def test_audit_get_logs_before_time(audit):
    logged_at = datetime.now(timezone.utc).replace(microsecond=0)

    for i in range(5):
        audit.log("category", "event", None, None, logged_at)
    for i in range(7):
        audit.log("category", "event", None, None, logged_at + timedelta(seconds=10))

    logs = audit.get_logs(end_time=logged_at + timedelta(seconds=5))
    assert len(logs.items) == 5
    for log in logs:
        assert log.logged_at == logged_at
