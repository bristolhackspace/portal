from datetime import date, datetime, timezone
from typing import Any

from flask import Flask
import pytest

from portal.extensions import db
from portal.models import Member


@pytest.fixture()
def member_model(init_db):
    member = Member(
        id=1,
        display_name="Test Member",
        email="example@example.com",
        username="test",
        join_date=date(2026, 3, 31),
        leave_date=date(2026, 4, 1),
        updated=datetime.now(timezone.utc),
    )
    db.session.add(member)
    db.session.commit()
    return member


@pytest.fixture()
def member_model_null_values(init_db):
    member = Member(
        id=2,
        display_name="Test Member2",
        email="example2@example.com",
    )
    db.session.add(member)
    db.session.commit()
    return member


def auth_headers(app: Flask) -> dict[str, str]:
    return {"Authorization": f"Bearer {app.config['API_SECRET']}"}


def test_member_get(client, app, member_model):
    response = client.get(
        f"/api/v1/members/{member_model.id}", headers=auth_headers(app)
    )
    assert response.status_code == 200

    data: dict[str, Any] = response.json
    assert data["display_name"] == member_model.display_name
    assert data["email"] == member_model.email
    assert data["join_date"] == member_model.join_date.isoformat()
    assert data["leave_date"] == member_model.leave_date.isoformat()
    assert data["updated"] == member_model.updated.timestamp()
    assert data["username"] == member_model.username


def test_member_get_null_values(client, app, member_model_null_values):
    response = client.get(
        f"/api/v1/members/{member_model_null_values.id}", headers=auth_headers(app)
    )
    assert response.status_code == 200

    data: dict[str, Any] = response.json
    assert data["display_name"] == member_model_null_values.display_name
    assert data["email"] == member_model_null_values.email
    assert data["join_date"] == None
    assert data["leave_date"] == None
    assert data["updated"] == None
    assert data["username"] == None


def test_member_update(client, app, member_model):
    updated = datetime.now(timezone.utc).replace(microsecond=0)
    new_join_date = date.today()
    new_leave_date = date.today()
    new_display_name = "Alice"
    new_email = "alice@example.com"
    new_username = "alice_likes_ducks"

    response = client.put(
        f"/api/v1/members/{member_model.id}",
        headers=auth_headers(app),
        json={
            "display_name": new_display_name,
            "updated": updated.isoformat(),
            "email": new_email,
            "join_date": new_join_date.isoformat(),
            "leave_date": new_leave_date.isoformat(),
            "username": new_username,
        },
    )
    assert response.status_code == 200

    assert member_model.updated == updated
    assert member_model.join_date == new_join_date
    assert member_model.leave_date == new_leave_date
    assert member_model.display_name == new_display_name
    assert member_model.email == new_email
    assert member_model.username == new_username


def test_member_create(client, app):
    updated = datetime.now(timezone.utc).replace(microsecond=0)
    new_join_date = date.today()
    new_leave_date = date.today()
    new_display_name = "Alice"
    new_email = "alice@example.com"
    new_username = "alice_likes_ducks"

    member_id = 10

    response = client.put(
        f"/api/v1/members/{member_id}",
        headers=auth_headers(app),
        json={
            "display_name": new_display_name,
            "updated": updated.isoformat(),
            "email": new_email,
            "join_date": new_join_date.isoformat(),
            "leave_date": new_leave_date.isoformat(),
            "username": new_username,
        },
    )
    assert response.status_code == 200

    member = db.session.get(Member, member_id)

    assert member is not None

    assert member.updated == updated
    assert member.join_date == new_join_date
    assert member.leave_date == new_leave_date
    assert member.display_name == new_display_name
    assert member.email == new_email
    assert member.username == new_username


def test_member_get_unauthorized(client, member_model):
    headers = {"Authorization": f"Bearer wrong_secret"}
    response = client.get(f"/api/v1/members/{member_model.id}", headers=headers)
    assert response.status_code == 401
