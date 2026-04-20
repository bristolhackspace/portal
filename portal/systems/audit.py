from datetime import datetime, timezone
from typing import Any

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_sqlalchemy.pagination import Pagination
import sqlalchemy as sa

from portal.models import AuditLog
from portal.models import Member


class Audit:
    def __init__(self, db: SQLAlchemy, app: Flask):
        self.db = db

    def log(
        self,
        category: str,
        event: str,
        member: Member | None = None,
        data: Any | None = None,
        logged_at: datetime | None = None,
    ):
        if logged_at is None:
            logged_at = datetime.now(timezone.utc)
        log_entry = AuditLog(
            logged_at=logged_at,
            category=category,
            event=event,
            member=member,
            data=data,
        )
        self.db.session.add(log_entry)
        self.db.session.commit()

    def get_logs(
        self,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        category: str | None = None,
        event: str | None = None,
        **kwargs
    ) -> Pagination:
        query = sa.select(AuditLog)

        if start_time:
            query = query.where(AuditLog.logged_at >= start_time)
        if end_time:
            query = query.where(AuditLog.logged_at < end_time)
        if category:
            query = query.where(AuditLog.category == category)
        if event:
            query = query.where(AuditLog.event == event)

        query = query.order_by(AuditLog.logged_at)
        return self.db.paginate(query, **kwargs)
