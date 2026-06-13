from __future__ import annotations

from threading import Lock

from .models import PendingReview, ReviewStatus


class ApprovalStore:
    """Thread-safe in-memory approval queue for teaching.

    Replace with a durable database in production.
    """

    def __init__(self) -> None:
        self._items: dict[str, PendingReview] = {}
        self._lock = Lock()

    def create(self, review: PendingReview) -> PendingReview:
        with self._lock:
            self._items[review.review_id] = review
        return review

    def get(self, review_id: str) -> PendingReview | None:
        with self._lock:
            return self._items.get(review_id)

    def list_pending(self) -> list[PendingReview]:
        with self._lock:
            return [item for item in self._items.values() if item.status == ReviewStatus.pending]

    def save(self, review: PendingReview) -> PendingReview:
        with self._lock:
            self._items[review.review_id] = review
        return review

    def clear(self) -> None:
        with self._lock:
            self._items.clear()