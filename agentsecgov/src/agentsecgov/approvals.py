from uuid import uuid4

from .models import PendingReview, Principal, ToolCall


class ApprovalStore:
    def __init__(self) -> None:
        self._reviews: dict[str, PendingReview] = {}

    def create(
        self,
        request_id: str,
        review_id: str,
        principal: Principal,
        tool_call: ToolCall,
        reason: str,
    ) -> PendingReview:
        review = PendingReview(
            review_id=review_id,
            request_id=request_id,
            requester_id=principal.user_id,
            tenant_id=principal.tenant_id,
            tool_call=tool_call,
            policy_reason=reason,
            risk=tool_call.risk.value,
        )

        self._reviews[review.review_id] = review
        return review

    def list_pending(self) -> list[PendingReview]:
        return [review for review in self._reviews.values() if review.status == "pending_review"]

    def get(self, review_id: str) -> PendingReview | None:
        return self._reviews.get(review_id)


APPROVAL_STORE = ApprovalStore()


def get_approval_store() -> ApprovalStore:
    return APPROVAL_STORE
