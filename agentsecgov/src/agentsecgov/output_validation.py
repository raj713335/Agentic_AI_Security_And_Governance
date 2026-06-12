from pydantic import BaseModel, Field


class CustomerEmailDraft(BaseModel):
    customer_id: str
    subject: str = Field(min_length=3, max_length=120)
    body: str = Field(min_length=10, max_length=1000)


class OutputValidationError(Exception):
    pass


def validate_customer_email_output(data: dict) -> dict:
    draft = CustomerEmailDraft(**data)

    risky_terms = [
        "send me your password",
        "share your password",
        "api key",
        "secret key",
    ]

    body = draft.body.lower()

    if any(term in body for term in risky_terms):
        raise OutputValidationError("Email draft requests sensitive credentials")

    return draft.model_dump()