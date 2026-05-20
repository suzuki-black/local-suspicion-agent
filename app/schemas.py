from typing import List, Literal
from pydantic import BaseModel, Field

Label = Literal["phishing", "fraud", "manipulation", "prompt_injection", "harmless", "other"]


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000)


class AnalyzeResponse(BaseModel):
    score: int = Field(..., ge=0, le=100)
    label: Label
    reasons: List[str]
