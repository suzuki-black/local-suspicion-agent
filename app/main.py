from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import llm
from .schemas import AnalyzeRequest, AnalyzeResponse

LOG_PATH = Path(__file__).resolve().parent.parent / "suspicion.log"
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("suspicion")

app = FastAPI(title="local-suspicion-agent")

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    logger.info("analyze len=%d", len(req.text))
    try:
        result = await llm.analyze(req.text)
    except llm.LLMError as e:
        logger.warning("llm error: %s", e)
        raise HTTPException(status_code=503, detail=str(e))
    logger.info(
        "result trace=%s score=%d label=%s disagree=%s",
        result.trace_id, result.score, result.label, result.disagreement_flag,
    )
    return result
