# main.py

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cve_analysis import analyze_cve

app = FastAPI(
    title="CVE Analyst API",
    description="API backend for analyzing CVE IDs and retrieving detailed vulnerability information.",
    version="1.0.0",
)

class CVERequest(BaseModel):
    cve_id: str

@app.post("/analyze")
async def analyze_cve_endpoint(request: CVERequest):
    # Corrected line: Added 'await' to call the async function
    cve_entry, error = await analyze_cve(request.cve_id)
    if error:
        raise HTTPException(status_code=400, detail=error)
    return cve_entry
