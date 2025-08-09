from fastapi import FastAPI
import logging

app = FastAPI()
logger = logging.getLogger("uvicorn.error")

@app.get("/")
def read_root():
    print("Root endpoint hit!")  # quick debug print
    logger.info("Root endpoint was accessed")  # proper logging
    return {"message": "Packet Monitor API Running"}


@app.get("/status")
def get_status():
    return {"status": "Monitoring"}
