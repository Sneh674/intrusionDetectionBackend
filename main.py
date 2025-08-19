from fastapi import FastAPI
import logging
from scapy.all import sniff
from scapy.layers.inet import IP
import threading

app = FastAPI()
logger = logging.getLogger("uvicorn.error")

# Global variable to store sniffing state
sniffing_active = False

def packet_callback(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        logger.info(f"Packet: {src} -> {dst} (Protocol: {proto})")

def stop_filter(packet):
    return not sniffing_active  # Stop sniffing if sniffing_active becomes False

def start_sniffing():
    global sniffing_active
    sniffing_active = True
    sniff(prn=packet_callback, store=0, stop_filter=stop_filter)
    logger.info("Sniffing ended.")

@app.get("/start_sniffing")
def start_sniffing_endpoint():
    if not sniffing_active:
        thread = threading.Thread(target=start_sniffing, daemon=True)
        thread.start()
        logger.info("Started packet sniffing thread.")
        return {"message": "Packet sniffing started."}
    else:
        return {"message": "Packet sniffing is already running."}

@app.get("/stop_sniffing")
def stop_sniffing():
    global sniffing_active
    sniffing_active = False
    logger.info("Packet sniffing stop requested.")
    return {"message": "Packet sniffing will stop shortly."}

@app.get("/")
def read_root():
    logger.info("Root endpoint was accessed")
    return {"message": "Packet Monitor API Running"}

@app.get("/status")
def get_status():
    return {"status": "Monitoring" if sniffing_active else "Not Monitoring"}
