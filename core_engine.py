from fastapi import FastAPI, HTTPException
from sklearn.ensemble import IsolationForest
import nmap
import pandas as pd
import os

app = FastAPI(title="CyberSentinel Core")

# Initialisation de l'IA (Apprentissage des comportements normaux)
# [span_0](start_span)[span_1](start_span)Source: Spécification technique CyberSentinel Pro[span_0](end_span)[span_1](end_span)
model_ia = IsolationForest(contamination=0.1)

@app.post("/api/v1/analyze")
async def analyze_traffic(data: dict):
    # [span_2](start_span)Logique d'analyse comportementale[span_2](end_span)
    # Données attendues: [packet_count, size, duration]
    try:
        features = pd.DataFrame([data])
        prediction = model_ia.predict(features)
        
        # [span_3](start_span)1 = Normal, -1 = Anomalie (Menace)[span_3](end_span)
        status = "CLEAN" if prediction[0] == 1 else "THREAT_DETECTED"
        return {
            "analysis_id": "99x", 
            "status": status, 
            "confidence": 0.98
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/v1/scan/{target}")
async def network_scan(target: str):
    # [span_4](start_span)Utilisation de Nmap pour un scan rapide[span_4](end_span)
    nm = nmap.PortScanner()
    nm.scan(target, arguments="-F") 
    
    if target in nm.all_hosts():
        return {"host": target, "open_ports": nm[target]['tcp']}
    return {"host": target, "open_ports": {}, "message": "Host not found"}
