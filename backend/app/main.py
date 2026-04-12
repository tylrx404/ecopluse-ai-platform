"""
EcoPulse — FastAPI AI Backend
==============================
Entry point: uvicorn app.main:app --reload

Endpoints (ML / AI):
  GET  /predict             — 7-day temperature forecast (ONNX)
  POST /predict/aqi         — AQI forecast 24 / 48 / 72 h
  POST /predict/aqi-hourly  — Hourly AQI for next 72 h
  POST /predict/temp-hourly — Hourly temperature for next 72 h
  POST /predict/rain-hourly — Hourly rainfall probability for next 72 h
  POST /predict/eco-score   — AI eco-impact score from daily habits
  POST /recommendations     — Personalised environmental recommendations
  POST /chat                — AI assistant (Google Gemini)

Auth / Data endpoints are registered via routers.
"""

import logging
import os
import json
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import joblib

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dotenv import load_dotenv

# ── Load env vars ─────────────────────────────────────────────────────────────
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
from app.core.config import GEMINI_API_KEY, ML_DIR, BASE_DIR

# ── Optional dependencies ─────────────────────────────────────────────────────
try:
    import google.generativeai as genai
    _GENAI_AVAILABLE = True
except ImportError:
    genai = None  # type: ignore
    _GENAI_AVAILABLE = False
    logger.warning("⚠️  google-generativeai not installed — /chat will use fallback")

try:
    import onnxruntime as ort
    _ORT_AVAILABLE = True
except ImportError:
    _ORT_AVAILABLE = False
    logger.warning("⚠️  onnxruntime not installed — /predict will use rule-based fallback")

# ── Load ONNX weather model ───────────────────────────────────────────────────
onnx_session    = None
onnx_input_name = None

try:
    _onnx_path = ML_DIR / "weather_model.ONNX"
    if _ORT_AVAILABLE and _onnx_path.exists():
        onnx_session    = ort.InferenceSession(str(_onnx_path))
        onnx_input_name = onnx_session.get_inputs()[0].name
        logger.info("✅  ONNX weather model loaded")
    else:
        logger.warning("⚠️  ONNX model not found or onnxruntime unavailable — using fallback")
except Exception as exc:
    logger.warning("⚠️  ONNX model load failed: %s", exc)

# ── Load sklearn / joblib ML models ──────────────────────────────────────────
def _load_model(name: str):
    path = ML_DIR / f"{name}.pkl"
    if path.exists():
        try:
            m = joblib.load(path)
            logger.info("✅  %s model loaded", name)
            return m
        except Exception as exc:
            logger.error("❌  Error loading %s model: %s", name, exc)
    else:
        logger.warning("⚠️  %s model not found — using rule-based fallback", name)
    return None

aqi_model       = _load_model("aqi_model")
eco_score_model = _load_model("eco_score_model")
temp_model      = _load_model("temp_model")
rain_model      = _load_model("rain_model")

# ── Gemini ────────────────────────────────────────────────────────────────────
gemini_model = None
_placeholder = "placeholder_gemini_key_replace_with_real_key"

if not GEMINI_API_KEY or GEMINI_API_KEY == _placeholder:
    logger.warning("⚠️  Gemini API key missing — /chat will use rule-based fallback")
elif not _GENAI_AVAILABLE:
    logger.warning("⚠️  google-generativeai not installed — /chat will use fallback")
else:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        gemini_model = genai.GenerativeModel(
            model_name="gemini-1.5-flash",
            system_instruction=(
                "You are EcoPulse AI — an expert environmental intelligence assistant.\n\n"
                "Your expertise covers:\n"
                "- Air quality: AQI, PM2.5, PM10, NO2, SO2, O3, CO — Indian CPCB standards\n"
                "  (0-50 Good, 51-100 Satisfactory, 101-200 Moderate, 201-300 Poor, 301-400 Very Poor, 401-500 Severe)\n"
                "- Weather: temperature, humidity, wind speed, UV index, rainfall\n"
                "- Pollution health effects and precautions\n"
                "- Carbon footprint reduction: transport, diet, energy, water, waste\n"
                "- Environmental events: World Environment Day, Earth Day, Clean Air campaigns\n"
                "- Indian environmental context: CPCB, Swachh Bharat, PMUY, FAME-II EV scheme\n\n"
                "When live context data is provided (city, AQI, temperature, etc.), USE it for specific answers.\n"
                "Response style: direct, specific, 2-5 sentences, max 2 emojis."
            ),
        )
        logger.info("✅  Gemini AI initialized")
    except Exception as exc:
        logger.error("❌  Gemini init failed: %s — /chat will use fallback", exc)

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="EcoPulse AI API",
    description="AI-powered environmental intelligence backend for EcoPulse",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve uploaded images as static files
_uploads_dir = BASE_DIR / "uploads"
_uploads_dir.mkdir(exist_ok=True)
app.mount("/uploads", StaticFiles(directory=str(_uploads_dir)), name="uploads")

# ── Register routers ──────────────────────────────────────────────────────────
try:
    from backend.app.db import engine
    from backend.app.models import Base
    from backend.app.routers import auth, data, civic

    app.include_router(auth.router)
    app.include_router(data.router)
    app.include_router(civic.router)
    logger.info("✅  Routers registered")
except Exception as exc:
    logger.error("❌  Router initialization failed: %s", exc)
    engine = None  # type: ignore
    Base   = None  # type: ignore


@app.on_event("startup")
def startup():
    """Create all DB tables on startup (idempotent)."""
    if engine is not None and Base is not None:
        try:
            Base.metadata.create_all(bind=engine)
            logger.info("✅  Database tables created / verified")
        except Exception as exc:
            logger.error("❌  DB table creation failed: %s", exc)
    else:
        logger.warning("⚠️  Skipping DB table creation — engine not available")


# ─────────────────────────────────────────────────────────────────────────────
# REQUEST / RESPONSE MODELS
# ─────────────────────────────────────────────────────────────────────────────

class AQIRequest(BaseModel):
    temperature: float
    humidity:    float
    wind_speed:  float
    pm25:        float
    pm10:        float
    co:          float
    no2:         float
    so2:         float
    o3:          float


class AQIForecastPoint(BaseModel):
    hours:    int
    aqi:      int
    category: str
    color:    str


class AQIPredictionResponse(BaseModel):
    forecast:         List[AQIForecastPoint]
    current_aqi:      int
    current_category: str


class EcoScoreRequest(BaseModel):
    ac_fan_hours:     float
    water_usage:      float
    transport_mode:   str   # "walk" | "cycle" | "public" | "private"
    outdoor_exposure: str   # "low" | "medium" | "high"
    waste_segregation: bool


class EcoScoreResponse(BaseModel):
    score:     float
    category:  str
    insights:  List[str]
    breakdown: Dict


class RecommendationRequest(BaseModel):
    aqi:              float
    temperature:      float
    humidity:         float
    wind_speed:       float
    condition:        str
    ac_fan_hours:     Optional[float] = None
    water_usage:      Optional[float] = None
    transport_mode:   Optional[str]   = None
    waste_segregation: Optional[bool] = None


class Recommendation(BaseModel):
    icon:        str
    title:       str
    description: str
    priority:    str  # "high" | "medium" | "low"
    category:    str  # "air" | "energy" | "transport" | "water" | "waste"


class RecommendationResponse(BaseModel):
    recommendations: List[Recommendation]


class ChatMessage(BaseModel):
    role:    str   # "user" | "assistant"
    content: str


class ChatRequest(BaseModel):
    message: str
    history: Optional[List[ChatMessage]] = []
    context: Optional[Dict] = None


class ChatResponse(BaseModel):
    response: str


class HourlyPredictionRequest(BaseModel):
    temperature: float
    humidity:    float
    wind_speed:  float
    pressure:    float = 1013.0
    pm25:        float
    pm10:        float
    co:          float
    no2:         float
    so2:         float
    o3:          float


class HourlyPoint(BaseModel):
    hour:        int
    aqi:         Optional[float] = None
    temperature: Optional[float] = None
    rainfall:    Optional[float] = None


class WeeklyForecastResponse(BaseModel):
    days:        List[str]
    temperature: List[float]


# ─────────────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

TRANSPORT_MAP = {"walk": 0, "cycle": 1, "public": 2, "private": 3}
OUTDOOR_MAP   = {"low": 0, "medium": 1, "high": 2}


def aqi_to_category(aqi: int) -> Tuple[str, str]:
    if aqi <= 50:  return ("Good",        "#22c55e")
    if aqi <= 100: return ("Satisfactory", "#84cc16")
    if aqi <= 200: return ("Moderate",     "#f59e0b")
    if aqi <= 300: return ("Poor",         "#f97316")
    if aqi <= 400: return ("Very Poor",    "#ef4444")
    return ("Severe", "#7c3aed")


def eco_score_to_category(score: float) -> str:
    if score >= 75: return "Eco-Friendly"
    if score >= 50: return "Moderate"
    return "High Impact"


def rule_based_aqi_forecast(req: AQIRequest, hours_ahead: int) -> int:
    def pm25_to_aqi(pm: float) -> int:
        if pm <= 30:  return int(pm * 50 / 30)
        if pm <= 60:  return int(51 + (pm - 31) * 49 / 29)
        if pm <= 90:  return int(101 + (pm - 61) * 99 / 29)
        if pm <= 120: return int(201 + (pm - 91) * 99 / 29)
        if pm <= 250: return int(301 + (pm - 121) * 99 / 129)
        return int(401 + (pm - 251) * 99 / 249)

    current     = pm25_to_aqi(req.pm25)
    wind_effect = -req.wind_speed * 0.3 * (hours_ahead / 24)
    noise       = np.random.normal(0, 5)
    return max(0, min(500, int(current + wind_effect + noise)))


def rule_based_eco_score(req: EcoScoreRequest) -> float:
    score = 55.0
    score += max(-15, min(10, (135 - req.water_usage) / 10 * 2))
    score += max(-20, min(18, (6 - req.ac_fan_hours) * 3))
    score += {"walk": 12, "cycle": 10, "public": 6, "private": -5}.get(req.transport_mode, 0)
    score += 5 if req.waste_segregation else -5
    score += {"high": 5, "medium": 2, "low": 0}.get(req.outdoor_exposure, 0)
    return round(max(0, min(100, score)), 1)


def _base_features(req: HourlyPredictionRequest) -> np.ndarray:
    return np.array([
        req.temperature, req.humidity, req.wind_speed, req.pressure,
        req.pm25, req.pm10, req.co, req.no2, req.so2, req.o3,
    ])


def _onnx_predict_temp(humidity: float, wind_speed: float, temp_lag1: float) -> float:
    arr    = np.array([[humidity, wind_speed, temp_lag1]], dtype=np.float32)
    output = onnx_session.run(None, {onnx_input_name: arr})
    return float(output[0][0])


def _rule_based_predict_temp(humidity: float, wind_speed: float, temp_lag1: float, day: int) -> float:
    return round(
        temp_lag1
        + (-wind_speed * 0.05)
        + (-(humidity - 60) * 0.05)
        + ((28.0 - temp_lag1) * 0.08)
        + float(np.sin(day * 1.1) * 0.8),
        2,
    )


# ─────────────────────────────────────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "message":       "EcoPulse AI API is running 🌱",
        "models_loaded": aqi_model is not None,
        "gemini_active": gemini_model is not None,
        "docs":          "/docs",
    }


@app.post("/predict/aqi", response_model=AQIPredictionResponse)
def predict_aqi(req: AQIRequest):
    features = [req.temperature, req.humidity, req.wind_speed,
                req.pm25, req.pm10, req.co, req.no2, req.so2, req.o3]
    X        = np.array([features])
    forecast = []
    for hours in [24, 48, 72]:
        if aqi_model:
            jitter  = np.array([[0, 0, hours * 0.1, -hours * 0.05, -hours * 0.05, 0, 0, 0, 0]])
            aqi_val = int(np.clip(aqi_model.predict(X + jitter)[0], 0, 500))
        else:
            aqi_val = rule_based_aqi_forecast(req, hours)
        category, color = aqi_to_category(aqi_val)
        forecast.append(AQIForecastPoint(hours=hours, aqi=aqi_val, category=category, color=color))

    current_cat, _ = aqi_to_category(int(req.pm25))
    return AQIPredictionResponse(
        forecast=forecast,
        current_aqi=int(rule_based_aqi_forecast(req, 0)),
        current_category=current_cat,
    )


@app.post("/predict/aqi-hourly", response_model=List[HourlyPoint])
def predict_aqi_hourly(req: HourlyPredictionRequest):
    result = []
    base   = _base_features(req)
    for h in range(73):
        aqi_req = AQIRequest(
            temperature=req.temperature, humidity=req.humidity, wind_speed=req.wind_speed,
            pm25=req.pm25, pm10=req.pm10, co=req.co, no2=req.no2, so2=req.so2, o3=req.o3,
        )
        if h == 0 or not aqi_model:
            aqi = rule_based_aqi_forecast(aqi_req, h)
        else:
            jitter = np.array([[0, 0, h * 0.1, 0, -h * 0.05, -h * 0.05, 0, 0, 0, 0]])
            aqi    = int(np.clip(aqi_model.predict(base.reshape(1, -1) + jitter)[0], 0, 500))
        result.append(HourlyPoint(hour=h, aqi=float(aqi)))
    return result


@app.post("/predict/temp-hourly", response_model=List[HourlyPoint])
def predict_temp_hourly(req: HourlyPredictionRequest):
    result       = []
    base         = _base_features(req)
    current_hour = datetime.datetime.now().hour
    for h in range(73):
        if temp_model:
            feats = np.append(base, h).reshape(1, -1)
            temp  = float(np.clip(temp_model.predict(feats)[0], 5, 50))
        else:
            future_hour = (current_hour + h) % 24
            diurnal     = -5 * np.cos((future_hour - 14) * 2 * np.pi / 24)
            temp        = float(np.clip(
                req.temperature + diurnal - 0.3 * (h // 24) - req.wind_speed * 0.05,
                5, 50,
            ))
        result.append(HourlyPoint(hour=h, temperature=round(temp, 1)))
    return result


@app.post("/predict/rain-hourly", response_model=List[HourlyPoint])
def predict_rain_hourly(req: HourlyPredictionRequest):
    result       = []
    base         = _base_features(req)
    current_hour = datetime.datetime.now().hour
    for h in range(73):
        if rain_model:
            feats = np.append(base, h).reshape(1, -1)
            prob  = float(np.clip(rain_model.predict(feats)[0], 0, 100))
        else:
            future_hour     = (current_hour + h) % 24
            base_prob       = max(0, (req.humidity - 40) * 1.2 + (1013 - req.pressure) * 0.8)
            afternoon_boost = 20 if 14 <= future_hour <= 18 else 0
            prob            = float(np.clip(
                base_prob + afternoon_boost - req.wind_speed * 0.3 + np.sin(h * 0.7) * 8,
                0, 100,
            ))
        result.append(HourlyPoint(hour=h, rainfall=round(prob, 1)))
    return result


@app.post("/predict/eco-score", response_model=EcoScoreResponse)
def predict_eco_score(req: EcoScoreRequest):
    transport_enc = TRANSPORT_MAP.get(req.transport_mode, 3)
    outdoor_enc   = OUTDOOR_MAP.get(req.outdoor_exposure, 0)

    if eco_score_model:
        X     = np.array([[req.ac_fan_hours, req.water_usage, transport_enc,
                           outdoor_enc, int(req.waste_segregation)]])
        score = float(np.clip(eco_score_model.predict(X)[0], 0, 100))
    else:
        score = rule_based_eco_score(req)

    score = round(score, 1)
    cat   = eco_score_to_category(score)

    insights = []
    if req.water_usage > 135:
        insights.append(f"You used {req.water_usage - 135:.0f}L more than the national avg. Try shorter showers. 🚿")
    else:
        insights.append(f"Great job! You saved {135 - req.water_usage:.0f}L of water today. 💧")
    if req.ac_fan_hours > 6:
        insights.append(f"AC/Fan ran {req.ac_fan_hours:.0f}h — try reducing by 1-2 hours to save energy. ⚡")
    else:
        insights.append(f"Energy usage looks good! Only {req.ac_fan_hours:.0f}h of AC/Fan. ✅")
    if req.transport_mode == "private":
        insights.append("Switching to public transport twice a week cuts your carbon footprint by ~30%. 🚌")
    elif req.transport_mode in ("walk", "cycle"):
        insights.append("Walking/cycling — zero emissions and great for your health! 🚶")
    if not req.waste_segregation:
        insights.append("Segregating wet and dry waste improves recycling rates dramatically. 🗑️")

    breakdown = {
        "water_score":     round(max(0, min(20, 10 + (135 - req.water_usage) / 10 * 1.5)), 1),
        "energy_score":    round(max(0, min(25, 12 + (6 - req.ac_fan_hours) * 2.5)), 1),
        "transport_score": {"walk": 25, "cycle": 22, "public": 18, "private": 5}[req.transport_mode],
        "waste_score":     15 if req.waste_segregation else 5,
        "outdoor_score":   {"high": 10, "medium": 6, "low": 2}[req.outdoor_exposure],
    }
    return EcoScoreResponse(score=score, category=cat, insights=insights, breakdown=breakdown)


@app.post("/recommendations", response_model=RecommendationResponse)
def get_recommendations(req: RecommendationRequest):
    recs: List[Recommendation] = []

    if req.aqi > 300:
        recs.append(Recommendation(icon="😷", title="Wear N95 Mask Outdoors",
            description=f"AQI is {req.aqi:.0f} (Severe). An N95 mask is essential — limit all outdoor time.",
            priority="high", category="air"))
    elif req.aqi > 200:
        recs.append(Recommendation(icon="🏠", title="Stay Indoors Today",
            description=f"AQI is {req.aqi:.0f} (Very Poor). Avoid outdoor exercise and keep windows closed.",
            priority="high", category="air"))
    elif req.aqi > 100:
        recs.append(Recommendation(icon="⏰", title="Exercise in Early Morning",
            description=f"AQI is {req.aqi:.0f} (Moderate). Outdoor exercise is safer before 7 AM.",
            priority="medium", category="air"))
    else:
        recs.append(Recommendation(icon="🌿", title="Great Day for Outdoor Activity",
            description=f"AQI is {req.aqi:.0f} (Good). Perfect conditions for outdoor exercise.",
            priority="low", category="air"))

    if req.temperature > 38:
        recs.append(Recommendation(icon="💧", title="Stay Hydrated",
            description=f"At {req.temperature:.0f}°C, drink 3-4L of water. Avoid peak heat (12PM-4PM).",
            priority="high", category="energy"))
    elif req.temperature > 32:
        recs.append(Recommendation(icon="🌬️", title="Optimize AC Usage",
            description="Set AC to 24-26°C — saves up to 20% energy with minimal comfort loss.",
            priority="medium", category="energy"))

    if req.wind_speed > 20:
        recs.append(Recommendation(icon="🪟", title="Open Windows for Natural Ventilation",
            description=f"Wind speed is {req.wind_speed:.0f} km/h — natural ventilation is excellent right now.",
            priority="low", category="air"))

    if req.transport_mode == "private":
        recs.append(Recommendation(icon="🚌", title="Try Public Transport",
            description="Switching to public transport today reduces your CO₂ emissions by up to 70%.",
            priority="medium", category="transport"))
    elif req.transport_mode is None:
        recs.append(Recommendation(icon="🚲", title="Cycle or Walk Short Distances",
            description="For trips under 5km, cycling or walking produces zero emissions.",
            priority="low", category="transport"))

    if req.water_usage is not None and req.water_usage > 150:
        recs.append(Recommendation(icon="🚿", title="Reduce Water Usage",
            description=f"You used {req.water_usage:.0f}L (India avg: 135L). Fix dripping taps and take shorter showers.",
            priority="medium", category="water"))

    if req.waste_segregation is False:
        recs.append(Recommendation(icon="🗑️", title="Start Waste Segregation",
            description="Separate wet (food) and dry (paper, plastic) waste. Improves city recycling rates by 40%.",
            priority="medium", category="waste"))

    if req.condition in ("Rainy", "Stormy"):
        recs.append(Recommendation(icon="🌧️", title="Harvest Rainwater",
            description="Collect rooftop rainwater for garden/toilet use.",
            priority="low", category="water"))

    return RecommendationResponse(recommendations=recs[:6])


@app.post("/chat", response_model=ChatResponse)
def chat_with_assistant(req: ChatRequest):
    context_block = ""
    if req.context:
        ctx = req.context
        context_block = (
            f"[LIVE EcoPulse DATA]\n"
            f"City: {ctx.get('city','your city')}\n"
            f"AQI: {ctx.get('aqi','N/A')} — {ctx.get('aqiCategory','')}\n"
            f"Temperature: {ctx.get('temperature','N/A')}°C | Humidity: {ctx.get('humidity','N/A')}% | Wind: {ctx.get('windSpeed','N/A')} km/h\n"
            f"Sky: {ctx.get('condition','N/A')}\n"
            f"Eco Score: {ctx.get('ecoScore','N/A')}\n\n"
        )

    full_msg = context_block + req.message

    if gemini_model:
        try:
            history = []
            for msg in (req.history or [])[:-1]:
                history.append({"role": "user" if msg.role == "user" else "model", "parts": [msg.content]})
            chat     = gemini_model.start_chat(history=history)
            response = chat.send_message(full_msg)
            return ChatResponse(response=response.text)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Gemini API error: {exc}")

    # ── Rule-based fallback ───────────────────────────────────────────────
    msg_lower = req.message.lower()
    aqi_val   = req.context.get("aqi", 100)   if req.context else 100
    city_name = req.context.get("city","your city") if req.context else "your city"
    temp_val  = req.context.get("temperature","N/A") if req.context else "N/A"
    hum_val   = req.context.get("humidity","N/A")    if req.context else "N/A"
    cond_val  = req.context.get("condition","N/A")   if req.context else "N/A"

    if any(w in msg_lower for w in ["weather","temperature","hot","cold","humid","rain"]):
        return ChatResponse(response=(
            f"Current weather in {city_name}: {temp_val}°C, {hum_val}% humidity, {cond_val}. "
            f"AQI: {aqi_val} — {'good for outdoors' if aqi_val <= 100 else 'consider limiting outdoor exposure'}."
        ))
    if any(w in msg_lower for w in ["aqi","air quality","pollution","pm2","pm10"]):
        levels = [(50,"Good","Air is clean — great for all outdoor activities!"),
                  (100,"Satisfactory","Acceptable. Sensitive groups should moderate outdoor exertion."),
                  (200,"Moderate","Sensitive individuals should reduce outdoor activity."),
                  (300,"Poor","Everyone should avoid prolonged outdoor activity. Wear N95."),
                  (500,"Very Poor / Severe","Stay indoors! Avoid all outdoor activity.")]
        level, advice = next(((l, a) for cap, l, a in levels if aqi_val <= cap), ("Severe","Stay indoors!"))
        return ChatResponse(response=f"AQI in {city_name} is {aqi_val} — {level}. {advice}")
    if "carbon" in msg_lower or "footprint" in msg_lower:
        return ChatResponse(response="To reduce your carbon footprint: (1) Use public transport for trips <10 km, (2) Set AC to 24-26°C, (3) Segregate waste, (4) Reduce meat consumption, (5) Switch to LED bulbs. 🌍")
    if "water" in msg_lower and ("save" in msg_lower or "conserve" in msg_lower):
        return ChatResponse(response="Water saving tips: (1) Fix dripping taps (15L/day waste), (2) 5-min showers, (3) Collect rainwater, (4) Full washing machine loads only, (5) Use a bucket instead of hose. 💧")
    if "energy" in msg_lower or "electricity" in msg_lower:
        return ChatResponse(response="Energy tips: (1) AC at 24°C, (2) LED bulbs (80% less energy), (3) Unplug idle chargers, (4) Use natural light, (5) Consider rooftop solar. ⚡")
    if "waste" in msg_lower or "recycle" in msg_lower:
        return ChatResponse(response="Waste tips: (1) Segregate wet/dry waste, (2) Compost kitchen scraps, (3) E-waste to authorised collectors, (4) Use cloth bags, (5) Repair before replacing. ♻️")

    return ChatResponse(response=(
        f"I'm EcoPulse AI! In {city_name}: AQI {aqi_val}, Temp {temp_val}°C, {cond_val}. "
        "Ask me about air quality, weather, carbon footprint, waste management, or sustainability. 🌱"
    ))


@app.get("/predict", response_model=WeeklyForecastResponse)
def predict_weekly_temperature(
    humidity:   float = Query(..., description="Current relative humidity (%)"),
    wind_speed: float = Query(..., description="Current wind speed (km/h)"),
    meantemp:   float = Query(..., description="Current mean temperature (°C)"),
):
    """7-day iterative temperature forecast (ONNX or rule-based fallback)."""
    today_idx    = datetime.datetime.now().weekday()
    day_abbrs    = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    ordered_days = [day_abbrs[(today_idx + i) % 7] for i in range(7)]

    predictions:  List[float] = []
    current_temp: float       = meantemp

    for i in range(7):
        if onnx_session is not None:
            try:
                next_temp = _onnx_predict_temp(humidity, wind_speed, current_temp)
            except Exception:
                next_temp = _rule_based_predict_temp(humidity, wind_speed, current_temp, i)
        else:
            next_temp = _rule_based_predict_temp(humidity, wind_speed, current_temp, i)

        next_temp    = round(float(np.clip(next_temp, 5.0, 55.0)), 2)
        predictions.append(next_temp)
        current_temp = next_temp

    return WeeklyForecastResponse(days=ordered_days, temperature=predictions)


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=port)
