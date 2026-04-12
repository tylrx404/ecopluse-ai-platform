"""
EcoPulse — FastAPI AI Backend  |  http://localhost:8000

Endpoints:
  GET  /predict           — 7-day temperature forecast (ONNX model)
  POST /predict/aqi       — AQI forecast (24 / 48 / 72 h)
  POST /predict/aqi-hourly — Hourly AQI for next 72 h
  POST /predict/temp-hourly — Hourly temperature for next 72 h
  POST /predict/rain-hourly — Hourly rainfall probability for next 72 h
  POST /predict/eco-score — AI eco-impact score from daily habits
  POST /recommendations   — Personalised environmental recommendations
  POST /chat              — AI assistant powered by Google Gemini
"""
import logging
logging.basicConfig(level=logging.INFO)
import os
import json
import numpy as np
import joblib   
from pathlib import Path
from typing import Optional, List, Tuple, Dict

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dotenv import load_dotenv

try:
    import google.generativeai as genai
    _GENAI_AVAILABLE = True
except ImportError:
    genai = None  # type: ignore
    _GENAI_AVAILABLE = False
    print("⚠️  google-generativeai not installed — /chat will use fallback responses")

# onnxruntime — optional, graceful degradation if missing
try:
    import onnxruntime as ort
    _ORT_AVAILABLE = True
except ImportError:
    _ORT_AVAILABLE = False
    print("⚠️   onnxruntime not installed — /predict will use rule-based fallback")

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
BASE_DIR = Path(__file__).resolve().parent.parent
ML_DIR = BASE_DIR / "ml-model"

# ─────────────────────────────────────────────
# LOAD ONNX WEATHER MODEL
# ─────────────────────────────────────────────

onnx_session    = None
onnx_input_name = None

try:
    _onnx_path = ML_DIR / "weather_model.ONNX"
    if _ORT_AVAILABLE and _onnx_path.exists():
        onnx_session    = ort.InferenceSession(str(_onnx_path))
        onnx_input_name = onnx_session.get_inputs()[0].name
        print("✅  ONNX weather model loaded")
    else:
        print("⚠️   ONNX model not found or onnxruntime unavailable — /predict uses fallback")
except Exception as e:
    print(f"⚠️   ONNX model load failed: {e}")

# ─────────────────────────────────────────────
# LOAD ML MODELS (if available)
# ─────────────────────────────────────────────

aqi_model       = None
eco_score_model = None
temp_model      = None
rain_model      = None

_aqi_path = ML_DIR / "aqi_model.pkl"
if _aqi_path.exists():
    try:
        aqi_model = joblib.load(_aqi_path)
        print("✅  AQI model loaded")
    except Exception as e:
        print(f"❌  Error loading AQI model: {e}")
else:
    print("⚠️  AQI model not found — using rule-based fallback")

_eco_path = ML_DIR / "eco_score_model.pkl"
if _eco_path.exists():
    try:
        eco_score_model = joblib.load(_eco_path)
        print("✅  EcoScore model loaded")
    except Exception as e:
        print(f"❌  Error loading EcoScore model: {e}")
else:
    print("⚠️  EcoScore model not found — using rule-based fallback")

_temp_path = ML_DIR / "temp_model.pkl"
if _temp_path.exists():
    try:
        temp_model = joblib.load(_temp_path)
        print("✅  Temperature model loaded")
    except Exception as e:
        print(f"❌  Error loading Temperature model: {e}")
else:
    print("⚠️  Temperature model not found — using rule-based fallback")

_rain_path = ML_DIR / "rain_model.pkl"
if _rain_path.exists():
    try:
        rain_model = joblib.load(_rain_path)
        print("✅  Rain model loaded")
    except Exception as e:
        print(f"❌  Error loading Rain model: {e}")
else:
    print("⚠️  Rain model not found — using rule-based fallback")

# ─────────────────────────────────────────────
# GEMINI SETUP
# ─────────────────────────────────────────────

gemini_model = None
if not GEMINI_API_KEY or GEMINI_API_KEY == "placeholder_gemini_key_replace_with_real_key":
    print("⚠️  Gemini API key missing — /chat will use rule-based fallback responses")
elif not _GENAI_AVAILABLE:
    print("⚠️  google-generativeai not installed — /chat will use fallback responses")
else:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        gemini_model = genai.GenerativeModel(
            model_name="gemini-1.5-flash",
            system_instruction="""You are EcoPulse AI — an expert environmental intelligence assistant built into the EcoPulse platform.

You MUST answer every question fully and helpfully. NEVER give generic or evasive responses.

Your expertise covers:
- Air quality: AQI, PM2.5, PM10, NO2, SO2, O3, CO — Indian CPCB standards (0-50 Good, 51-100 Satisfactory, 101-200 Moderate, 201-300 Poor, 301-400 Very Poor, 401-500 Severe)
- Weather: temperature, humidity, wind speed, UV index, rainfall prediction
- Pollution health effects: which groups are most vulnerable, what precautions to take
- Carbon footprint reduction: transport, diet, energy, water, waste hierarchy
- Environmental events: World Environment Day, Earth Day, Clean Air campaigns
- Sustainability practices: zero-waste, renewable energy, green commuting, water conservation
- Indian environmental context: CPCB regulations, Swachh Bharat, PMUY, FAME-II EV scheme

When environmental context data is provided (city, AQI, temperature, etc.), USE IT to give a specific, personalized answer.

For weather questions: give actual numbers from context. For AQI questions: interpret the number and its health implications. For sustainability questions: give 3-5 practical, actionable tips.

Response style:
- Be direct, specific, and helpful — never vague
- Keep responses 2-5 sentences unless detail is needed
- Use emojis sparingly (max 2 per response)
- Always answer the actual question asked
- If asked for a specific city not in your context, say you have live data for the user's registered city and give general guidance for the queried city"""
        )
        print("✅  Gemini AI initialized")
    except Exception as e:
        gemini_model = None
        print(f"❌  Gemini initialization failed: {e} — /chat will use fallback responses")

# ─────────────────────────────────────────────
# APP INIT
# ─────────────────────────────────────────────

app = FastAPI(
    title="EcoPulse AI API",
    description="AI-powered environmental intelligence backend for EcoPulse",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "*"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve uploaded images
_uploads_dir = BASE_DIR / "uploads"
_uploads_dir.mkdir(exist_ok=True)
app.mount("/uploads", StaticFiles(directory=str(_uploads_dir)), name="uploads")

# ── Import routers and register them ─────────────────────────────────────────
try:
    from database import engine
    from models import Base
    import civic_models  # noqa — registers civic tables on Base
    from routers import auth_router, data_router
    from routers import civic_router

    # Include Routers
    app.include_router(auth_router.router)
    app.include_router(data_router.router)
    app.include_router(civic_router.router)
    print("✅  Routers registered")
except Exception as e:
    print(f"❌  Router initialization failed: {e}")
    engine = None
    Base = None


@app.on_event("startup")
def startup():
    """Create all database tables on app startup."""
    if engine is not None and Base is not None:
        try:
            Base.metadata.create_all(bind=engine)
            print("✅  Database tables created/verified")
        except Exception as e:
            print(f"❌  Database table creation failed: {e}")
    else:
        print("⚠️  Skipping DB table creation — engine not available")

# ─────────────────────────────────────────────
# REQUEST / RESPONSE MODELS
# ─────────────────────────────────────────────

class AQIRequest(BaseModel):
    temperature: float
    humidity: float
    wind_speed: float
    pm25: float
    pm10: float
    co: float
    no2: float
    so2: float
    o3: float

class AQIForecastPoint(BaseModel):
    hours: int
    aqi: int
    category: str
    color: str

class AQIPredictionResponse(BaseModel):
    forecast: List[AQIForecastPoint]
    current_aqi: int
    current_category: str

class EcoScoreRequest(BaseModel):
    ac_fan_hours: float
    water_usage: float
    transport_mode: str   # "walk" | "cycle" | "public" | "private"
    outdoor_exposure: str # "low" | "medium" | "high"
    waste_segregation: bool

class EcoScoreResponse(BaseModel):
    score: float
    category: str
    insights: List[str]
    breakdown: Dict

class RecommendationRequest(BaseModel):
    aqi: float
    temperature: float
    humidity: float
    wind_speed: float
    condition: str
    ac_fan_hours: Optional[float] = None
    water_usage: Optional[float] = None
    transport_mode: Optional[str] = None
    waste_segregation: Optional[bool] = None

class Recommendation(BaseModel):
    icon: str
    title: str
    description: str
    priority: str   # "high" | "medium" | "low"
    category: str   # "air" | "energy" | "transport" | "water" | "waste"

class RecommendationResponse(BaseModel):
    recommendations: List[Recommendation]

class ChatMessage(BaseModel):
    role: str   # "user" | "assistant"
    content: str

class ChatRequest(BaseModel):
    message: str
    history: Optional[List[ChatMessage]] = []
    context: Optional[Dict] = None   # optional: current AQI, city, weather

class ChatResponse(BaseModel):
    response: str

# ─────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────

TRANSPORT_MAP = {"walk": 0, "cycle": 1, "public": 2, "private": 3}
OUTDOOR_MAP   = {"low": 0, "medium": 1, "high": 2}

def aqi_to_category(aqi: int) -> Tuple[str, str]:
    """Return (category_label, color_hex) for a given AQI."""
    if aqi <= 50:   return ("Good", "#22c55e")
    if aqi <= 100:  return ("Satisfactory", "#84cc16")
    if aqi <= 200:  return ("Moderate", "#f59e0b")
    if aqi <= 300:  return ("Poor", "#f97316")
    if aqi <= 400:  return ("Very Poor", "#ef4444")
    return ("Severe", "#7c3aed")

def eco_score_to_category(score: float) -> str:
    if score >= 75: return "Eco-Friendly"
    if score >= 50: return "Moderate"
    return "High Impact"

def rule_based_aqi_forecast(req: AQIRequest, hours_ahead: int) -> int:
    """Fallback when ML model not available."""
    # Simple rule: use pm25 as primary driver with trend noise
    def pm25_to_aqi(pm: float) -> int:
        if pm <= 30:  return int(pm * 50 / 30)
        if pm <= 60:  return int(51 + (pm - 31) * 49 / 29)
        if pm <= 90:  return int(101 + (pm - 61) * 99 / 29)
        if pm <= 120: return int(201 + (pm - 91) * 99 / 29)
        if pm <= 250: return int(301 + (pm - 121) * 99 / 129)
        return int(401 + (pm - 251) * 99 / 249)

    current = pm25_to_aqi(req.pm25)
    # Slightly vary based on wind forecast
    wind_effect = -req.wind_speed * 0.3 * (hours_ahead / 24)
    noise = np.random.normal(0, 5)
    return max(0, min(500, int(current + wind_effect + noise)))

def rule_based_eco_score(req: EcoScoreRequest) -> float:
    """Fallback when ML model not available."""
    score = 55.0
    water_delta  = (135 - req.water_usage) / 10
    energy_delta = (6 - req.ac_fan_hours)
    score += max(-15, min(10, water_delta * 2))
    score += max(-20, min(18, energy_delta * 3))
    transport_bonus = {"walk": 12, "cycle": 10, "public": 6, "private": -5}
    score += transport_bonus.get(req.transport_mode, 0)
    score += 5 if req.waste_segregation else -5
    outdoor_bonus = {"high": 5, "medium": 2, "low": 0}
    score += outdoor_bonus.get(req.outdoor_exposure, 0)
    return round(max(0, min(100, score)), 1)

# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "message":    "EcoPulse AI API is running 🌱",
        "models_loaded": aqi_model is not None,
        "gemini_active": gemini_model is not None,
        "docs":       "/docs",
    }


@app.post("/predict/aqi", response_model=AQIPredictionResponse)
def predict_aqi(req: AQIRequest):
    """Predict AQI for the next 24, 48, and 72 hours."""
    features = [
        req.temperature, req.humidity, req.wind_speed,
        req.pm25, req.pm10, req.co, req.no2, req.so2, req.o3
    ]
    X = np.array([features])

    forecast = []
    hour_offsets = [24, 48, 72]

    for hours in hour_offsets:
        if aqi_model:
            # Add slight jitter per horizon to simulate different conditions
            jitter = np.array([[0, 0, hours * 0.1, -hours * 0.05, -hours * 0.05, 0, 0, 0, 0]])
            aqi_val = int(np.clip(aqi_model.predict(X + jitter)[0], 0, 500))
        else:
            aqi_val = rule_based_aqi_forecast(req, hours)

        category, color = aqi_to_category(aqi_val)
        forecast.append(AQIForecastPoint(hours=hours, aqi=aqi_val, category=category, color=color))

    current_cat, _ = aqi_to_category(int(req.pm25))  # approximate from PM2.5
    return AQIPredictionResponse(
        forecast=forecast,
        current_aqi=int(rule_based_aqi_forecast(req, 0)),
        current_category=current_cat,
    )


# ─────────────────────────────────────────────
# NEW MODELS — Shared request schema
# ─────────────────────────────────────────────

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


def _base_features(req: HourlyPredictionRequest) -> np.ndarray:
    """Return the 10 environmental feature array (without hour_offset)."""
    return np.array([
        req.temperature, req.humidity, req.wind_speed, req.pressure,
        req.pm25, req.pm10, req.co, req.no2, req.so2, req.o3,
    ])


@app.post("/predict/aqi-hourly", response_model=List[HourlyPoint])
def predict_aqi_hourly(req: HourlyPredictionRequest):
    """Predict hourly AQI for the next 72 hours."""
    result = []
    base   = _base_features(req)

    for h in range(73):  # 0 (current) … 72
        if h == 0:
            aqi = rule_based_aqi_forecast(
                AQIRequest(
                    temperature=req.temperature, humidity=req.humidity,
                    wind_speed=req.wind_speed, pm25=req.pm25, pm10=req.pm10,
                    co=req.co, no2=req.no2, so2=req.so2, o3=req.o3,
                ),
                0,
            )
        elif aqi_model:
            feats = np.append(base, h).reshape(1, -1)
            # AQI model was trained without hour_offset — use jitter trick
            jitter = np.array([[0, 0, h * 0.1, 0, -h * 0.05, -h * 0.05, 0, 0, 0, 0]])
            aqi = int(np.clip(aqi_model.predict(base.reshape(1, -1) + jitter)[0], 0, 500))
        else:
            aqi = rule_based_aqi_forecast(
                AQIRequest(
                    temperature=req.temperature, humidity=req.humidity,
                    wind_speed=req.wind_speed, pm25=req.pm25, pm10=req.pm10,
                    co=req.co, no2=req.no2, so2=req.so2, o3=req.o3,
                ),
                h,
            )
        result.append(HourlyPoint(hour=h, aqi=float(aqi)))
    return result


@app.post("/predict/temp-hourly", response_model=List[HourlyPoint])
def predict_temp_hourly(req: HourlyPredictionRequest):
    """Predict hourly temperature for the next 72 hours."""
    result = []
    base   = _base_features(req)
    import datetime
    current_hour = datetime.datetime.now().hour

    for h in range(73):
        if temp_model:
            feats = np.append(base, h).reshape(1, -1)
            temp  = float(np.clip(temp_model.predict(feats)[0], 5, 50))
        else:
            # Rule-based diurnal fallback
            future_hour = (current_hour + h) % 24
            diurnal     = -5 * np.cos((future_hour - 14) * 2 * np.pi / 24)
            day_drift   = -0.3 * (h // 24)
            wind_effect = -req.wind_speed * 0.05
            temp = float(np.clip(req.temperature + diurnal + day_drift + wind_effect, 5, 50))
        result.append(HourlyPoint(hour=h, temperature=round(temp, 1)))
    return result


@app.post("/predict/rain-hourly", response_model=List[HourlyPoint])
def predict_rain_hourly(req: HourlyPredictionRequest):
    """Predict hourly rainfall probability (0–100%) for the next 72 hours."""
    result = []
    base   = _base_features(req)
    import datetime
    current_hour = datetime.datetime.now().hour

    for h in range(73):
        if rain_model:
            feats = np.append(base, h).reshape(1, -1)
            prob  = float(np.clip(rain_model.predict(feats)[0], 0, 100))
        else:
            # Rule-based fallback
            base_prob      = max(0, (req.humidity - 40) * 1.2 + (1013 - req.pressure) * 0.8)
            future_hour    = (current_hour + h) % 24
            afternoon_boost= 20 if 14 <= future_hour <= 18 else 0
            wind_reduction = -req.wind_speed * 0.3
            noise          = np.sin(h * 0.7) * 8
            prob = float(np.clip(base_prob + afternoon_boost + wind_reduction + noise, 0, 100))
        result.append(HourlyPoint(hour=h, rainfall=round(prob, 1)))
    return result


@app.post("/predict/eco-score", response_model=EcoScoreResponse)

def predict_eco_score(req: EcoScoreRequest):
    """AI-powered eco-impact score from daily user habits."""
    transport_enc = TRANSPORT_MAP.get(req.transport_mode, 3)
    outdoor_enc   = OUTDOOR_MAP.get(req.outdoor_exposure, 0)

    if eco_score_model:
        X = np.array([[req.ac_fan_hours, req.water_usage, transport_enc, outdoor_enc,
                       int(req.waste_segregation)]])
        score = float(np.clip(eco_score_model.predict(X)[0], 0, 100))
    else:
        score = rule_based_eco_score(req)

    score   = round(score, 1)
    cat     = eco_score_to_category(score)

    # Build personalized insights
    insights = []
    if req.water_usage > 135:
        over = req.water_usage - 135
        insights.append(f"You used {over:.0f}L more water than the national average. Try shorter showers. 🚿")
    else:
        insights.append(f"Great job! You saved {135 - req.water_usage:.0f}L of water today. 💧")

    if req.ac_fan_hours > 6:
        insights.append(f"AC/Fan ran {req.ac_fan_hours:.0f}h — try reducing by 1–2 hours to save energy. ⚡")
    else:
        insights.append(f"Energy usage looks good! Only {req.ac_fan_hours:.0f}h of AC/Fan. ✅")

    if req.transport_mode == "private":
        insights.append("Switching to public transport just twice a week cuts your carbon footprint by ~30%. 🚌")
    elif req.transport_mode in ("walk", "cycle"):
        insights.append("Walking/cycling — zero emissions and great for your health! 🚶")

    if not req.waste_segregation:
        insights.append("Segregating wet and dry waste improves recycling rates dramatically. 🗑️")

    breakdown = {
        "water_score":    round(max(0, min(20, 10 + (135 - req.water_usage) / 10 * 1.5)), 1),
        "energy_score":   round(max(0, min(25, 12 + (6 - req.ac_fan_hours) * 2.5)), 1),
        "transport_score": {"walk": 25, "cycle": 22, "public": 18, "private": 5}[req.transport_mode],
        "waste_score":    15 if req.waste_segregation else 5,
        "outdoor_score":  {"high": 10, "medium": 6, "low": 2}[req.outdoor_exposure],
    }

    return EcoScoreResponse(score=score, category=cat, insights=insights, breakdown=breakdown)


@app.post("/recommendations", response_model=RecommendationResponse)
def get_recommendations(req: RecommendationRequest):
    """Generate contextual environmental recommendations based on AQI, weather, and behavior."""
    recs = []

    # ── AQI-based recommendations
    if req.aqi > 300:
        recs.append(Recommendation(
            icon="😷", title="Wear N95 Mask Outdoors",
            description=f"AQI is {req.aqi:.0f} (Severe). An N95 mask is essential — limit all outdoor time.",
            priority="high", category="air"
        ))
    elif req.aqi > 200:
        recs.append(Recommendation(
            icon="🏠", title="Stay Indoors Today",
            description=f"AQI is {req.aqi:.0f} (Very Poor). Avoid outdoor exercise and keep windows closed.",
            priority="high", category="air"
        ))
    elif req.aqi > 100:
        recs.append(Recommendation(
            icon="⏰", title="Exercise in Early Morning",
            description=f"AQI is {req.aqi:.0f} (Moderate). Outdoor exercise is safer before 7 AM when pollution is lower.",
            priority="medium", category="air"
        ))
    else:
        recs.append(Recommendation(
            icon="🌿", title="Great Day for Outdoor Activity",
            description=f"AQI is {req.aqi:.0f} (Good). Perfect conditions for outdoor exercise and fresh air.",
            priority="low", category="air"
        ))

    # ── Temperature-based
    if req.temperature > 38:
        recs.append(Recommendation(
            icon="💧", title="Stay Hydrated",
            description=f"At {req.temperature:.0f}°C, drink 3–4L of water today. Avoid peak heat (12PM–4PM).",
            priority="high", category="energy"
        ))
    elif req.temperature > 32:
        recs.append(Recommendation(
            icon="🌬️", title="Optimize AC Usage",
            description="Set AC to 24–26°C instead of lower — saves up to 20% energy with minimal comfort loss.",
            priority="medium", category="energy"
        ))

    # ── Wind-based air purification
    if req.wind_speed > 20:
        recs.append(Recommendation(
            icon="🪟", title="Open Windows for Natural Ventilation",
            description=f"Wind speed is {req.wind_speed:.0f} km/h — natural ventilation is excellent right now.",
            priority="low", category="air"
        ))

    # ── Behavior-based recs
    if req.transport_mode == "private":
        recs.append(Recommendation(
            icon="🚌", title="Try Public Transport",
            description="Switching to public transport today reduces your personal CO₂ emissions by up to 70%.",
            priority="medium", category="transport"
        ))
    elif req.transport_mode is None:
        recs.append(Recommendation(
            icon="🚲", title="Cycle or Walk Short Distances",
            description="For trips under 5km, cycling or walking produces zero emissions and improves fitness.",
            priority="low", category="transport"
        ))

    if req.water_usage is not None and req.water_usage > 150:
        recs.append(Recommendation(
            icon="🚿", title="Reduce Water Usage",
            description=f"You used {req.water_usage:.0f}L (India avg: 135L). Fix dripping taps and take shorter showers.",
            priority="medium", category="water"
        ))

    if req.waste_segregation is False:
        recs.append(Recommendation(
            icon="🗑️", title="Start Waste Segregation",
            description="Separate wet (food) and dry (paper, plastic) waste. This small step improves city recycling rates by 40%.",
            priority="medium", category="waste"
        ))

    # Always include a seasonal / condition tip
    if req.condition in ("Rainy", "Stormy"):
        recs.append(Recommendation(
            icon="🌧️", title="Harvest Rainwater",
            description="Today's rain is an opportunity — collect rooftop rainwater for garden/toilet use.",
            priority="low", category="water"
        ))

    return RecommendationResponse(recommendations=recs[:6])  # max 6 displayed


@app.post("/chat", response_model=ChatResponse)
def chat_with_assistant(req: ChatRequest):
    """EcoPulse AI assistant — powered by Google Gemini."""

    # Build a rich context block from live environmental data
    context_block = ""
    if req.context:
        ctx = req.context
        city        = ctx.get("city", "your city")
        aqi         = ctx.get("aqi", "N/A")
        aqi_cat     = ctx.get("aqiCategory", "")
        temp        = ctx.get("temperature", "N/A")
        humidity    = ctx.get("humidity", "N/A")
        wind        = ctx.get("windSpeed", "N/A")
        condition   = ctx.get("condition", "N/A")
        eco_score   = ctx.get("ecoScore", "N/A")

        context_block = (
            f"[LIVE EcoPulse DATA — use this to answer the user's question]\n"
            f"City: {city}\n"
            f"AQI: {aqi} — {aqi_cat}\n"
            f"Temperature: {temp}°C | Humidity: {humidity}% | Wind: {wind} km/h\n"
            f"Sky Condition: {condition}\n"
            f"User's Eco Score: {eco_score}\n"
            f"[Use these exact values when the user asks about weather or AQI in {city}]\n\n"
        )

    full_user_message = context_block + req.message

    # ── Gemini path ────────────────
    if gemini_model:
        try:
            # Rebuild conversation history for Gemini (exclude the very last user turn — we send it now)
            history = []
            for msg in (req.history or [])[:-1]:  # skip last user msg, we inject it fresh
                role = "user" if msg.role == "user" else "model"
                history.append({"role": role, "parts": [msg.content]})

            chat = gemini_model.start_chat(history=history)
            response = chat.send_message(full_user_message)
            return ChatResponse(response=response.text)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Gemini API error: {str(e)}")

    # ── Rule-based fallback (no Gemini key) ──────
    msg_lower = req.message.lower()
    aqi_val   = req.context.get("aqi", 100) if req.context else 100
    city_name = req.context.get("city", "your city") if req.context else "your city"
    temp_val  = req.context.get("temperature", "N/A") if req.context else "N/A"
    hum_val   = req.context.get("humidity", "N/A") if req.context else "N/A"
    cond_val  = req.context.get("condition", "N/A") if req.context else "N/A"

    # Weather question
    if any(w in msg_lower for w in ["weather", "temperature", "hot", "cold", "humid", "rain"]):
        return ChatResponse(response=(
            f"Current weather in {city_name}: {temp_val}°C, {hum_val}% humidity, "
            f"condition: {cond_val}. "
            f"The AQI is {aqi_val} — {'good conditions for being outdoors' if aqi_val <= 100 else 'consider limiting outdoor exposure today'}."
        ))

    # AQI / air quality question
    if any(w in msg_lower for w in ["aqi", "air quality", "pollution", "pm2", "pm10"]):
        if aqi_val <= 50:
            level, advice = "Good (0-50)",    "Air is clean — great for all outdoor activities! "
        elif aqi_val <= 100:
            level, advice = "Satisfactory",   "Acceptable air quality. Sensitive groups should moderate prolonged outdoor exertion. "
        elif aqi_val <= 200:
            level, advice = "Moderate",       "Sensitive individuals (children, elderly, heart/lung patients) should reduce outdoor activity. "
        elif aqi_val <= 300:
            level, advice = "Poor",           "Everyone should avoid prolonged outdoor activity. Wear N95 if going out. "
        else:
            level, advice = "Very Poor/Severe","Stay indoors! Avoid all outdoor activity. Use an air purifier indoors if available. "
        return ChatResponse(response=(
            f"Current AQI in {city_name} is {aqi_val} — {level}. {advice}"
            f"AQI follows Indian CPCB standards: 0-50 Good, 51-100 Satisfactory, 101-200 Moderate, 201-300 Poor, 301-400 Very Poor, 401-500 Severe."
        ))

    if "pm2.5" in msg_lower or "pm25" in msg_lower:
        return ChatResponse(response="PM2.5 are fine particles (< 2.5μm) that penetrate deep into lungs and enter the bloodstream. Long-term exposure causes cardiovascular and respiratory disease. Indian CPCB limit: 60 μg/m³ (annual). On high PM2.5 days, wear N95 masks and use HEPA air purifiers indoors. 😷")

    if "safe" in msg_lower and ("outside" in msg_lower or "outdoor" in msg_lower):
        return ChatResponse(response=(
            f"AQI in {city_name} is currently {aqi_val}. "
            + ("It's safe to go outside — enjoy the fresh air!" if aqi_val <= 100
               else "It's advisable to limit outdoor exposure. If you must go out, wear an N95 mask.")
        ))

    if "carbon" in msg_lower or "footprint" in msg_lower:
        return ChatResponse(response="To reduce your carbon footprint: (1) Use public transport or cycle for trips < 10 km, (2) Set AC to 24-26°C, (3) Segregate waste for recycling, (4) Reduce meat consumption, (5) Switch to LED bulbs. Small daily actions add up to big impact! 🌍")

    if "water" in msg_lower and ("save" in msg_lower or "conserve" in msg_lower):
        return ChatResponse(response="Water saving tips: (1) Fix dripping taps — each wastes 15L/day, (2) Take 5-minute showers instead of baths, (3) Collect rainwater for gardens, (4) Run washing machines only with full loads, (5) Use a bucket instead of a running hose. 💧")

    if "energy" in msg_lower or "electricity" in msg_lower:
        return ChatResponse(response="Energy saving tips: (1) Set AC to 24°C — each degree lower adds 6% to your bill, (2) Use LED bulbs (80% less energy), (3) Unplug chargers when not in use, (4) Use natural light during daytime, (5) Consider rooftop solar if you own your premises. ⚡")

    if "waste" in msg_lower or "recycle" in msg_lower or "trash" in msg_lower:
        return ChatResponse(response="Waste management tips: (1) Segregate wet (organic) and dry (paper/plastic) waste, (2) Compost kitchen scraps into garden fertilizer, (3) Give e-waste to authorized collectors, (4) Use cloth bags instead of plastic, (5) Repair before replacing electronics. ♻️")

    # Generic helpful fallback
    return ChatResponse(response=(
        f"I'm EcoPulse AI! Currently in {city_name}: AQI {aqi_val}, Temp {temp_val}°C, Condition: {cond_val}. "
        "I can answer questions about air quality, pollution, weather, carbon footprint, waste management, and sustainable living. What would you like to know? 🌱"
    ))


# ─────────────────────────────────────────────
# ONNX 7-DAY TEMPERATURE FORECAST
# ─────────────────────────────────────────────

DAYS_OF_WEEK = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]


def _onnx_predict_temp(humidity: float, wind_speed: float, temp_lag1: float) -> float:
    """Single ONNX inference call: returns next predicted temperature."""
    input_array = np.array([[humidity, wind_speed, temp_lag1]], dtype=np.float32)
    output = onnx_session.run(None, {onnx_input_name: input_array})
    return float(output[0][0])


def _rule_based_predict_temp(humidity: float, wind_speed: float, temp_lag1: float, day: int) -> float:
    """Simple physics-based fallback when ONNX unavailable."""
    wind_effect     = -wind_speed * 0.05
    humidity_effect = -(humidity - 60) * 0.05
    # Slight daily drift toward a climatological mean (~28°C)
    mean_reversion  = (28.0 - temp_lag1) * 0.08
    noise           = float(np.sin(day * 1.1) * 0.8)  # deterministic oscillation
    return round(temp_lag1 + wind_effect + humidity_effect + mean_reversion + noise, 2)


class WeeklyForecastResponse(BaseModel):
    days:        List[str]
    temperature: List[float]


@app.get("/predict", response_model=WeeklyForecastResponse)
def predict_weekly_temperature(
    humidity:   float = Query(..., description="Current relative humidity (%)"),
    wind_speed: float = Query(..., description="Current wind speed (km/h)"),
    meantemp:   float = Query(..., description="Current mean temperature (°C)"),
):
    """
    7-day iterative temperature forecast using the ONNX weather model.
    Falls back to rule-based prediction if the model is unavailable.

    Query params:
      humidity   — current humidity (%)
      wind_speed — current wind speed (km/h)
      meantemp   — current temperature (°C), used as temp_lag1 for day 1
    """
    import datetime
    today_idx    = datetime.datetime.now().weekday()  # 0=Mon … 6=Sun (Python)
    # Map Python weekday → calendar order starting from today
    # We want labels starting with today's abbreviated day name
    day_abbrs    = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    ordered_days = [day_abbrs[(today_idx + i) % 7] for i in range(7)]

    predictions:  list[float] = []
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
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)

    