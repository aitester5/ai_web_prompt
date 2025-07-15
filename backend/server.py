from fastapi import FastAPI, APIRouter, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import StreamingResponse, FileResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
import os
import logging
import asyncio
import subprocess
import json
import sqlite3
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Dict, Optional
import uuid
from datetime import datetime
import tempfile
import shutil
import databases
import sqlalchemy

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# SQLite Database setup
DATABASE_URL = "sqlite:///./vulnerability_scanner.db"
database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

# Create tables
scan_sessions_table = sqlalchemy.Table(
    "scan_sessions",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.String, primary_key=True),
    sqlalchemy.Column("environment", sqlalchemy.String),
    sqlalchemy.Column("model_name", sqlalchemy.String),
    sqlalchemy.Column("probes", sqlalchemy.Text),  # JSON string
    sqlalchemy.Column("tool", sqlalchemy.String),
    sqlalchemy.Column("status", sqlalchemy.String),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime),
    sqlalchemy.Column("completed_at", sqlalchemy.DateTime, nullable=True),
    sqlalchemy.Column("output_file", sqlalchemy.String, nullable=True),
    sqlalchemy.Column("error_message", sqlalchemy.String, nullable=True),
    sqlalchemy.Column("promptmap_directory", sqlalchemy.String, nullable=True),
)

status_checks_table = sqlalchemy.Table(
    "status_checks",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.String, primary_key=True),
    sqlalchemy.Column("client_name", sqlalchemy.String),
    sqlalchemy.Column("timestamp", sqlalchemy.DateTime),
)

engine = sqlalchemy.create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
metadata.create_all(engine)

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()

# Define Models
class StatusCheck(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client_name: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class StatusCheckCreate(BaseModel):
    client_name: str

class ScanRequest(BaseModel):
    environment: str
    model_name: str
    probes: List[str]
    tool: str = "garak"  # garak or promptmap
    promptmap_directory: Optional[str] = None  # Required when tool is promptmap

class ScanSession(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    environment: str
    model_name: str
    probes: List[str]
    tool: str
    status: str = "pending"  # pending, running, completed, failed
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    output_file: Optional[str] = None
    error_message: Optional[str] = None
    promptmap_directory: Optional[str] = None

# Utility functions
async def get_conda_environments():
    """Get list of available conda environments"""
    try:
        result = subprocess.run(
            ["conda", "env", "list", "--json"],
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8',
            errors='replace'
        )
        environments = json.loads(result.stdout)
        env_names = []
        for env in environments.get("envs", []):
            env_path = Path(env)
            env_name = env_path.name
            if env_name not in ["base", "root"]:
                env_names.append(env_name)
        return env_names
    except Exception as e:
        logging.error(f"Error getting conda environments: {e}")
        # Return mock data for demo purposes when conda is not available
        return ["garak_env", "promptmap_env", "security_test_env"]

async def get_ollama_models():
    """Get list of available Ollama models"""
    try:
        result = subprocess.run(
            ["ollama", "list"],
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8',
            errors='replace'
        )
        models = []
        lines = result.stdout.strip().split('\n')[1:]  # Skip header
        for line in lines:
            if line.strip():
                model_name = line.split()[0]
                models.append(model_name)
        return models
    except Exception as e:
        logging.error(f"Error getting Ollama models: {e}")
        # Return mock data for demo purposes when ollama is not available
        return ["llama3:latest", "llama3:8b", "gemma:7b", "mistral:7b", "codellama:7b"]

async def get_garak_probes():
    """Get list of available Garak probes"""
    garak_probes = [
        "test.Test",
        "dan.Dan_11_0",
        "dan.Dan_6_0",
        "dan.Dan_6_2",
        "dan.Dan_7_0",
        "dan.Dan_8_0",
        "dan.Dan_9_0",
        "dan.Dan_10_0",
        "continuation.ContinueSlursReclaimedSlurs",
        "continuation.ContinueSlursReclaimedSlurs_ko",
        "promptinject.PromptInjectClassifier",
        "promptinject.PromptInjectGCG",
        "realtoxicityprompts.RealToxicityPrompts",
        "malwaregen.Malwaregen",
        "xss.XSS",
        "latentinjection.LatentInjection",
        "encoding.InjectBase64",
        "encoding.InjectUnicode",
        "encoding.InjectROT13",
        "encoding.InjectHex",
        "encoding.InjectMorse",
        "encoding.InjectZalgo",
        "encoding.InjectQwerty",
        "encoding.InjectBraille",
        "encoding.InjectMirror",
        "encoding.InjectASCII",
        "encoding.InjectUpsideDown",
        "encoding.InjectLeet",
        "encoding.InjectCaesar",
        "encoding.InjectAtbash",
        "exploitation.Exploitation",
        "hijacking.Hijacking",
        "lmrc.Lmrc",
        "packagehallucination.PackageHallucination"
    ]
    return garak_probes

async def run_garak_scan(environment: str, model_name: str, probes: List[str], websocket: WebSocket):
    """Run Garak scan with real-time output"""
    try:
        # Create the command
        probe_str = ",".join(probes)
        command = [
            "conda", "run", "-n", environment,
            "python", "-m", "garak",
            "--model_type", "ollama",
            "--model_name", model_name,
            "--probes", probe_str,
            "--report_prefix", f"garak_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        ]

        # Send command info to WebSocket
        await manager.send_personal_message(f"🚀 Starting Garak scan...", websocket)
        await manager.send_personal_message(f"📋 Environment: {environment}", websocket)
        await manager.send_personal_message(f"🤖 Model: {model_name}", websocket)
        await manager.send_personal_message(f"🔍 Probes: {probe_str}", websocket)
        await manager.send_personal_message(f"⚡ Running command: {' '.join(command)}", websocket)

        # Check if conda is available
        try:
            conda_check = await asyncio.create_subprocess_exec(
                "conda", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await conda_check.wait()
            if conda_check.returncode != 0:
                await manager.send_personal_message("❌ Conda not found. Please install Miniconda/Anaconda.", websocket)
                return False, "Conda not found"
        except Exception as e:
            await manager.send_personal_message(f"❌ Conda not available: {str(e)}", websocket)
            return False, f"Conda not available: {str(e)}"

        # Check if environment exists
        try:
            env_check = await asyncio.create_subprocess_exec(
                "conda", "env", "list",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await env_check.communicate()
            if environment not in stdout.decode('utf-8', errors='replace'):
                await manager.send_personal_message(f"❌ Environment '{environment}' not found.", websocket)
                return False, f"Environment '{environment}' not found"
        except Exception as e:
            await manager.send_personal_message(f"❌ Error checking environment: {str(e)}", websocket)
            return False, f"Error checking environment: {str(e)}"

        # Set environment variables to fix Unicode issues
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        env['PYTHONUTF8'] = '1'

        # Start the process with proper encoding handling
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env
        )

        # Stream output in real-time
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            # Decode with error handling for Unicode issues
            decoded_line = line.decode('utf-8', errors='replace').strip()
            if decoded_line:
                await manager.send_personal_message(decoded_line, websocket)

        # Wait for process to complete
        await process.wait()

        if process.returncode == 0:
            await manager.send_personal_message("✅ Scan completed successfully!", websocket)
            return True, None
        else:
            await manager.send_personal_message(f"❌ Scan failed with return code: {process.returncode}", websocket)
            return False, f"Process failed with return code: {process.returncode}"

    except Exception as e:
        error_msg = f"Error running Garak scan: {str(e)}"
        await manager.send_personal_message(f"❌ {error_msg}", websocket)
        return False, error_msg

async def run_promptmap_scan(environment: str, model_name: str, websocket: WebSocket):
    """Run Promptmap scan with real-time output"""
    try:
        # Create the command for promptmap
        command = [
            "conda", "run", "-n", environment,
            "python", "-m", "promptmap",
            "--model", model_name,
            "--output", f"promptmap_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        ]

        # Send command info to WebSocket
        await manager.send_personal_message(f"🚀 Starting Promptmap scan...", websocket)
        await manager.send_personal_message(f"📋 Environment: {environment}", websocket)
        await manager.send_personal_message(f"🤖 Model: {model_name}", websocket)
        await manager.send_personal_message(f"⚡ Running command: {' '.join(command)}", websocket)

        # Set environment variables to fix Unicode issues
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        env['PYTHONUTF8'] = '1'

        # Start the process with proper encoding handling
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env
        )

        # Stream output in real-time
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            # Decode with error handling for Unicode issues
            decoded_line = line.decode('utf-8', errors='replace').strip()
            if decoded_line:
                await manager.send_personal_message(decoded_line, websocket)

        # Wait for process to complete
        await process.wait()

        if process.returncode == 0:
            await manager.send_personal_message("✅ Scan completed successfully!", websocket)
            return True, None
        else:
            await manager.send_personal_message(f"❌ Scan failed with return code: {process.returncode}", websocket)
            return False, f"Process failed with return code: {process.returncode}"

    except Exception as e:
        error_msg = f"Error running Promptmap scan: {str(e)}"
        await manager.send_personal_message(f"❌ {error_msg}", websocket)
        return False, error_msg

# API Routes
@api_router.get("/")
async def root():
    return {"message": "LLM Vulnerability Scanner API"}

@api_router.get("/environments")
async def get_environments():
    """Get available conda environments"""
    environments = await get_conda_environments()
    return {"environments": environments}

@api_router.get("/models")
async def get_models():
    """Get available Ollama models"""
    models = await get_ollama_models()
    return {"models": models}

@api_router.get("/probes")
async def get_probes():
    """Get available Garak probes"""
    probes = await get_garak_probes()
    return {"probes": probes}

@api_router.post("/scan")
async def create_scan(scan_request: ScanRequest):
    """Create a new vulnerability scan"""
    try:
        # Validate input
        if not scan_request.environment or not scan_request.environment.strip():
            raise HTTPException(status_code=422, detail="Environment is required")
        
        if not scan_request.model_name or not scan_request.model_name.strip():
            raise HTTPException(status_code=422, detail="Model name is required")
        
        if scan_request.tool == "garak" and (not scan_request.probes or len(scan_request.probes) == 0):
            raise HTTPException(status_code=422, detail="At least one probe is required for Garak")

        session = ScanSession(
            environment=scan_request.environment,
            model_name=scan_request.model_name,
            probes=scan_request.probes,
            tool=scan_request.tool
        )

        # Save session to database
        query = scan_sessions_table.insert().values(
            id=session.id,
            environment=session.environment,
            model_name=session.model_name,
            probes=json.dumps(session.probes),
            tool=session.tool,
            status=session.status,
            created_at=session.created_at,
            completed_at=session.completed_at,
            output_file=session.output_file,
            error_message=session.error_message
        )
        await database.execute(query)

        return {"session_id": session.id, "status": "created"}

    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error in create_scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.websocket("/ws/scan/{session_id}")
async def websocket_scan(websocket: WebSocket, session_id: str):
    """WebSocket endpoint for real-time scan execution"""
    await manager.connect(websocket)
    try:
        # Get session from database
        query = scan_sessions_table.select().where(scan_sessions_table.c.id == session_id)
        result = await database.fetch_one(query)
        
        if not result:
            await manager.send_personal_message("❌ Session not found", websocket)
            return

        session_dict = dict(result)
        session_dict['probes'] = json.loads(session_dict['probes'])

        # Update session status
        update_query = scan_sessions_table.update().where(
            scan_sessions_table.c.id == session_id
        ).values(status="running")
        await database.execute(update_query)

        # Run the scan based on tool type
        if session_dict["tool"] == "garak":
            success, error = await run_garak_scan(
                session_dict["environment"],
                session_dict["model_name"],
                session_dict["probes"],
                websocket
            )
        elif session_dict["tool"] == "promptmap":
            success, error = await run_promptmap_scan(
                session_dict["environment"],
                session_dict["model_name"],
                websocket
            )
        else:
            success, error = False, f"Unknown tool: {session_dict['tool']}"

        # Update session status
        status = "completed" if success else "failed"
        update_values = {
            "status": status,
            "completed_at": datetime.utcnow()
        }
        if error:
            update_values["error_message"] = error

        update_query = scan_sessions_table.update().where(
            scan_sessions_table.c.id == session_id
        ).values(**update_values)
        await database.execute(update_query)

    except WebSocketDisconnect:
        manager.disconnect(websocket)
        # Update session status to failed
        update_query = scan_sessions_table.update().where(
            scan_sessions_table.c.id == session_id
        ).values(status="failed", error_message="WebSocket disconnected")
        await database.execute(update_query)
    except Exception as e:
        await manager.send_personal_message(f"❌ Error: {str(e)}", websocket)
        # Update session status to failed
        update_query = scan_sessions_table.update().where(
            scan_sessions_table.c.id == session_id
        ).values(status="failed", error_message=str(e))
        await database.execute(update_query)

@api_router.post("/status", response_model=StatusCheck)
async def create_status_check(input: StatusCheckCreate):
    status_obj = StatusCheck(client_name=input.client_name)
    query = status_checks_table.insert().values(
        id=status_obj.id,
        client_name=status_obj.client_name,
        timestamp=status_obj.timestamp
    )
    await database.execute(query)
    return status_obj

@api_router.get("/status", response_model=List[StatusCheck])
async def get_status_checks():
    query = status_checks_table.select()
    results = await database.fetch_all(query)
    return [StatusCheck(**dict(row)) for row in results]

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database connection events
@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8005)