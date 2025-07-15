import React, { useState, useEffect, useRef } from "react";
import "./App.css";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import axios from "axios";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const ScanWizard = () => {
  const [currentStep, setCurrentStep] = useState(1);
  const [environments, setEnvironments] = useState([]);
  const [models, setModels] = useState([]);
  const [probes, setProbes] = useState([]);
  const [selectedEnvironment, setSelectedEnvironment] = useState("");
  const [selectedModel, setSelectedModel] = useState("");
  const [selectedTool, setSelectedTool] = useState("");
  const [selectedProbes, setSelectedProbes] = useState([]);
  const [promptmapDirectory, setPromptmapDirectory] = useState("");
  const [scanSession, setScanSession] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanOutput, setScanOutput] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const wsRef = useRef(null);
  const outputRef = useRef(null);

  useEffect(() => {
    loadInitialData();
  }, []);

  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [scanOutput]);

  const loadInitialData = async () => {
    setLoading(true);
    try {
      const [envResponse, modelResponse, probeResponse] = await Promise.all([
        axios.get(`${API}/environments`),
        axios.get(`${API}/models`),
        axios.get(`${API}/probes`)
      ]);
      setEnvironments(envResponse.data.environments);
      setModels(modelResponse.data.models);
      setProbes(probeResponse.data.probes);
    } catch (err) {
      setError("Failed to load initial data: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleProbeSelection = (probe) => {
    setSelectedProbes(prev =>
      prev.includes(probe)
        ? prev.filter(p => p !== probe)
        : [...prev, probe]
    );
  };

  const startScan = async () => {
    if (!selectedEnvironment || !selectedModel || !selectedTool) {
      setError("Please select environment, model, and tool");
      return;
    }

    if (selectedTool === "garak" && selectedProbes.length === 0) {
      setError("Please select at least one probe for Garak");
      return;
    }

    if (selectedTool === "promptmap" && !promptmapDirectory.trim()) {
      setError("Please enter the Promptmap directory path");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const scanData = {
        environment: selectedEnvironment,
        model_name: selectedModel,
        tool: selectedTool.toLowerCase()
      };

      // Add probes if Garak is selected
      if (selectedTool === "garak") {
        scanData.probes = selectedProbes;
      } else {
        scanData.probes = []; // Empty array for promptmap
      }

      // Add promptmap directory if Promptmap is selected
      if (selectedTool === "promptmap") {
        scanData.promptmap_directory = promptmapDirectory;
      }

      const response = await axios.post(`${API}/scan`, scanData);
      setScanSession(response.data);
      setCurrentStep(4);
      connectWebSocket(response.data.session_id);
    } catch (err) {
      setError("Failed to start scan: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  const connectWebSocket = (sessionId) => {
    const wsUrl = `${BACKEND_URL.replace('http', 'ws')}/api/ws/scan/${sessionId}`;
    wsRef.current = new WebSocket(wsUrl);

    wsRef.current.onopen = () => {
      setIsScanning(true);
      setScanOutput([]);
    };

    wsRef.current.onmessage = (event) => {
      setScanOutput(prev => [...prev, event.data]);
    };

    wsRef.current.onclose = () => {
      setIsScanning(false);
    };

    wsRef.current.onerror = (error) => {
      setError("WebSocket error: " + error.message);
      setIsScanning(false);
    };
  };

  const nextStep = () => {
    if (currentStep < 4) {
      setCurrentStep(currentStep + 1);
    }
  };

  const prevStep = () => {
    if (currentStep > 1) {
      setCurrentStep(currentStep - 1);
    }
  };

  const resetWizard = () => {
    setCurrentStep(1);
    setSelectedEnvironment("");
    setSelectedModel("");
    setSelectedTool("");
    setSelectedProbes([]);
    setScanSession(null);
    setIsScanning(false);
    setScanOutput([]);
    setError("");
    if (wsRef.current) {
      wsRef.current.close();
    }
  };

  const renderStep = () => {
    switch (currentStep) {
      case 1:
        return (
          <div className="step-content">
            <h2 className="step-title">🤖 Select LLM Model</h2>
            <p className="step-description">Choose the model to test for vulnerabilities</p>
            {loading ? (
              <div className="loading">Loading models...</div>
            ) : (
              <div className="selection-grid">
                {models.map(model => (
                  <div
                    key={model}
                    className={`selection-card ${selectedModel === model ? 'selected' : ''}`}
                    onClick={() => setSelectedModel(model)}
                  >
                    <div className="selection-icon">🧠</div>
                    <div className="selection-name">{model}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        );

      case 2:
        return (
          <div className="step-content">
            <h2 className="step-title">🔧 Select Environment</h2>
            <p className="step-description">Choose the conda environment where the tools are installed</p>
            {loading ? (
              <div className="loading">Loading environments...</div>
            ) : (
              <div className="selection-grid">
                {environments.map(env => (
                  <div
                    key={env}
                    className={`selection-card ${selectedEnvironment === env ? 'selected' : ''}`}
                    onClick={() => setSelectedEnvironment(env)}
                  >
                    <div className="selection-icon">🐍</div>
                    <div className="selection-name">{env}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        );

      case 3:
        return (
          <div className="step-content">
            <h2 className="step-title">🛠️ Select Tool</h2>
            <p className="step-description">Choose the vulnerability testing tool</p>
            
            <div className="selection-grid">
              <div
                className={`selection-card ${selectedTool === 'garak' ? 'selected' : ''}`}
                onClick={() => setSelectedTool('garak')}
              >
                <div className="selection-icon">🔍</div>
                <div className="selection-name">Garak</div>
              </div>
              <div
                className={`selection-card ${selectedTool === 'promptmap' ? 'selected' : ''}`}
                onClick={() => setSelectedTool('promptmap')}
              >
                <div className="selection-icon">🗺️</div>
                <div className="selection-name">Promptmap</div>
              </div>
            </div>

            {selectedTool === 'garak' && (
              <div className="probe-selection">
                <h3 className="probe-title">🔍 Select Probes</h3>
                <p className="step-description">Choose the vulnerability probes to run</p>
                <div className="probe-stats">
                  Selected: {selectedProbes.length} / {probes.length}
                </div>
                <div className="probe-grid">
                  {probes.map(probe => (
                    <div
                      key={probe}
                      className={`probe-card ${selectedProbes.includes(probe) ? 'selected' : ''}`}
                      onClick={() => handleProbeSelection(probe)}
                    >
                      <div className="probe-name">{probe}</div>
                      <div className="probe-checkbox">
                        {selectedProbes.includes(probe) ? '✅' : '⬜'}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        );

      case 4:
        return (
          <div className="step-content">
            <h2 className="step-title">⚡ Running Scan</h2>
            <div className="scan-info">
              <div className="scan-details">
                <p><strong>Model:</strong> {selectedModel}</p>
                <p><strong>Environment:</strong> {selectedEnvironment}</p>
                <p><strong>Tool:</strong> {selectedTool}</p>
                {selectedTool === 'garak' && (
                  <p><strong>Probes:</strong> {selectedProbes.join(", ")}</p>
                )}
              </div>
              <div className="scan-status">
                {isScanning ? (
                  <div className="scanning-indicator">
                    <div className="spinner"></div>
                    <span>Scanning in progress...</span>
                  </div>
                ) : (
                  <div className="scan-complete">
                    <span>✅ Scan completed</span>
                  </div>
                )}
              </div>
            </div>
            <div className="terminal-output" ref={outputRef}>
              {scanOutput.map((line, index) => (
                <div key={index} className="terminal-line">
                  {line}
                </div>
              ))}
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className="wizard-container">
      <div className="wizard-header">
        <h1>🛡️ LLM Vulnerability Scanner</h1>
        <div className="progress-bar">
          {[1, 2, 3, 4].map(step => (
            <div
              key={step}
              className={`progress-step ${currentStep >= step ? 'active' : ''}`}
            >
              {step}
            </div>
          ))}
        </div>
      </div>

      <div className="wizard-body">
        {error && (
          <div className="error-message">
            ❌ {error}
          </div>
        )}
        {renderStep()}
      </div>

      <div className="wizard-footer">
        <button
          className="btn btn-secondary"
          onClick={prevStep}
          disabled={currentStep === 1 || isScanning}
        >
          Previous
        </button>

        {currentStep < 3 && (
          <button
            className="btn btn-primary"
            onClick={nextStep}
            disabled={
              (currentStep === 1 && !selectedModel) ||
              (currentStep === 2 && !selectedEnvironment) ||
              loading
            }
          >
            Next
          </button>
        )}

        {currentStep === 3 && (
          <button
            className="btn btn-success"
            onClick={startScan}
            disabled={
              !selectedTool || 
              (selectedTool === 'garak' && selectedProbes.length === 0) ||
              loading
            }
          >
            {loading ? 'Starting...' : 'Start Scan'}
          </button>
        )}

        {currentStep === 4 && !isScanning && (
          <button
            className="btn btn-primary"
            onClick={resetWizard}
          >
            New Scan
          </button>
        )}
      </div>
    </div>
  );
};

const Home = () => {
  return <ScanWizard />;
};

function App() {
  return (
    <div className="App">
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Home />} />
        </Routes>
      </BrowserRouter>
    </div>
  );
}

export default App;