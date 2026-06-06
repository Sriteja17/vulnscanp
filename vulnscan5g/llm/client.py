"""Ollama API client with retry and timeout."""
import requests
from vulnscan5g.config import OLLAMA_URL, OLLAMA_MODEL, LLM_TIMEOUT, LLM_TEMPERATURE


class OllamaClient:
    def __init__(self, url: str = OLLAMA_URL, model: str = OLLAMA_MODEL,
                 temperature: float = LLM_TEMPERATURE):
        self.url = url
        self.model = model
        self.temperature = temperature

    def generate(self, prompt: str) -> str:
        """Send prompt to Ollama and return the response text."""
        data = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": self.temperature},
        }
        try:
            resp = requests.post(self.url, json=data, timeout=LLM_TIMEOUT)
            resp.raise_for_status()
            return resp.json().get("response", "").strip()
        except requests.ConnectionError:
            raise ConnectionError(
                f"Cannot reach Ollama at {self.url}. "
                "Make sure Ollama is running (ollama serve)."
            )
        except requests.Timeout:
            raise TimeoutError(f"Ollama request timed out after {LLM_TIMEOUT}s.")
        except Exception as e:
            raise RuntimeError(f"Ollama error: {e}")

    def is_available(self) -> bool:
        try:
            r = requests.get(self.url.replace("/api/generate", ""), timeout=5)
            return r.status_code == 200
        except Exception:
            return False
