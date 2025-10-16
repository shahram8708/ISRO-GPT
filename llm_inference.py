"""Local LLM integration for the ISRO-GPT RAG pipeline."""
from __future__ import annotations

import logging
import hashlib
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import requests

try:  # Import lazily so the module can load even if llama-cpp is absent during linting.
    from llama_cpp import Llama  # type: ignore
except Exception:  # noqa: BLE001 - optional dependency at runtime
    Llama = None  # type: ignore[assignment]


class LLMInferenceError(Exception):
    """Raised when the local LLM pipeline fails to produce an answer."""


@dataclass
class LLMConfig:
    backend: str
    llama_model_path: Optional[str]
    llama_n_ctx: int
    llama_n_threads: Optional[int]
    temperature: float
    max_output_tokens: int
    ollama_base_url: str
    ollama_model: Optional[str]
    request_timeout: float


class LLMClient:
    """Wrapper around llama.cpp or Ollama for chat-style inference."""

    def __init__(self, config: dict, logger: Optional[logging.Logger] = None) -> None:
        self.logger = logger or logging.getLogger(__name__)
        self._config = config

        backend = (config.get("LLM_BACKEND") or "llama_cpp").strip().lower()
        llama_model_path = config.get("LLAMA_CPP_MODEL_PATH") or None
        llama_n_ctx = int(config.get("LLAMA_CPP_N_CTX", 4096))
        llama_n_threads_raw = config.get("LLAMA_CPP_N_THREADS")
        llama_n_threads = int(llama_n_threads_raw) if llama_n_threads_raw else None
        temperature = float(config.get("LLM_TEMPERATURE", 0.2))
        max_output_tokens = int(config.get("LLM_MAX_OUTPUT_TOKENS", 512))
        ollama_base_url = config.get("OLLAMA_BASE_URL") or "http://localhost:11434"
        ollama_model = config.get("OLLAMA_MODEL") or None
        request_timeout = float(config.get("LLM_REQUEST_TIMEOUT", 120))

        self._cfg = LLMConfig(
            backend=backend,
            llama_model_path=llama_model_path,
            llama_n_ctx=llama_n_ctx,
            llama_n_threads=llama_n_threads,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
            ollama_base_url=ollama_base_url.rstrip("/"),
            ollama_model=ollama_model,
            request_timeout=request_timeout,
        )

        self._llama: Optional[Llama] = None  # type: ignore[assignment]
        self._model_lock = threading.Lock()
        self._model_prepared = False

        if self._cfg.backend not in {"llama_cpp", "ollama"}:
            self.logger.warning(
                "Unsupported LLM backend '%s'; defaulting to llama_cpp.", self._cfg.backend
            )
            self._cfg.backend = "llama_cpp"

        if self._cfg.backend == "llama_cpp":
            self._prepare_llama_model()

    def _ensure_llama(self):
        if self._cfg.backend != "llama_cpp":
            raise LLMInferenceError("llama.cpp backend is not active.")
        if not self._cfg.llama_model_path:
            raise LLMInferenceError("LLAMA_CPP_MODEL_PATH is not configured.")
        if Llama is None:
            raise LLMInferenceError(
                "llama_cpp-python is not available. Ensure the package is installed."
            )
        if not self._model_prepared:
            self._prepare_llama_model()
        if self._llama is None:
            try:
                self.logger.info(
                    "Loading llama.cpp model from %s (n_ctx=%s, n_threads=%s)",
                    self._cfg.llama_model_path,
                    self._cfg.llama_n_ctx,
                    self._cfg.llama_n_threads,
                )
                self._llama = Llama(
                    model_path=self._cfg.llama_model_path,
                    n_ctx=self._cfg.llama_n_ctx,
                    n_threads=self._cfg.llama_n_threads,
                    logits_all=False,
                    embedding=False,
                )
            except Exception as exc:  # noqa: BLE001 - upstream errors can vary
                raise LLMInferenceError(f"Failed to load llama.cpp model: {exc}") from exc
        return self._llama

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        """Generate a response using the configured LLM backend."""
        system_prompt = (system_prompt or "").strip()
        user_prompt = (user_prompt or "").strip()
        if not user_prompt:
            raise LLMInferenceError("User prompt cannot be empty.")

        if self._cfg.backend == "ollama":
            return self._generate_via_ollama(system_prompt, user_prompt)
        return self._generate_via_llama(system_prompt, user_prompt)

    def _generate_via_llama(self, system_prompt: str, user_prompt: str) -> str:
        llama = self._ensure_llama()
        try:
            response = llama.create_chat_completion(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=self._cfg.temperature,
                max_tokens=self._cfg.max_output_tokens,
            )
        except Exception as exc:  # noqa: BLE001
            raise LLMInferenceError(f"llama.cpp generation failed: {exc}") from exc

        try:
            content = response["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMInferenceError("llama.cpp returned an unexpected response format.") from exc
        if not content:
            raise LLMInferenceError("llama.cpp returned an empty response.")
        return content.strip()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _prepare_llama_model(self) -> None:
        if self._cfg.backend != "llama_cpp":
            return
        if not self._cfg.llama_model_path:
            raise LLMInferenceError("LLAMA_CPP_MODEL_PATH is not configured.")

        model_path = Path(self._cfg.llama_model_path)
        if model_path.exists():
            if self._verify_model_checksum(model_path):
                self.logger.debug("llama.cpp model already present at %s", model_path)
                self._model_prepared = True
                return
            self.logger.warning("Existing model at %s failed checksum verification. Re-downloading.", model_path)
            model_path.unlink(missing_ok=True)

        download_url = self._config.get("LLM_MODEL_URL")
        if not download_url:
            raise LLMInferenceError(
                "Model file is missing and LLM_MODEL_URL is not configured for automatic download."
            )

        model_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = model_path.with_suffix(model_path.suffix + ".tmp")

        with self._model_lock:
            if model_path.exists():
                self._model_prepared = True
                return

            self.logger.info("Downloading llama.cpp model from %s", download_url)
            try:
                with requests.get(download_url, stream=True, timeout=120) as response:
                    response.raise_for_status()
                    with open(tmp_path, "wb") as handle:
                        for chunk in response.iter_content(chunk_size=1024 * 1024):
                            if chunk:
                                handle.write(chunk)
                os.replace(tmp_path, model_path)
            except Exception as exc:  # noqa: BLE001
                if tmp_path.exists():
                    tmp_path.unlink(missing_ok=True)
                raise LLMInferenceError(f"Failed to download llama.cpp model: {exc}") from exc

            if not self._verify_model_checksum(model_path):
                model_path.unlink(missing_ok=True)
                raise LLMInferenceError("Downloaded model failed checksum verification.")

            self.logger.info("llama.cpp model downloaded to %s", model_path)
            self._model_prepared = True

    def _verify_model_checksum(self, model_path: Path) -> bool:
        expected_checksum = (self._config.get("LLM_MODEL_SHA256") or "").strip().lower()
        if not expected_checksum:
            return True
        sha256 = hashlib.sha256()
        try:
            with open(model_path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    sha256.update(chunk)
        except OSError as exc:
            self.logger.error("Failed to hash model file %s: %s", model_path, exc)
            return False
        digest = sha256.hexdigest().lower()
        if digest != expected_checksum:
            self.logger.error(
                "Model checksum mismatch: expected %s, got %s", expected_checksum, digest
            )
            return False
        return True

    def _generate_via_ollama(self, system_prompt: str, user_prompt: str) -> str:
        if not self._cfg.ollama_model:
            raise LLMInferenceError("OLLAMA_MODEL is not configured.")

        payload = {
            "model": self._cfg.ollama_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "options": {
                "temperature": self._cfg.temperature,
                "num_predict": self._cfg.max_output_tokens,
            },
        }
        try:
            response = requests.post(
                f"{self._cfg.ollama_base_url}/api/chat",
                json=payload,
                timeout=self._cfg.request_timeout,
            )
            if response.status_code >= 400:
                raise LLMInferenceError(
                    f"Ollama request failed with status {response.status_code}: {response.text[:200]}"
                )
            data = response.json()
            message = data.get("message") or {}
            content = message.get("content")
            if not content and "choices" in data:
                # Compatibility with some Ollama builds that mimic OpenAI schema.
                choices = data.get("choices")
                if isinstance(choices, list) and choices:
                    content = choices[0].get("message", {}).get("content")
            if not content:
                raise LLMInferenceError("Ollama returned an empty response.")
            return str(content).strip()
        except requests.RequestException as exc:
            raise LLMInferenceError(f"Failed to reach Ollama server: {exc}") from exc
