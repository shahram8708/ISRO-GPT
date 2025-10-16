## 1. Project Title
ISRO-GPT · Retrieval-Augmented Mission Copilot with Web, WhatsApp, and Android Touchpoints

## 2. Project Overview / Description
ISRO-GPT is a Flask-based conversational assistant designed around MOSDAC (Meteorological & Oceanographic Satellite Data Archival Centre) knowledge workflows. It blends Retrieval-Augmented Generation (RAG), local document understanding, and conversational UX to help ISRO researchers, students, and citizen scientists interrogate satellite documentation, run mission briefings, and collaborate securely. The platform spans a responsive web app, Twilio-powered WhatsApp interface, and downloadable Android client, all backed by Python services, HTML/CSS/JS front-end templates, and third-party APIs.

## 3. Key Features
- **Conversational Mission Workspace**
  - Persistent chats with Markdown rendering, attachments, image previews, PDF ingestion, and inline citations from the RAG pipeline.
  - Speech recognition for voice entry and browser-based text-to-speech playback of AI answers.
  - Quick feedback controls (like/dislike) with optional reasoning capture.
- **Retrieval-Augmented Intelligence**
  - DuckDuckGo search + asynchronous content fetching (local_search.py).
  - HTML readability, language filtering, chunked indexing via Whoosh, and llama.cpp/Ollama LLM abstraction (rag_pipeline.py, llm_inference.py, retriever.py).
  - Cached MOSDAC news harvesting with structured storage in `mosdac_updates` table.
- **Collaboration & Sharing**
  - Chat ownership, editor roles, invitations, shareable read-only links, and PDF transcript exports.
  - OTP-gated user registration, login via email or username, password reset flows, and admin seeding (`/setup_admin`).
- **Multi-channel Access**
  - Twilio WhatsApp webhook with attachment handling, PDF text extraction, markdown sanitization, and response length limits.
  - Android APK download surfaced on the dashboard.
- **Administration & Analytics**
  - Admin dashboard with user/chat/message totals and Chart.js visualization.
  - User management table with delete controls (self-protection for current admin).
- **Engagement & Support Content**
  - Rich static pages (`about`, `support`, `terms`, `privacy`, `contact`) describing mission context, onboarding tutorials, and trust policies.
  - Contact form with query categorization, char-count guidance, and Flask-Mail delivery to configured admin email.
- **Utilities & Infrastructure**
  - Configurable environment defaults (config.py), SQLite by default, optional env-based overrides.
  - CSRF protection, Flask-Migrate bootstrap, SQLAlchemy models, password hashing, and an LRU cache helper (cache_utils.py).
  - Requirements pinned in requirements.txt, covering web, AI, PDF, search, and optional fastapi/langchain tooling.

## 4. Project Architecture / File Structure
- app.py: Central Flask application factory, route definitions, Twilio + RAG initialization, messaging orchestration, OTP flows, admin tools, sharing, exports, and static page routing.
- config.py: Environment-driven configuration (secret key, DB URL, mail, Twilio, RAG, LLM parameters, upload limits).
- extensions.py: Flask extension singletons (`db`, `login_manager`, `csrf`, `migrate`).
- models.py: SQLAlchemy models (`User`, `Chat`, `Message`, `ChatParticipant`, `ShareLink`, `MosdacUpdate`) with relationships and helpers.
- forms.py: Flask-WTF forms for registration, login, and contact submissions.
- rag_pipeline.py, local_search.py, llm_inference.py, retriever.py, cache_utils.py: Retrieval, LLM interface, caching, and search orchestration.
- templates: Comprehensive Jinja2 templates (base layout, dashboard UI, chat surfaces, static informational pages, modal dialogs).
- styles.css: Custom styling on top of Bootstrap.
- chat.js: Client-side chat logic (fetch submission, previews, speech, TTS, feedback, search filtering).
- admin.js: Placeholder for future admin interactivity.
- ISRO-GPT.apk: Packaged Android client.
- uploads: Runtime storage for uploaded media and PDFs.
- requirements.txt: Dependency manifest.
- __init__.py: Exposes `create_app` for WSGI entrypoints.

## 5. Installation & Setup Instructions
1. **Prerequisites**
   - Python 3.10+ (recommended for llama-cpp compatibility).
   - `pip`, `virtualenv`, and optionally `make`.
   - C++ toolchain if compiling `llama-cpp-python`.
   - Twilio account (WhatsApp sandbox), SMTP credentials, and (optionally) local LLM binaries.
2. **Clone & Environment**
   ```powershell
   git clone https://github.com/shahram8708/ISRO-GPT.git
   cd ISRO-GPT
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install --upgrade pip
   pip install -r requirements.txt
   ```
3. **Environment Variables (`.env` recommended)**
   - Core: `SECRET_KEY`, `DATABASE_URL` (defaults to `sqlite:///isro-gpt.db`), `UPLOAD_FOLDER`.
   - Email: `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USE_TLS/SSL`, `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_DEFAULT_SENDER`, `ADMIN_EMAIL`.
   - Twilio WhatsApp: `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_WHATSAPP_NUMBER` (defaults provided but should be replaced).
   - RAG Search: `SEARCH_MAX_RESULTS`, `SEARCH_SAFE_MODE`, `SEARCH_REGION`, `SEARCH_ALLOWED_LANGS`.
   - LLM: `LLM_BACKEND` (`llama_cpp` or `ollama`), `LLAMA_CPP_MODEL_PATH`, `LLAMA_CPP_N_CTX`, `LLAMA_CPP_N_THREADS`, `LLM_TEMPERATURE`, `LLM_MAX_OUTPUT_TOKENS`, `LLM_MODEL_URL`, `LLM_MODEL_SHA256`, `OLLAMA_BASE_URL`, `OLLAMA_MODEL`.
   - WhatsApp reply caps: `WHATSAPP_MAX_WORDS`, `WHATSAPP_MAX_CHARACTERS`.
4. **Database Initialization**
   ```powershell
   flask db upgrade  # Requires FLASK_APP=app.py or equivalent
   ```
   or rely on `db.create_all()` invoked in `create_app()` for SQLite prototyping.
5. **Run Server**
   ```powershell
   flask run --debug
   ```
   or `python app.py` for the built-in development server (`0.0.0.0`, reload disabled).
6. **Optional Assets**
   - Place additional static media under image.
   - Ensure uploads is writable for attachments.
   - If using llama.cpp, download/verify GGUF model to configured path (auto-download supported when `LLM_MODEL_URL` & checksum set).

## 6. Usage Guide
- **Web App**
  - Visit `http://localhost:5000`.
  - Register with OTP (email must be reachable); login via email or username.
  - Use dashboard widgets for quick navigation, MOSDAC updates, prompt inspiration, and activity overview.
  - Start chats, attach files, speak queries, listen to answers, invite collaborators, and export transcripts.
- **WhatsApp Integration**
  - Ensure Twilio sandbox is configured with webhook pointing to `/integrations/whatsapp`.
  - Send messages (text/images/PDF) to the WhatsApp sandbox number; AI replies respect configured word/character limits.
- **Android App**
  - Download ISRO-GPT.apk, sideload onto device, and connect to the same backend URL.
- **Admin Console**
  - Seed admin via `/setup_admin` (returns generated/updated credentials).
  - Access `/admin` for stats and `/admin/users` for management.
- **Support/Documentation**
  - Explore `/support` for onboarding guides, tutorials, FAQ.
  - `/about`, `/terms`, `/privacy`, `/contact` provide mission context and governance details.

## 7. Technical Details
- **Backend**
  - Flask (app.py) with SQLAlchemy ORM, Flask-Login, Flask-WTF, Flask-Mail, Flask-Migrate.
  - SQLite default; configurable to PostgreSQL/MySQL via `SQLALCHEMY_DATABASE_URI`.
  - OTP email via Gmail defaults (replace with production account).
  - Twilio REST SDK for WhatsApp inbound/outbound handling.
  - PDF handling with `pdfplumber` (text extraction) and `xhtml2pdf`/`reportlab` for exports; `mistune` Markdown conversion.
- **RAG Pipeline**
  - local_search.py: DuckDuckGo text search via `duckduckgo-search` with caching and URL normalization.
  - Async fetching (httpx) + readability + BeautifulSoup cleaning.
  - Optional language filtering (`langdetect`).
  - retriever.py: In-memory Whoosh indexing with token-overlap chunking and BM25 scoring.
  - llm_inference.py: Backend abstraction; supports `llama_cpp` (local GGUF) or `ollama` via REST.
  - rag_pipeline.py: Orchestrates end-to-end flow, caches responses, constructs prompts with context citations.
- **Frontend**
  - Bootstrap 5, Font Awesome, Marked.js for Markdown rendering.
  - chat.js: Handles message submission, optimistic “thinking” bubble, attachments preview, clipboard, speech recognition (Web Speech API), audio playback, inline feedback, and sidebar search.
  - styles.css: Chat bubble theming, attachment grids, animations, global overrides.
  - Templates use Jinja with base layout injecting SEO/meta tags, navigation, flash messages.
- **Data Flow**
  - User message stored ➜ attachments persisted ➜ optional PDF text appended ➜ RAG pipeline executed ➜ AI answer stored with sources ➜ response rendered and optionally sanitized (WhatsApp).
  - MOSDAC refresh routes run RAG prompt to fetch JSON, persisted to DB, surfaced on dashboard.
  - Sessions track OTP verification states; CSRF tokens embedded per request.

## 8. All Features Summary (A–Z)
- **__init__.py**: Exposes `create_app`.
- **app.py**
  - App factory initializes DB, login manager, CSRF, migrations, Mail, Twilio client, RAG pipeline.
  - Helpers: `allowed_file`, `persist_bytes_to_uploads`, `register_local_attachment`, `count_words`, `sanitize_whatsapp_markdown`, `process_chat_interaction`.
  - Error handlers for 403/404/500/Exception returning error.html.
  - Routes:
    - Auth: `/register`, `/login`, `/logout`, OTP send/verify, `/forgot`, `/reset_password`.
    - Dashboard & chats: `/dashboard`, `/chat/new`, `/chat/<id>`, `/chat/send/<id>`, rename/delete/search/export/invite/join/share/view.
    - Feedback: `/feedback/like`, `/feedback/dislike`.
    - MOSDAC: `/api/mosdac/updates`, `/api/mosdac/refresh` (two definitions; one CSRF-exempt).
    - Support pages: `/contact`, `/support`, `/terms`, `/about`, `/privacy`.
    - Admin: `/admin`, `/admin/users`, `/admin/delete_user/<id>`, `/setup_admin`.
    - Twilio webhook: `/integrations/whatsapp`.
  - Session permanence, anonymous safeguards, share link tokens, PDF export with Markdown rendering, duplicate `send_otp` routes (register + forgot flow).
- **cache_utils.py**: Thread-safe LRU cache class used by search and RAG.
- **config.py**: Default constants, environment overrides, Twilio values currently hard-coded (replace), LLM hints, mail defaults, upload policies.
- **extensions.py**: Central extension instances.
- **forms.py**: Registration/login/contact forms with validators and custom error messaging.
- **llm_inference.py**: `LLMClient` with `LLMConfig`, backend selection, GGUF download checksum, request timeouts, thread-safe lazy loading.
- **local_search.py**: `LocalSearchClient` performing DuckDuckGo text search with deduplication and caching.
- **models.py**: ORM models with relationships, password hashing, `to_dict` for messages and MOSDAC entries, login loader.
- **rag_pipeline.py**: `RAGPipeline` orchestrator, caching, asynchronous fetch, context builder, prompt composer.
- **retriever.py**: `WhooshRetriever` chunking, indexing, BM25 retrieval, validations.
- **requirements.txt**: Flask stack, AI/search libs, plus optional `fastapi`, `langchain`, `sentence-transformers`, `hnswlib` (unused presently).
- **Templates**
  - base.html: Global SEO meta, nav, flash UI, script includes.
  - dashboard.html: Mission widgets (Quick Access, MOSDAC updates, stats, prompt library, news, activity, dark mode toggle).
  - chat.html: Sidebar, rename/delete/export/invite/share, chat history rendering, modals for rename/dislike feedback.
  - chat_shared.html: Read-only embed with copy buttons.
  - admin.html, admin_users.html: Admin stats and table view with animations.
  - login.html, register.html, forgot.html: Forms with floating labels, OTP interactions, validation.
  - contact.html: Query form with char counter and categories.
  - support.html: Extensive onboarding documentation, tips, FAQ.
  - about.html, terms.html, privacy.html: Storytelling, policy details, dynamic styling.
  - error.html: Friendly error handling with countdown redirect.
- **Static**
  - chat.js: Core client logic (submit, attachments preview, speech recognition, TTS, copy, feedback, chat search).
  - admin.js: Reserved for future admin features.
  - styles.css: Chat styling, attachments, animations.
  - ISRO-GPT.apk: Android package download.
  - logo.png: Branding asset.

## 9. Error Handling & Validation
- Flask error handler wraps 403/404/500 and generic exceptions, rendering error.html.
- CSRF enforced globally via Flask-WTF (`generate_csrf` injected in templates); webhook routes explicitly `@csrf.exempt`.
- Form validators block duplicate usernames/emails, ensure password confirmation, message length (contact), and query type selection.
- OTP flows validate email presence, OTP match, expiration (10 minutes) before enabling subsequent fields.
- File uploads restricted by `ALLOWED_EXTENSIONS`, empty files rejected, read errors logged, PDF extraction exceptions handled gracefully.
- RAG pipeline catches search/retrieval/LLM exceptions with user-friendly fallbacks and detailed logs.
- WhatsApp replies sanitized for supported Markdown, word/character caps logged if exceeded.
- Password hashing via Werkzeug; password reset ensures matching confirmation.

## 10. Security & Permissions
- User authentication with Flask-Login, session permanence, optional “remember me”.
- Passwords stored hashed; OTP stored in server session (not database) and cleared after use.
- Role-based chat access: owners vs editors vs viewers; invites require login, share links read-only.
- Admin-only pages guard by `current_user.is_admin`; self-deletion prevented.
- CSRF tokens embedded in templates and AJAX headers; Twilio webhook exempt (external origin).
- Sensitive defaults in config.py (Twilio keys, Gmail credentials) must be overridden before production.
- Uploaded files saved to uploads (publicly accessible); do not store sensitive data or enforce additional ACLs if needed.
- RAG pipeline uses external web search; consider network access controls in constrained environments.

## 11. APIs / Integrations
- **REST Endpoints**
  - `GET /api/mosdac/updates`: Returns cached MOSDAC update list.
  - `POST /api/mosdac/refresh` (two definitions; one CSRF exempt): Triggers RAG fetch, updates DB, returns records.
  - `POST /chat/send/<chat_id>`: Multipart message submission with attachments; returns serialized messages + sources.
  - `GET /chat/search?q=...`: Search chats/messages for current user.
  - `GET /chat/export/<chat_id>`: PDF export stream.
  - `POST /chat/rename/<id>`, `POST /chat/delete/<id>`: Manage chats (owner only).
  - `GET /chat/share/<id>`: Creates share link (owner only).
  - `GET /chat/view/<token>`: Public read-only view.
  - `GET /chat/invite/<id>` + `GET /chat/join/<id>?token=...`: Invite flow.
  - `POST /feedback/like`, `POST /feedback/dislike`: Capture feedback.
  - OTP & password reset endpoints (`/send_otp`, `/verify_otp`, `/reset_password`).
  - Admin management routes.
- **Integrations**
  - Twilio WhatsApp webhook (`POST /integrations/whatsapp`): Validates sender, fetches media from Twilio, stores attachments, calls RAG, returns sanitized reply using TwiML.
  - Flask-Mail: Sends OTPs and contact form messages via configured SMTP.
  - LLM backends: local llama.cpp (GGUF) or remote Ollama.
  - DuckDuckGo Search via `duckduckgo_search`.
  - Android APK distribution via static file.

## 12. Future Enhancements / Roadmap
- Consolidate the duplicated `/api/mosdac/refresh` route definitions (resolve CSRF strategy and avoid shadowing).
- Harden file storage (private buckets, signed URLs) and enforce virus scanning for uploads.
- Finish admin.js with live metrics (e.g., websockets, filtering).
- Add unit/integration tests (e.g., pytest + coverage) for core flows (OTP, chat messaging, RAG fallback logic).
- Introduce rate limiting and captcha for OTP endpoints to prevent abuse.
- Support rich source rendering (inline citations with anchor links in chat UI).
- Parameterize word/character limits per channel; add UI warnings if AI reply truncated.
- Expand LLM backend support (OpenAI, Azure) and allow per-user model selection.
- Provide CLI or Celery tasks for scheduled MOSDAC refresh.
- Document/how-to for deploying behind production-grade WSGI (gunicorn/uvicorn) and HTTPS.

## 13. Contributors / Credits
- Core development by the ISRO-GPT team (repository owner: `shahram8708`) with inspiration from MOSDAC Vikas Saptah Hackathon.
- Community mentions throughout templates (scientists, AI engineers, design researchers) acknowledge collaborative inputs.

## 14. License (if applicable)
No license defined in this repository. All rights reserved by the authors; contact maintainers for usage terms.

## 15. Contact / Support Information
- Primary support email: `multimosaic.help@gmail.com` (configurable via `ADMIN_EMAIL`).
- Additional contact showcased in UI: `hello@isrogpt.in`.
- Support resources: `/support` (tutorials, FAQ), `/contact` (form submission), social links in `about` page.
- Twilio WhatsApp sandbox instructions provided in dashboard widget for quick demos.