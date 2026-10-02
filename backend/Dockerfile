FROM python:3.11-slim

WORKDIR /workspace

# Install system dependencies: tshark for packet inspection, build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    libpcap-dev \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install CPU-only PyTorch first to keep final Docker image < 1 GB (P2-3)
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

# Install remaining Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend codebase
COPY backend/ ./backend/
COPY captures/ ./captures/

# Create runtime directories
RUN mkdir -p /workspace/backend/uploads /workspace/backend/stored_results /workspace/backend/generated_reports /workspace/captures

EXPOSE 8000

ENV PYTHONUNBUFFERED=1

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
