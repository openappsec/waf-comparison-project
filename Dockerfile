FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CHROME_PATH=/usr/bin/chromium

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      chromium \
      libnss3 \
      libcairo2 \
      libpango-1.0-0 \
      libpangoft2-1.0-0 \
      libpangocairo-1.0-0 \
      libgdk-pixbuf-2.0-0 \
      libharfbuzz0b \
      libfribidi0 \
      libfreetype6 \
      fontconfig \
      libjpeg62-turbo \
      libxml2 \
      libxslt1.1 \
      libffi8 \
      zlib1g \
      fonts-dejavu-core && \
    apt-get clean && rm -rf /var/lib/apt/lists/*


COPY requirements.txt .
RUN pip install --only-binary=:all: --no-compile -r requirements.txt
COPY . .

ENTRYPOINT ["python", "entrypoint.py"]
