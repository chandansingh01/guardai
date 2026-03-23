FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml .
COPY src/ src/
COPY templates/ templates/
COPY static/ static/

RUN pip install --no-cache-dir .

EXPOSE 5000

CMD ["python", "-m", "src.api.app"]
