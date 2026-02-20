FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml /app/
RUN pip install --no-cache-dir -U pip && pip install --no-cache-dir .

# semgrep optional
RUN pip install --no-cache-dir semgrep

COPY vsh /app/vsh
ENTRYPOINT ["vsh"]
