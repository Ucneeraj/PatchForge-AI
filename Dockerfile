FROM python:3.11-slim

WORKDIR /workspace

# Install standard pytest and the json-report plugin
RUN pip install --no-cache-dir pytest pytest-json-report

CMD ["pytest"]