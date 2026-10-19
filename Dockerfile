FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ src/
COPY tests/ tests/
COPY examples/ examples/
COPY scripts/ scripts/
RUN python -m pip install --no-cache-dir -e '.[test]' \
    && python -m pip check \
    && useradd --uid 10001 --create-home researcher
USER 10001:10001

CMD ["sh", "-ec", "python scripts/check_container.py && python -m pytest -q -p no:cacheprovider && python examples/quickstart.py"]
