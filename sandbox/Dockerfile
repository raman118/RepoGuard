FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
RUN pip install --no-cache-dir pytest==9.1.1 PyYAML==6.0.3
COPY sandbox/validate.py /runner/validate.py
COPY sandbox/pytest.ini /runner/pytest.ini
USER 10001:10001
WORKDIR /work
ENTRYPOINT []
