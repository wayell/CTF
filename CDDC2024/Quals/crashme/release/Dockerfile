FROM python:3.11-slim AS base

FROM disconnect3d/nsjail

COPY --from=base / /jail/

COPY crashMe.so /jail/crashMe.so
COPY crashMe.py /jail/crashMe.py
COPY run_py.sh /jail/run_py.sh
RUN chmod +x /jail/run_py.sh
COPY flag /jail/flag

COPY start.sh /start.sh
RUN chmod +x /start.sh

CMD [ "/start.sh" ]
