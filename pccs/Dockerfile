FROM intel/pccs:v2.3

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends jq \
    && rm -rf /var/lib/apt/lists/*

USER pccs

COPY ./ssl_key/ ./ssl_key/
COPY ./pccs.config.json /opt/intel/pccs/config/template.json
COPY ./entrypoint.sh /

ENTRYPOINT [ "/entrypoint.sh" ]