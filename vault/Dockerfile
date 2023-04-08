FROM gramineproject/gramine:v1.4

RUN curl -sSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor > /usr/share/keyrings/hashicorp-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com focal main" > /etc/apt/sources.list.d/hashicorp.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends libsgx-dcap-default-qpl vault \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/

COPY ./sgx_default_qcnl.conf /etc/
COPY ./plugins/ ./plugins/
COPY ./premain-vault ./vault.manifest.template ./config.hcl ./entrypoint.sh ./

RUN gramine-sgx-gen-private-key \
    && gramine-manifest -Darch_libdir=/lib/x86_64-linux-gnu vault.manifest.template vault.manifest \
    && gramine-sgx-sign --manifest vault.manifest --output vault.manifest.sgx

VOLUME /data/
EXPOSE 8200/tcp

ENTRYPOINT [ "./entrypoint.sh" ]
