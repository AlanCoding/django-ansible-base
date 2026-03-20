FROM quay.io/centos/centos:stream9

RUN sed -i '/^\[crb\]$/,/^enabled=0$/ s/enabled=0/enabled=1/' /etc/yum.repos.d/centos.repo
RUN dnf -y install \
    python3.12 \
    python3.12-pip \
    python3.12-devel \
    gcc \
    openldap-devel \
    xmlsec1 \
    xmlsec1-openssl \
    xmlsec1-devel \
    libtool-ltdl-devel \
    libpq-devel \
    libpq \
    postgresql

# Create /etc/ansible-automation-platform/testapp folder
RUN mkdir -p /etc/ansible-automation-platform/testapp
# add settings.yaml to /etc/ansible-automation-platform/
COPY test_app/example_files/*.yaml /etc/ansible-automation-platform/testapp/

RUN python3.12 -m venv /venv

COPY requirements/requirements_all.txt /tmp/requirements_all.txt
RUN /venv/bin/pip install -r /tmp/requirements_all.txt

COPY requirements/requirements_dev.txt /tmp/requirements_dev.txt
RUN /venv/bin/pip install -r /tmp/requirements_dev.txt

# Install OPA binary
ARG OPA_VERSION=1.4.2
RUN curl -L -o /usr/local/bin/opa \
    "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_amd64_static" \
    && chmod +x /usr/local/bin/opa
