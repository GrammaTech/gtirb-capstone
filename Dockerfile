FROM docker.grammatech.com/rewriting/gtirb/ubuntu18

RUN apt-get update \
    && apt-get -y install \
    python3 \
    python3-pip \
    python3-protobuf \
    cmake \
    clang-format \
    git \
    curl \
    sbcl \
    emacs-nox \
    slime \
    elpa-paredit \
    unzip

RUN python3 -m pip install "virtualenv<20.0.0"
RUN python3 -m pip install pre-commit wheel tox

# Install keystone
RUN cd /tmp && \
    git clone https://github.com/keystone-engine/keystone.git && \
    cd keystone && \
    mkdir build && \
    cd build && \
    ../make-share.sh && \
    make install

# Install the lisp-format pre-commit format checker.
RUN curl https://raw.githubusercontent.com/eschulte/lisp-format/master/lisp-format > /usr/bin/lisp-format
RUN chmod +x /usr/bin/lisp-format
RUN echo "(add-to-list 'load-path \"/usr/share/emacs/site-lisp/\")" > /root/.lisp-formatrc

# Install pre-commit hooks
COPY .git /gt/gtirb-capstone/.git
COPY .pre-commit-config.yaml /gt/gtirb-capstone/.pre-commit-config.yaml
WORKDIR /gt/gtirb-capstone
RUN pre-commit install-hooks
