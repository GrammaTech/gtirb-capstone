FROM ubuntu:18.04

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
    unzip \
    wget

RUN python3 -m pip install --upgrade pip && \
    python3 -m pip install pkginfo pre-commit requests wheel tox twine

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
WORKDIR /gt/gtirb-capstone
RUN git init
COPY .pre-commit-config.yaml /gt/gtirb-capstone/.pre-commit-config.yaml
RUN pre-commit install-hooks
