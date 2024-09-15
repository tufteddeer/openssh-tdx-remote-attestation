# intel trustauthority-cli needs ubuntu 22
FROM ubuntu:22.04

RUN apt-get update 
RUN apt-get install -y \
	curl \
	libcurl4-openssl-dev \
	libjansson-dev \
	libssl-dev \
	autoconf \
	make \
	gcc \
	zlib1g-dev \
	git \
	cmake \
	g++

RUN curl -sL https://raw.githubusercontent.com/intel/trustauthority-client-for-go/main/release/install-tdx-cli-azure.sh | CLI_VERSION=v1.4.0 bash -

# we need a newer version of libjwt than what is available in ubuntu 22
RUN git clone https://github.com/benmcollins/libjwt.git
RUN mkdir /libjwt/build
WORKDIR /libjwt/build
RUN cmake ..
RUN make install

COPY . /ra-ssh
WORKDIR /ra-ssh

RUN autoreconf
RUN ./configure
RUN make

# user for sshd privilege separation
RUN useradd -r -s /usr/sbin/nologin sshd
RUN mkdir /var/empty

# demo user:user
RUN useradd user -m -p "$(openssl passwd -1 user)"

CMD ["/ra-ssh/sshd", "-f", "/config/sshd_config", "-d"]