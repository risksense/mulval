FROM ubuntu:15.04
MAINTAINER Christian Romano <christian.romano@risksense.com>

# Set MySQL credentials
RUN echo mysql-server mysql-server/root_password password root | debconf-set-selections && \
  echo mysql-server mysql-server/root_password_again password root | debconf-set-selections

# Install managed dependencies
RUN apt-get update && apt-get install -y \
  autoconf \
  bison \
  flex \
  g++ \
  graphviz \
  libpcre3 \
  libpcre3-dev \
  libcurl3 \
  libcurl4-openssl-dev \
  make \
  mysql-server \
  openjdk-8-jdk \
  texlive-font-utils \
  vim \
  wget \
&& apt-get clean \
&& rm -rf /var/lib/apt/lists/*

# Copy jni_md.h to new location (this resolvfes file not found warning for XSB)
WORKDIR /usr/lib/jvm/java-8-openjdk-amd64/include
RUN cp linux/jni_md.h .

# Set JAVA_HOME for XSB
ENV JAVA_HOME /usr/lib/jvm/java-8-openjdk-amd64

# Install XSB
WORKDIR /root
RUN wget http://xsb.sourceforge.net/downloads/XSB360.tar.gz && \
  tar -xzf XSB360.tar.gz && \
  rm XSB360.tar.gz
WORKDIR /root/XSB/build
RUN ./configure && ./makexsb
ENV PATH ${PATH}:/root/XSB/bin/

# Install MulVAL
WORKDIR /root
RUN mkdir mulval && \
  mkdir mulval/bin && \
  mkdir mulval/bin/adapter && \
  mkdir mulval/bin/metrics
ADD mulval.tar.gz /root/mulval/
WORKDIR /root/mulval
ENV MULVALROOT /root/mulval/
ENV PATH ${PATH}:${MULVALROOT}/bin:${MULVALROOT}/utils
RUN make

# Create and populate mysql database with vulnerability data
WORKDIR /root
RUN echo "jdbc:mysql://localhost:3306/nvd\nroot\nroot" > \
  config.txt
RUN echo "#!/usr/bin/env bash" > \
  createDatabase.bash && \
  echo 'service mysql restart\nsleep 5\nmysql -uroot -proot -e "create database nvd"' >> \
  createDatabase.bash && \
  echo "nvd_sync.sh\nexit 0" >> \
  createDatabase.bash && \
  chmod +x createDatabase.bash && \
  ./createDatabase.bash
RUN echo "#!/usr/bin/env bash" > \
  startSql.bash && \
  echo "service mysql start\nexit 0" >> \
  startSql.bash && \
  chmod +x startSql.bash

# Create the input directory
RUN mkdir /input && cp /root/config.txt /input/
WORKDIR /input
VOLUME ["/input"]

# Run script to start mysql service and exit to bash
CMD bash -C '/root/startSql.bash';'bash'

