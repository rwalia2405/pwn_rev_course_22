FROM ubuntu:20.04
RUN apt-get update -y && apt-get install -y \
    lib32z1 xinetd \
 && rm -rf /var/lib/apt/lists/*
RUN useradd sh4dy
RUN mkdir /pwn
RUN echo "You've been blocked by our server,try again, and report if this repeats." > /etc/banner_fail
COPY ./ctf.xinetd /etc/xinetd.d/pwn
COPY ./start.sh /start.sh
COPY ./setup.sh /setup.sh
COPY ./chall /pwn/
COPY ./flag.txt /pwn/flag.txt
COPY ./ld-2.31.so /pwn/
COPY ./libc.so.6 /pwn/
RUN chown -R root:sh4dy /pwn && chmod -R 750 /pwn
RUN chmod +x /setup.sh
RUN chown root:sh4dy /start.sh && chmod 750 /start.sh

CMD ["/setup.sh"]

EXPOSE 7001