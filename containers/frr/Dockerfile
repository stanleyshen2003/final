FROM frrouting/frr-debian
LABEL maintainer=N0BALL

RUN echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf && \
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf

RUN echo "hostname frr\nlog file /var/log/frr/zebra.log\n!\ninterface *\nipv4 enable\nipv6 enable\n!" > /etc/frr/zebra.conf

RUN apt update -y && apt install -y iproute2 arping mtr telnet