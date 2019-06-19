FROM mattrayner/lamp:latest-1604

RUN apt update
RUN apt-get install -y php7.3-gmp

CMD ["/run.sh"]