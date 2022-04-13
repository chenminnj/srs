############################################################
# dist
############################################################
FROM ubuntu:focal-20210609 AS dist
# RTMP/1935, API/1985, HTTP/8080
EXPOSE 1935 1985 8080 8000 10080

# For SRS Log Rotate
ARG DEBIAN_FRONTEND=noninteractive
ARG DEBCONF_NOWARNINGS="yes"
RUN apt-get update
RUN apt-get install -y --no-install-recommends --no-install-suggests cron logrotate

RUN mkdir -p /usr/local/srs/objs
#ADD objs/nginx /usr/local/srs/objs/nginx
COPY research/api-server/static-dir/index.html /usr/local/srs/objs/nginx/html/
COPY research/api-server/static-dir/favicon.ico /usr/local/srs/objs/nginx/html/
COPY research/api-server/static-dir/crossdomain.xml /usr/local/srs/objs/nginx/html/
COPY research/console /usr/local/srs/objs/nginx/html/console
COPY research/players /usr/local/srs/objs/nginx/html/players
COPY 3rdparty/signaling/www/demos /usr/local/srs/objs/nginx/html/demos

# FFMPEG 4.1
#COPY --from=build /usr/local/bin/ffmpeg /usr/local/srs/objs/ffmpeg/bin/ffmpeg
# SRS binary, config files and srs-console.
COPY objs/srs /usr/local/srs/objs/
# Use docker.conf as default config.
#COPY conf /usr/local/srs/conf
# Default workdir and command.

# Add script for starting SRS with logrotate
COPY scripts/start.sh /usr/local/srs/

WORKDIR /usr/local/srs
ENTRYPOINT ["/usr/local/srs/start.sh"]