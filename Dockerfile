FROM node:9.10.1
MAINTAINER TzLibre "tzlibre@mail.com"

COPY lib.js /tmp/lib.js
COPY package.json /tmp/package.json
COPY Makefile /tmp/Makefile
WORKDIR /tmp/
RUN npm install
RUN npm install -g browserify@16.1.1
CMD make lib
