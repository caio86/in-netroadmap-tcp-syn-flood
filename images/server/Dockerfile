FROM nginx:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    procps \
    net-tools \
    iputils-ping \
    iproute2 \
    bash \
    iperf3 \
    vsftpd \
    xmlstarlet \
    ffmpeg \
    unzip \
    ethtool \
    && rm -rf /var/lib/apt/lists/*

COPY scripts /scripts

COPY vsftpd.conf /etc/vsftpd.conf
RUN mkdir -p /ftp
WORKDIR /ftp
RUN curl -o JihanGrandTheater.jpg https://upload.wikimedia.org/wikipedia/commons/thumb/1/17/Jinan_Grand_Theater-20150520-RM-170343.jpg/1920px-Jinan_Grand_Theater-20150520-RM-170343.jpg

COPY nginx.conf /etc/nginx/nginx.conf
RUN mkdir -p /usr/share/nginx/html/videos
WORKDIR /usr/share/nginx/html/videos

RUN curl -o BigBuckBunny.mp4.zip https://download.blender.org/peach/bigbuckbunny_movies/BigBuckBunny_320x180.mp4.zip
RUN unzip BigBuckBunny.mp4.zip
RUN mv BigBuckBunny_320x180.mp4 BigBuckBunny.mp4
RUN rm BigBuckBunny.mp4.zip

RUN ffmpeg -i BigBuckBunny.mp4 -map 0 -map 0 -c:a aac -c:v libx264 -b:v:0 800k -s:v:0 640x360 -adaptation_sets "id=0,streams=v id=1,streams=a" -preset veryfast -f dash video.mpd
EXPOSE 80 5000

CMD nginx -g 'daemon off;'
