FROM p4lang/p4c:latest AS p4c-extractor
FROM p4lang/behavioral-model:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
	bash \
	iproute2 \
	iputils-ping \
	libboost-iostreams-dev \
	libboost-graph-dev \
	libgc1 \
	libgmp10 \
	build-essential \
	&& rm -rf /var/lib/apt/lists/*

COPY --from=p4c-extractor /usr/local/bin/p4c* /usr/local/bin/
COPY --from=p4c-extractor /usr/local/share/p4c /usr/local/share/p4c
COPY --from=p4c-extractor /usr/local/lib /usr/local/lib

RUN ldconfig

RUN p4c --version

CMD ["/bin/bash"]
