# https://github.com/NVIDIA/nvidia-docker
FROM    ubuntu:xenial
SHELL   ["/bin/bash", "-xeuo", "pipefail", "-c"]
RUN     export DEBIAN_FRONTEND=noninteractive && \
        apt-get update && \
        apt-get upgrade -y && \
	# install opencl and some other dependencies \
        apt-get install -y --no-install-recommends \
                apt-transport-https ca-certificates clinfo libssl-dev ocl-icd-libopencl1 ocl-icd-opencl-dev && \
	# see https://gitlab.com/nvidia/opencl/blob/ubuntu16.04/runtime/Dockerfile
        mkdir -p /etc/OpenCL/vendors && \
        echo "libnvidia-opencl.so.1" > /etc/OpenCL/vendors/nvidia.icd && \
        # get Mono https://www.mono-project.com/download/stable/ \
        echo "deb https://download.mono-project.com/repo/ubuntu stable-xenial main" | \
                tee /etc/apt/sources.list.d/mono-official-stable.list && \
        apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys "3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF" && \
        apt-get update && \
        apt-get install -y --no-install-recommends \
                msbuild mono-devel && \
        rm -rf /var/lib/apt/lists/*

## copy project and build
COPY    . /opt
WORKDIR /opt
RUN     /usr/bin/msbuild scallion.sln

# container runtime
ENV     NVIDIA_VISIBLE_DEVICES all
ENV     NVIDIA_DRIVER_CAPABILITIES compute,utility
ENTRYPOINT      ["/usr/bin/mono", "/opt/scallion/bin/Debug/scallion.exe"]
