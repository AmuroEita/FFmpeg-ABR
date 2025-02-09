FFmpeg-ABR README
=============

FFmpeg-ABR is a multimedia content for ABR research, based on FFmpeg, typically used for DASH/HLS adaptive bitrate testing.


## Getting Started

### Prerequisites

Ubuntu 22.0.4

* Libtensorflow
  ```sh
  wget https://storage.googleapis.com/tensorflow/libtensorflow/libtensorflow-gpu-linux-x86_64-2.6.0.tar.gz
  sudo tar -C /usr/local -xzf libtensorflow-gpu-linux-x86_64-2.6.0.tar.gz
  ```

* Libpcap-dev
  ```sh
  sudo apt-get install libpcap-dev
  ```

* Libxml 2.0
  ```sh
  sudo apt-get install libxml2-dev
  ```

* Libssl-dev
  ```sh
  sudo apt-get install libssl-dev
  ```

* Libsdl2-dev
  ```sh
  sudo apt-get install libsdl2-dev
  ```

### Before Compile

* Replace pcap header
  ```sh
  sudo cp pcap/bpf.h /usr/include/pcap/bpf.h
  sudo cp pcap/pcap.h /usr/include/pcap/pcap.h
  ```

### Compile

```sh
sh build.sh
```

### Before Play
  ```sh
  sudo mkdir net_stat && mkdir seg_stat
  ```

### Play

```sh
./ffplay -abr -abr-params format=dash ffabr:$(dash source url)
```
