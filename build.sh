./configure \
--enable-gpl \
--enable-nonfree \
--enable-debug=3 \
--enable-sdl \
--enable-openssl \
--enable-demuxer=dash \
--enable-libxml2 \
--disable-optimizations \
--disable-asm \
--disable-stripping \
--enable-libtensorflow \
--enable-libpcap

make -j96